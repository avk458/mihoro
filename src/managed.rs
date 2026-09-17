//! Configuration generations and explicit system service support.
use crate::cmd::{Args, Commands};
use crate::config::{Config, ServiceScope};
use crate::mihoro::{BinaryPlan, Mihoro};
use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde_yaml::{Mapping, Value};
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

const MARKER: &str = "# Managed by mihoro generations v1";
const SYSTEM_CORE: &str = "/usr/local/lib/mihoro/mihomo";
const SYSTEM_ROOT: &str = "/var/lib/mihoro";

pub fn enabled(config: &Config) -> bool {
    config.service_scope == ServiceScope::System
        || !config.subscriptions.is_empty()
        || config.policy_file.is_some()
}

struct Manager {
    mihoro: Mihoro,
    system: bool,
    root: PathBuf,
    unit: PathBuf,
    systemctl: PathBuf,
}

impl Manager {
    fn new(mut config: Config) -> Result<Self> {
        let system = config.service_scope == ServiceScope::System;
        if system {
            // Fixed protected paths prevent a privileged service from executing a user-owned core.
            config.mihomo_binary_path = SYSTEM_CORE.into();
            config.mihomo_config_root = SYSTEM_ROOT.into();
        }
        let root = PathBuf::from(shellexpand::tilde(&config.mihomo_config_root).as_ref());
        if !root.is_absolute() {
            bail!("mihomo_config_root must be absolute");
        }
        let unit = if system {
            PathBuf::from("/etc/systemd/system/mihomo.service")
        } else {
            PathBuf::from(shellexpand::tilde(&config.user_systemd_root).as_ref())
                .join("mihomo.service")
        };
        Ok(Self {
            mihoro: Mihoro::from_config(config),
            system,
            root,
            unit,
            systemctl: PathBuf::from("systemctl"),
        })
    }

    fn ctl(&self, action: &str) -> Command {
        let mut cmd = Command::new(&self.systemctl);
        if !self.system {
            cmd.arg("--user");
        }
        cmd.arg(action);
        cmd
    }

    fn service(&self, action: &str) -> Result<()> {
        let status = self.ctl(action).arg("mihomo.service").status()?;
        if !status.success() {
            bail!("systemctl {action} failed: {status}");
        }
        Ok(())
    }

    fn guard(&self, starting: bool) -> Result<()> {
        if self.system {
            let uid = Command::new("id").arg("-u").output()?;
            if uid.stdout != b"0\n" {
                bail!("system mode changes require administrator access; run this command with sudo and an explicit -m config path");
            }
            // Check every existing ancestor, including the executable itself.
            protected_path(Path::new(SYSTEM_CORE))?;
        }
        if self.unit.exists() {
            let existing = fs::read_to_string(&self.unit)?;
            if !existing.starts_with(MARKER) {
                bail!("existing {} is not managed by this installation; migrate it explicitly before continuing", self.unit.display());
            }
        }
        // Also detect vendor units and drop-ins, not only /etc unit files.
        let output = self
            .ctl("show")
            .args(["mihomo.service", "-p", "FragmentPath", "-p", "DropInPaths"])
            .output()?;
        if !output.status.success() {
            bail!("cannot inspect service ownership");
        }
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if let Some(path) = line.strip_prefix("FragmentPath=") {
                if !path.is_empty() && Path::new(path) != self.unit {
                    bail!("a different mihomo.service is installed at {path}");
                }
            }
            if let Some(paths) = line.strip_prefix("DropInPaths=") {
                if !paths.is_empty() {
                    bail!("mihomo.service has external drop-ins; review them before migration");
                }
            }
        }
        if starting {
            let mut other = Command::new(&self.systemctl);
            if self.system {
                // sudo does not have the invoking user's user bus. Inspect processes below too.
                other.arg("--user");
            }
            let active = other
                .args(["is-active", "--quiet", "mihomo.service"])
                .output()?;
            if active.status.success() {
                bail!("mihomo.service is active in the other service scope");
            }
            let own = self
                .ctl("show")
                .args(["mihomo.service", "-p", "MainPID", "--value"])
                .output()?;
            let own_pid = String::from_utf8_lossy(&own.stdout).trim().to_owned();
            for entry in fs::read_dir("/proc")?.flatten() {
                let pid = entry.file_name().to_string_lossy().into_owned();
                if pid == own_pid || !pid.bytes().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                if fs::read_to_string(entry.path().join("comm")).is_ok_and(|s| s.trim() == "mihomo")
                {
                    bail!("another Mihomo process is running (PID {pid}); stop it explicitly before migration");
                }
            }
        }
        Ok(())
    }

    async fn stage(&self, client: &Client, offline: bool) -> Result<TempDir> {
        fs::create_dir_all(&self.root)?;
        let stage = tempfile::Builder::new()
            .prefix("generation-")
            .tempdir_in(&self.root)?;
        let input_dir = stage.path().join("sources");
        fs::create_dir(&input_dir)?;
        let config = &self.mihoro.config;
        let mut sources = Vec::new();
        if config.subscriptions.is_empty() {
            let value = self
                .input(
                    client,
                    "remote",
                    &config.remote_config_url,
                    offline,
                    &input_dir,
                )
                .await?;
            sources.push(value);
        } else {
            for sub in &config.subscriptions {
                sources.push(
                    self.input(client, &sub.name, &sub.url, offline, &input_dir)
                        .await?,
                );
            }
        }
        let base = if config.subscriptions.is_empty() {
            sources.remove(0)
        } else {
            merge_nodes(&sources)?
        };
        let path = stage.path().join("config.yaml");
        fs::write(&path, serde_yaml::to_string(&base)?)?;
        crate::config::apply_mihomo_override(
            path.to_str().context("invalid config path")?,
            &config.mihomo_config,
        )?;
        let mut value: Value = serde_yaml::from_str(&fs::read_to_string(&path)?)?;
        if !config.subscriptions.is_empty() {
            // Named sources supply nodes only. Do not inject upstream TOML defaults.
            if let Some(mapping) = value.as_mapping_mut() {
                mapping.retain(|key, _| {
                    key.as_str().is_some_and(|key| {
                        key == "proxies" || config.explicit_mihomo_fields.contains(key)
                    })
                });
            }
        }
        if let Some(policy) = &config.policy_file {
            let policy: Value =
                serde_yaml::from_str(&fs::read_to_string(shellexpand::tilde(policy).as_ref())?)
                    .map_err(|_| anyhow::anyhow!("policy file is not valid YAML"))?;
            value = apply_policy(value, policy)?;
        }
        validate_references(&value)?;
        if !self.system && value["tun"]["enable"].as_bool() == Some(true) {
            bail!("TUN requires service_scope = 'system'");
        }
        fs::write(path, serde_yaml::to_string(&value)?)?;
        Ok(stage)
    }

    async fn input(
        &self,
        client: &Client,
        name: &str,
        url: &str,
        offline: bool,
        dir: &Path,
    ) -> Result<Value> {
        let filename = format!("{name}.yaml");
        let data = if offline {
            fs::read(self.root.join("current/sources").join(&filename))
                .with_context(|| format!("no cached input for {name}; run update first"))?
        } else if url.starts_with("file://") {
            let path = reqwest::Url::parse(url)?
                .to_file_path()
                .map_err(|_| anyhow::anyhow!("invalid local source {name}"))?;
            fs::read(path).with_context(|| format!("cannot read source {name}"))?
        } else {
            // Do not include reqwest errors: they can contain subscription credentials.
            let response = client
                .get(url)
                .header(
                    reqwest::header::USER_AGENT,
                    &self.mihoro.config.mihoro_user_agent,
                )
                .send()
                .await
                .map_err(|_| anyhow::anyhow!("download failed for source {name}"))?;
            if !response.status().is_success() {
                bail!("source {name} returned HTTP {}", response.status());
            }
            response
                .bytes()
                .await
                .map_err(|_| anyhow::anyhow!("cannot read source {name}"))?
                .to_vec()
        };
        let path = dir.join(filename);
        fs::write(&path, data)?;
        crate::utils::try_decode_base64_file_inplace(
            path.to_str().context("invalid source path")?,
        )?;
        // Parser errors may contain a source line with a password. Report only the source name.
        serde_yaml::from_slice(&fs::read(path)?)
            .map_err(|_| anyhow::anyhow!("source {name} is not valid YAML"))
    }

    fn validate(&self, path: &Path, core: &Path) -> Result<()> {
        let output = Command::new(core)
            .arg("-t")
            .arg("-d")
            .arg(&self.root)
            .arg("-f")
            .arg(path)
            .output()
            .context("cannot run Mihomo validation; install the core with init first")?;
        if !output.status.success() {
            bail!(
                "Mihomo rejected the candidate configuration; installed generation was preserved"
            );
        }
        Ok(())
    }

    fn unit_content(&self) -> Result<String> {
        let binary = quote_unit(&self.mihoro.mihomo_target_binary_path)?;
        let root = quote_unit(self.root.to_str().context("invalid root path")?)?;
        let config = quote_unit(
            self.root
                .join("current/config.yaml")
                .to_str()
                .context("invalid config path")?,
        )?;
        let security = if self.system {
            "DynamicUser=yes\nStateDirectory=mihoro\nStateDirectoryMode=0750\nAmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nRestrictSUIDSGID=yes\n"
        } else {
            ""
        };
        let target = if self.system {
            "multi-user.target"
        } else {
            "default.target"
        };
        Ok(format!("{MARKER}\n[Unit]\nDescription=Mihomo managed by mihoro\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=exec\n{security}ExecStart={binary} -d {root} -f {config}\nRestart=on-failure\nRestartSec=3\nLimitNOFILE=65536\n\n[Install]\nWantedBy={target}\n"))
    }

    fn install_unit(&self) -> Result<()> {
        let content = self.unit_content()?;
        fs::create_dir_all(self.unit.parent().context("invalid service path")?)?;
        atomic_write(&self.unit, content.as_bytes(), 0o644)?;
        let status = self.ctl("daemon-reload").status()?;
        if !status.success() {
            bail!("systemd daemon-reload failed");
        }
        Ok(())
    }

    fn publish(&self, stage: TempDir) -> Result<Option<PathBuf>> {
        let current = self.root.join("current");
        let previous = match fs::read_link(&current) {
            Ok(path) => Some(path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        // The service needs read access; sources remain private inside the generation.
        fs::set_permissions(stage.path(), fs::Permissions::from_mode(0o755))?;
        fs::set_permissions(
            stage.path().join("sources"),
            fs::Permissions::from_mode(0o700),
        )?;
        let generation = stage.keep();
        switch_link(
            &current,
            Path::new(generation.file_name().context("invalid generation")?),
        )?;
        Ok(previous)
    }

    fn restore(&self, previous: &Option<PathBuf>) -> Result<()> {
        if let Some(previous) = previous {
            switch_link(&self.root.join("current"), previous)?;
        } else {
            fs::remove_file(self.root.join("current"))?;
        }
        Ok(())
    }

    async fn activate(&self, previous: &Option<PathBuf>) -> Result<()> {
        let result = async {
            self.service("restart")?;
            // Detect immediate startup failures even when Restart=on-failure is set.
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let output = self
                .ctl("show")
                .args([
                    "mihomo.service",
                    "-p",
                    "ActiveState",
                    "-p",
                    "SubState",
                    "-p",
                    "NRestarts",
                ])
                .output()?;
            let state = String::from_utf8_lossy(&output.stdout);
            if !output.status.success()
                || !state.lines().any(|l| l == "ActiveState=active")
                || !state.lines().any(|l| l == "SubState=running")
                || !state.lines().any(|l| l == "NRestarts=0")
            {
                bail!("service failed startup checks");
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(error) = result {
            let stopped = self.service("stop");
            self.restore(previous)?;
            stopped.context("configuration restored, but failed service could not be stopped")?;
            return Err(error.context("activation failed; restored previous configuration"));
        }
        Ok(())
    }

    fn active(&self) -> Result<bool> {
        Ok(self
            .ctl("is-active")
            .args(["--quiet", "mihomo.service"])
            .output()?
            .status
            .success())
    }
}

fn protected_path(path: &Path) -> Result<()> {
    for component in path.ancestors() {
        match fs::symlink_metadata(component) {
            Ok(meta) if meta.file_type().is_symlink() || meta.uid() != 0 || meta.mode() & 0o022 != 0 => bail!("system core path must be root-owned, without symlinks or group/world write access: {}", component.display()),
            Ok(_) => {},
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn quote_unit(value: &str) -> Result<String> {
    if value.contains(['\n', '\r', '\0']) {
        bail!("invalid newline or NUL in service path");
    }
    Ok(format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    ))
}

fn atomic_write(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    let mut file = tempfile::NamedTempFile::new_in(path.parent().context("invalid output path")?)?;
    file.write_all(data)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    Ok(())
}

fn switch_link(path: &Path, target: &Path) -> Result<()> {
    let temporary = tempfile::tempdir_in(path.parent().context("invalid link path")?)?;
    let link = temporary.path().join("link");
    symlink(target, &link)?;
    fs::rename(link, path)?;
    Ok(())
}

fn merge_nodes(sources: &[Value]) -> Result<Value> {
    let mut nodes = Vec::new();
    for source in sources {
        let proxies = source["proxies"]
            .as_sequence()
            .context("each subscription must contain a proxies list")?;
        if proxies.is_empty() {
            bail!("subscription has no nodes");
        }
        nodes.extend(proxies.iter().cloned());
    }
    let mut base = Mapping::new();
    base.insert("proxies".into(), nodes.into());
    Ok(base.into())
}

fn deep_merge(base: &mut Value, overlay: Value) {
    match (base, overlay) {
        (Value::Mapping(base), Value::Mapping(overlay)) => {
            for (key, value) in overlay {
                deep_merge(base.entry(key).or_insert(Value::Null), value);
            }
        }
        (base, overlay) => *base = overlay,
    }
}

/// Plain Mihomo YAML is accepted. Existing clashctl prefix/suffix/override lists are supported.
fn apply_policy(mut base: Value, mut policy: Value) -> Result<Value> {
    let mapping = policy
        .as_mapping_mut()
        .context("policy must be a YAML mapping")?;
    mapping.remove(Value::from("_custom"));
    for key in ["rules", "proxies", "proxy-groups"] {
        if let Some(Value::Mapping(ops)) = mapping.get(Value::from(key)) {
            let mut list = Vec::new();
            let sequence = |name: &str| -> Result<Vec<Value>> {
                match ops.get(Value::from(name)) {
                    None | Some(Value::Null) => Ok(Vec::new()),
                    Some(Value::Sequence(items)) => Ok(items.clone()),
                    _ => bail!("{key}.{name} must be a list"),
                }
            };
            list.extend(sequence("prefix")?);
            let overrides = sequence("override")?;
            for item in base[key].as_sequence().cloned().unwrap_or_default() {
                let replacement = overrides
                    .iter()
                    .find(|v| v["name"].as_str().is_some() && v["name"] == item["name"]);
                let mut result = replacement.cloned().unwrap_or_else(|| item.clone());
                if key == "proxy-groups" {
                    if let Some(overlay) = replacement {
                        result = item.clone();
                        deep_merge(&mut result, overlay.clone());
                        let mut nodes = Vec::new();
                        for source in [
                            &overlay["proxies-prepend"],
                            &item["proxies"],
                            &overlay["proxies-append"],
                        ] {
                            if let Some(values) = source.as_sequence() {
                                for value in values {
                                    if !nodes.contains(value) {
                                        nodes.push(value.clone());
                                    }
                                }
                            }
                        }
                        result["proxies"] = nodes.into();
                        if let Some(map) = result.as_mapping_mut() {
                            map.remove(Value::from("proxies-prepend"));
                            map.remove(Value::from("proxies-append"));
                        }
                    }
                }
                list.push(result);
            }
            list.extend(sequence("suffix")?);
            mapping.insert(key.into(), list.into());
        }
    }
    deep_merge(&mut base, policy);
    Ok(base)
}

fn validate_references(value: &Value) -> Result<()> {
    let mut names: HashSet<String> = [
        "DIRECT",
        "REJECT",
        "REJECT-DROP",
        "PASS",
        "COMPATIBLE",
        "GLOBAL",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    for key in ["proxies", "proxy-groups"] {
        if let Some(items) = value[key].as_sequence() {
            for item in items {
                let name = item["name"].as_str().context("node or group has no name")?;
                if !names.insert(name.to_owned()) {
                    bail!("duplicate node or group name: {name}");
                }
            }
        }
    }
    if let Some(groups) = value["proxy-groups"].as_sequence() {
        for group in groups {
            if let Some(refs) = group["proxies"].as_sequence() {
                for name in refs {
                    let name = name.as_str().context("group reference must be a name")?;
                    if !names.contains(name) {
                        bail!("group references missing node or group: {name}");
                    }
                }
            }
        }
    }
    Ok(())
}

pub async fn run(config: Config, args: &Args, client: &Client) -> Result<()> {
    let manager = Manager::new(config)?;
    let core = Path::new(&manager.mihoro.mihomo_target_binary_path);
    let mutating = matches!(
        args.command,
        Some(
            Commands::Init { .. }
                | Commands::Setup { .. }
                | Commands::Update { .. }
                | Commands::Apply
                | Commands::Start
                | Commands::Restart
                | Commands::Stop
                | Commands::Uninstall
        )
    );
    let _lock = if mutating {
        manager.guard(!matches!(
            args.command,
            Some(Commands::Stop | Commands::Uninstall)
        ))?;
        fs::create_dir_all(&manager.root)?;
        if manager.system {
            fs::set_permissions(&manager.root, fs::Permissions::from_mode(0o750))?;
        }
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(manager.root.join(".mihoro.lock"))?;
        file.try_lock()
            .context("another mihoro operation is in progress")?;
        Some(file)
    } else {
        None
    };
    match args.command.as_ref().context("command required")? {
        Commands::Render { output, offline, core: validation_core, data_dir } => {
            // Render is isolated from the installed state, including when system scope is selected.
            let temporary = tempfile::tempdir()?;
            let mut renderer = Manager::new(manager.mihoro.config.clone())?;
            if *offline {
                symlink(manager.root.join("current"), temporary.path().join("current"))?;
            }
            renderer.root = temporary.path().to_owned();
            let stage = renderer.stage(client, *offline).await?;
            if let Some(data_dir) = data_dir { renderer.root = data_dir.clone(); } else { renderer.root = manager.root.clone(); }
            renderer.validate(&stage.path().join("config.yaml"), validation_core.as_deref().unwrap_or(core))?;
            atomic_write(output, &fs::read(stage.path().join("config.yaml"))?, 0o600)?;
            println!("Rendered and validated {}", output.display());
        },
        Commands::Init { force, arch, .. } | Commands::Setup { overwrite: force, arch } => {
            manager.guard(true)?;
            let plan = manager.mihoro.prepare_binary(client, *force, arch.as_deref()).await?;
            let stage = manager.stage(client, !*force && manager.root.join("current").exists()).await?;
            manager.mihoro.ensure_geodata(client, *force).await?;
            manager.mihoro.ensure_ui(client, *force).await?;
            let candidate = prepare_core(plan, core)?;
            manager.validate(&stage.path().join("config.yaml"), candidate.as_deref().unwrap_or(core))?;
            let was_active = manager.active()?;
            let mut backup = install_core(candidate, core)?;
            manager.install_unit()?;
            let previous = manager.publish(stage)?;
            if let Err(error) = manager.activate(&previous).await {
                backup.rollback()?;
                if was_active && previous.is_some() { manager.service("start")?; }
                return Err(error);
            }
            backup.commit();
            manager.service("enable")?;
            println!("Installed and started mihomo.service");
        },
        Commands::Update { config: update_config, core: update_core, geodata, ui, all, arch } => {
            manager.guard(true)?;
            let stage = if *all || *update_config || (!update_core && !geodata && !ui) {
                Some(manager.stage(client, false).await?)
            } else { None };
            if *all || *geodata { manager.mihoro.update_geodata(client).await?; }
            if *all || *ui { manager.mihoro.update_ui(client).await?; }
            let candidate = if *all || *update_core {
                prepare_core(manager.mihoro.prepare_binary(client, true, arch.as_deref()).await?, core)?
            } else { None };
            let config = stage.as_ref().map(|s| s.path().join("config.yaml")).unwrap_or_else(|| manager.root.join("current/config.yaml"));
            manager.validate(&config, candidate.as_deref().unwrap_or(core))?;
            let was_active = manager.active()?;
            let mut backup = install_core(candidate, core)?;
            let previous = if let Some(stage) = stage { manager.publish(stage)? } else { Some(fs::read_link(manager.root.join("current"))?) };
            if let Err(error) = manager.activate(&previous).await {
                backup.rollback()?;
                if was_active && previous.is_some() { manager.service("start")?; }
                return Err(error);
            }
            backup.commit();
            println!("Updated and activated configuration");
        },
        Commands::Apply => {
            manager.guard(true)?;
            let stage = manager.stage(client, true).await?;
            manager.validate(&stage.path().join("config.yaml"), core)?;
            let was_active = manager.active()?;
            let previous = manager.publish(stage)?;
            if let Err(error) = manager.activate(&previous).await {
                if was_active && previous.is_some() { manager.service("start")?; }
                return Err(error);
            }
        },
        Commands::Start | Commands::Restart => {
            manager.guard(true)?;
            manager.validate(&manager.root.join("current/config.yaml"), core)?;
            manager.service(if matches!(args.command, Some(Commands::Start)) { "start" } else { "restart" })?;
        },
        Commands::Stop => { manager.guard(false)?; manager.service("stop")?; },
        Commands::Status => manager.service("status")?,
        Commands::Log => {
            let mut cmd = Command::new("journalctl");
            if !manager.system { cmd.arg("--user"); }
            if !cmd.args(["-u", "mihomo.service", "-n", "40", "-f"]).status()?.success() { bail!("journalctl failed"); }
        },
        Commands::Uninstall => {
            manager.guard(false)?;
            manager.service("stop")?;
            manager.service("disable")?;
            fs::remove_file(&manager.unit)?;
            if !manager.ctl("daemon-reload").status()?.success() { bail!("daemon-reload failed"); }
            println!("Removed service. Configuration generations and core are retained at {} and {}", manager.root.display(), core.display());
        },
        Commands::Proxy { proxy } => manager.mihoro.proxy_commands(proxy)?,
        Commands::Completions { shell } => {
            use clap::CommandFactory;
            use clap_complete::{generate, shells::{Bash, Fish, Zsh}};
            use crate::cmd::ClapShell;
            match shell {
                Some(ClapShell::Bash) => generate(Bash, &mut Args::command(), "mihoro", &mut std::io::stdout()),
                Some(ClapShell::Fish) => generate(Fish, &mut Args::command(), "mihoro", &mut std::io::stdout()),
                Some(ClapShell::Zsh) => generate(Zsh, &mut Args::command(), "mihoro", &mut std::io::stdout()),
                None => {},
            }
        },
        #[cfg(feature = "self_update")]
        Commands::Upgrade { yes, check, target } => {
            if *check { println!("Available update: {:?}", crate::upgrade::check_for_update().await?); }
            else { crate::upgrade::run_upgrade(*yes, target.clone()).await?; }
        },
        #[cfg(not(feature = "self_update"))]
        Commands::Upgrade { .. } => bail!("this build does not include self-update support"),
        Commands::Cron { .. } => bail!("managed mode requires an explicit system timer with the -m config path; legacy cron is not used"),
    }
    Ok(())
}

fn prepare_core(plan: BinaryPlan, core: &Path) -> Result<Option<tempfile::TempPath>> {
    match plan {
        BinaryPlan::Skip(_) => Ok(None),
        BinaryPlan::Install(download) => {
            let parent = core.parent().context("invalid core path")?;
            fs::create_dir_all(parent)?;
            let candidate = tempfile::NamedTempFile::new_in(parent)?;
            crate::utils::extract_gzip(
                download.path(),
                candidate.path().to_str().context("invalid core path")?,
                "mihoro:",
            )?;
            fs::set_permissions(candidate.path(), fs::Permissions::from_mode(0o755))?;
            Ok(Some(candidate.into_temp_path()))
        }
    }
}

struct CoreSwap {
    backup: Option<tempfile::TempPath>,
    target: PathBuf,
    changed: bool,
}

impl CoreSwap {
    fn commit(&mut self) {
        self.changed = false;
    }
    fn rollback(&mut self) -> Result<()> {
        if self.changed {
            if let Some(backup) = self.backup.take() {
                backup.persist(&self.target)?;
            } else {
                fs::remove_file(&self.target)?;
            }
            self.changed = false;
        }
        Ok(())
    }
}

impl Drop for CoreSwap {
    fn drop(&mut self) {
        if let Err(error) = self.rollback() {
            eprintln!("core rollback failed: {error}");
        }
    }
}

fn install_core(candidate: Option<tempfile::TempPath>, core: &Path) -> Result<CoreSwap> {
    let mut swap = CoreSwap {
        backup: None,
        target: core.to_owned(),
        changed: false,
    };
    if let Some(candidate) = candidate {
        if core.exists() {
            let backup =
                tempfile::NamedTempFile::new_in(core.parent().context("invalid core path")?)?;
            fs::copy(core, backup.path())?;
            swap.backup = Some(backup.into_temp_path());
        }
        candidate.persist(core)?;
        swap.changed = true;
    }
    Ok(swap)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml(text: &str) -> Value {
        serde_yaml::from_str(text).unwrap()
    }

    #[test]
    fn existing_foreign_service_is_rejected_before_any_service_command() {
        let temp = tempfile::tempdir().unwrap();
        let manager = Manager::new(Config {
            user_systemd_root: temp.path().to_string_lossy().into_owned(),
            mihomo_config_root: temp.path().join("state").to_string_lossy().into_owned(),
            ..Config::default()
        })
        .unwrap();
        fs::write(&manager.unit, "[Service]\nExecStart=/existing/mihomo\n").unwrap();
        let error = manager.guard(true).unwrap_err().to_string();
        assert!(error.contains("not managed"));
        assert!(!manager.root.exists());
        assert_eq!(
            fs::read_to_string(&manager.unit).unwrap(),
            "[Service]\nExecStart=/existing/mihomo\n"
        );
    }

    #[test]
    fn failed_core_transaction_restores_previous_executable() {
        let temp = tempfile::tempdir().unwrap();
        let core = temp.path().join("mihomo");
        fs::write(&core, "old").unwrap();
        let candidate = tempfile::NamedTempFile::new_in(temp.path()).unwrap();
        fs::write(candidate.path(), "new").unwrap();
        {
            let _swap = install_core(Some(candidate.into_temp_path()), &core).unwrap();
            assert_eq!(fs::read_to_string(&core).unwrap(), "new");
        }
        assert_eq!(fs::read_to_string(&core).unwrap(), "old");
    }

    #[tokio::test]
    async fn activation_failure_stops_service_and_restores_generation() {
        let temp = tempfile::tempdir().unwrap();
        let config = Config {
            mihomo_config_root: temp.path().to_string_lossy().into_owned(),
            ..Config::default()
        };
        let mut manager = Manager::new(config).unwrap();
        let script = temp.path().join("systemctl");
        fs::write(
            &script,
            "#!/bin/sh\ncase \"$*\" in *restart*) exit 1;; *stop*) exit 0;; *) exit 2;; esac\n",
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        manager.systemctl = script;
        fs::create_dir(temp.path().join("old")).unwrap();
        fs::create_dir(temp.path().join("new")).unwrap();
        symlink("new", temp.path().join("current")).unwrap();
        assert!(manager.activate(&Some(PathBuf::from("old"))).await.is_err());
        assert_eq!(
            fs::read_link(temp.path().join("current")).unwrap(),
            PathBuf::from("old")
        );
    }

    #[test]
    fn subscriptions_supply_only_nodes_and_local_policy_controls_routing() {
        let a = yaml(
            "proxies: [{name: a, type: direct}]\nrules: ['MATCH,REJECT']\ndns: {enable: false}",
        );
        let b = yaml("proxies: [{name: b, type: direct}]\nproxy-groups: [{name: unwanted}]");
        let merged = merge_nodes(&[a, b]).unwrap();
        assert!(merged["rules"].is_null());
        assert!(merged["dns"].is_null());
        let policy = yaml("rules: {prefix: ['DOMAIN,example.com,AI', 'MATCH,AUTO'], suffix: []}\nproxy-groups:\n  prefix: [{name: AI, type: select, proxies: [b, AUTO]}, {name: AUTO, type: url-test, include-all: true}]\n  suffix: [{name: MANUAL, type: select, include-all: true}]\ndns: {enable: true}\ntun: {enable: true, exclude-interface: [windows0]}\n_custom: {internal: true}");
        let result = apply_policy(merged, policy).unwrap();
        validate_references(&result).unwrap();
        assert_eq!(result["proxies"].as_sequence().unwrap().len(), 2);
        assert_eq!(
            result["rules"],
            yaml("['DOMAIN,example.com,AI', 'MATCH,AUTO']")
        );
        assert_eq!(result["proxy-groups"].as_sequence().unwrap().len(), 3);
        assert_eq!(result["tun"]["exclude-interface"], yaml("[windows0]"));
        assert!(result["_custom"].is_null());
    }

    #[test]
    fn duplicate_and_missing_names_are_rejected() {
        assert!(validate_references(&yaml("proxies: [{name: a}, {name: a}]")).is_err());
        assert!(validate_references(&yaml(
            "proxies: [{name: a}]\nproxy-groups: [{name: g, proxies: [missing]}]"
        ))
        .is_err());
        assert!(merge_nodes(&[yaml("proxies: []")]).is_err());
    }

    #[test]
    fn plain_yaml_and_clashctl_overrides_preserve_order() {
        let base = yaml("rules: [old]\nproxy-groups: [{name: g, type: select, proxies: [a, b]}]\ndns: {enable: true, nameserver: [old]}");
        let policy = yaml("rules: [new]\nproxy-groups:\n  override: [{name: g, proxies-prepend: [c, a], proxies-append: [d, b]}]\ndns: {nameserver: [new]}");
        let result = apply_policy(base, policy).unwrap();
        assert_eq!(result["rules"], yaml("[new]"));
        assert_eq!(result["proxy-groups"][0]["proxies"], yaml("[c, a, b, d]"));
        assert!(result["proxy-groups"][0]["proxies-prepend"].is_null());
        assert_eq!(result["dns"], yaml("{enable: true, nameserver: [new]}"));
    }

    #[test]
    fn generation_switch_and_restore_keep_sources_and_config_together() {
        let temp = tempfile::tempdir().unwrap();
        let config = Config {
            mihomo_config_root: temp.path().to_string_lossy().into_owned(),
            ..Config::default()
        };
        let manager = Manager::new(config).unwrap();
        let stage = |name: &str| {
            let dir = tempfile::tempdir_in(temp.path()).unwrap();
            fs::create_dir(dir.path().join("sources")).unwrap();
            fs::write(dir.path().join("sources/a.yaml"), name).unwrap();
            fs::write(dir.path().join("config.yaml"), name).unwrap();
            dir
        };
        assert!(manager.publish(stage("old")).unwrap().is_none());
        let previous = manager.publish(stage("new")).unwrap();
        assert_eq!(
            fs::read_to_string(temp.path().join("current/config.yaml")).unwrap(),
            "new"
        );
        manager.restore(&previous).unwrap();
        for file in ["config.yaml", "sources/a.yaml"] {
            assert_eq!(
                fs::read_to_string(temp.path().join("current").join(file)).unwrap(),
                "old"
            );
        }
    }

    #[test]
    fn system_unit_uses_protected_core_and_network_capabilities() {
        let manager = Manager::new(Config {
            service_scope: ServiceScope::System,
            ..Config::default()
        })
        .unwrap();
        let unit = manager.unit_content().unwrap();
        assert!(unit.contains("DynamicUser=yes"));
        assert!(unit.contains("ProtectHome=yes"));
        assert!(unit.contains(SYSTEM_CORE));
        assert!(!unit.contains("CAP_SYS_ADMIN"));
        assert!(unit.contains("WantedBy=multi-user.target"));
        assert_eq!(quote_unit("/a b/%i/$x").unwrap(), "\"/a b/%%i/$$x\"");
        assert!(quote_unit("/a\nExecStart=/bad").is_err());
    }

    #[tokio::test]
    async fn failed_download_or_reference_does_not_replace_current_generation() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input.yaml");
        fs::write(&input, "proxies: [{name: good, type: direct}]").unwrap();
        let policy = temp.path().join("policy.yaml");
        fs::write(
            &policy,
            "proxy-groups: [{name: g, type: select, proxies: [good]}]\nrules: ['MATCH,g']",
        )
        .unwrap();
        let config = Config {
            mihomo_config_root: temp.path().to_string_lossy().into_owned(),
            subscriptions: vec![crate::config::Subscription {
                name: "a".into(),
                url: format!("file://{}", input.display()),
            }],
            policy_file: Some(policy.to_string_lossy().into_owned()),
            ..Config::default()
        };
        let manager = Manager::new(config).unwrap();
        let client = Client::new();
        let stage = manager.stage(&client, false).await.unwrap();
        let rendered = yaml(&fs::read_to_string(stage.path().join("config.yaml")).unwrap());
        assert!(
            rendered["port"].is_null(),
            "omitted defaults must not alter policy"
        );
        assert!(rendered["socks-port"].is_null());
        manager.publish(stage).unwrap();
        let old = fs::read_link(temp.path().join("current")).unwrap();
        fs::write(&input, "proxies: [{name: renamed, type: direct}]").unwrap();
        assert!(manager.stage(&client, false).await.is_err());
        fs::remove_file(&input).unwrap();
        assert!(manager.stage(&client, false).await.is_err());
        assert!(manager.stage(&client, true).await.is_ok());
        assert_eq!(fs::read_link(temp.path().join("current")).unwrap(), old);
    }
}
