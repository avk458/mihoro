# System service and subscription merging

This fork adds an optional system service and named subscriptions. Existing single-subscription user configurations keep their previous behavior.

## Configuration

Use [examples/system.toml](../examples/system.toml) as the starting configuration. Keep subscription URLs in a private file. Set `policy_file` to an absolute path. Set `service_scope = "system"` to enable TUN.

Named subscriptions supply only their `proxies` lists. Their rules, groups, DNS, and TUN settings are excluded. Node names must be unique across subscriptions. A source with no nodes, duplicate names, or a missing group reference causes the update to fail.

The configuration order is:

1. Combine subscription nodes in the configured order.
2. Apply explicitly configured `mihomo_config` TOML fields. Named subscriptions do not inherit omitted TOML defaults.
3. Apply local YAML policy last.
4. Validate with `mihomo -t`.

Local YAML can use standard Mihomo syntax. It can also use clashctl `prefix`, `suffix`, and `override` lists for rules, proxies, and groups. Group overrides support `proxies-prepend` and `proxies-append`. Other maps are merged recursively; ordinary lists replace the old list. `_custom` is excluded.

To migrate a clashctl merge pipeline, use its two subscription URLs as named sources and its `mixin.yaml` as the policy file. Preserve the rule order and exact node names. You do not need to import the generated profile or the merge shell script.

## Build and inspect

Until a fork release is published, build from source:

```sh
cargo build --release
```

Render a candidate with an existing core and geodata directory:

```sh
./target/release/mihoro -m /path/to/system.toml render \
  --core /path/to/mihomo \
  --data-dir /path/to/geodata \
  --output /tmp/mihomo-candidate.yaml
```

This command validates the candidate but does not install a service or activate TUN. Output permissions are `0600`. `file:///absolute/path.yaml` subscription URLs can use existing local inputs for migration checks. `--offline` uses the last installed generation.

## Installation and service control

Before installation, stop and disable the previous service and archive its unit. Do this as a separate migration step after you check the candidate. Mihoro refuses to replace an unrecognized unit, use external unit overrides, or start beside another Mihomo process.

```sh
sudo /path/to/mihoro -m /etc/mihoro/system.toml init --yes
sudo /path/to/mihoro -m /etc/mihoro/system.toml update
sudo /path/to/mihoro -m /etc/mihoro/system.toml apply
/path/to/mihoro -m /etc/mihoro/system.toml status
/path/to/mihoro -m /etc/mihoro/system.toml log
```

System mode uses these fixed paths:

- Core: `/usr/local/lib/mihoro/mihomo`
- State and configuration generations: `/var/lib/mihoro`
- Unit: `/etc/systemd/system/mihomo.service`

The service uses `DynamicUser`, a systemd state directory, and `CAP_NET_ADMIN`, `CAP_NET_RAW`, and `CAP_NET_BIND_SERVICE`. The executable and all its parent directories must be root-owned and must not be writable by other users. The service cannot access home directories. Policy paths for rule files and other runtime resources must be accessible from the service.

The CLI requires explicit administrator access for system changes. It does not install passwordless sudo rules. `start`, `stop`, `restart`, `status`, `log`, and `uninstall` use the configured service scope. Uninstall removes the managed unit but keeps the core and configuration data.

## Updates and recovery

`update` downloads all subscription inputs. `apply` uses cached inputs and applies the local policy again. `update --core`, `--geodata`, `--ui`, and `--all` are supported.

Each generation contains source snapshots and the final configuration. A lock prevents concurrent CLI changes. After validation, one symlink switch selects the generation. Failed downloads and validation leave the current generation intact. If the service fails the startup check, Mihoro restores the previous generation and core, then starts the previous service if it was running.

Core updates use file replacement. Network capabilities belong to the service and survive core updates. Previous configuration generations remain available for inspection. Geodata and dashboard updates are not included in configuration rollback.

The startup check confirms systemd reports a running service without automatic restarts after two seconds. It does not prove DNS or network connectivity. Test IPv4, IPv6, DNS, Tailscale, container exclusions, reboot, and shutdown on the target host before completing migration.

Automatic scheduling is not installed in managed mode. Use an explicitly configured system timer for the full command with its `-m` path. The legacy cron commands are not used because they do not preserve the selected config path.
