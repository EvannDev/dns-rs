# dns-rs

dns-rs is a network-wide DNS sinkhole written in Rust, a modern alternative
to Pi-hole built to run in a container and as stateless replicas on
Kubernetes. It forwards queries to an upstream resolver with a cache, blocks
the names on your blocklists, answers local records, and forwards chosen
domains to their own server. It exports a query log, Prometheus metrics and
Kubernetes probes.

All configuration is a TOML file that dns-rs reloads without a restart. The
project is young: see the [README](https://github.com/EvannDev/dns-rs#readme)
for its current status.

## Where to start

- New here: [Getting started](getting-started.md).
- Coming from Pi-hole: [Migrating from Pi-hole](migrating-from-pihole.md).
- Deploying: [Container image](container.md) or [Kubernetes](kubernetes.md).

## Pages

| Page | Content |
|---|---|
| [Getting started](getting-started.md) | Run the image or the Helm chart, check it, point clients at it |
| [Migrating from Pi-hole](migrating-from-pihole.md) | How Pi-hole concepts map to dns-rs, and what is missing |
| [Configuration](configuration.md) | Every setting, default, environment override and reload behavior |
| [Blocklists](blocklists.md) | Supported formats, rule syntax, blocking modes, download limits |
| [Metrics and probes](metrics.md) | The HTTP endpoint: `/healthz`, `/readyz`, `/metrics`, `/api/v1/check`, `/api/v1/status` and the metric series |
| [Logging](logging.md) | The query log and the operational log messages |
| [Container image](container.md) | Published tags, running the image, ports, signals |
| [Releasing](releasing.md) | Cutting a release: the tag checks and what gets published |
| [Kubernetes](kubernetes.md) | The Helm chart: objects, values, configuration changes, pod security |
| [Architecture decisions](adr/README.md) | Why dns-rs works the way it does |

Source code and issues:
[github.com/EvannDev/dns-rs](https://github.com/EvannDev/dns-rs).
