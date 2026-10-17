# Kubernetes

The Helm chart in [`charts/dns-rs`](../charts/dns-rs) runs dns-rs as stateless
replicas. It is not published to a chart repository yet: install it from a
checkout of the repository.

```sh
helm install dns-rs charts/dns-rs --namespace dns --create-namespace
```

The chart creates:

| Object | Name | Content |
|---|---|---|
| Deployment | `<release>-dns-rs` | `replicaCount` replicas (default 2); each loads the configuration and the blocklists itself |
| ConfigMap | `<release>-dns-rs` | `dns-rs.toml`, from `config`, mounted at `/etc/dns-rs` |
| Service | `<release>-dns-rs-dns` | DNS on `service.dns.port` (default 53), UDP and TCP, to container port 5353 |
| Service | `<release>-dns-rs-http` | Probes, metrics and API on `service.http.port` (default 8080) |
| Secret | `<release>-dns-rs-api` | The API token, only when `api.token` is set |
| PodDisruptionBudget | `<release>-dns-rs` | `maxUnavailable` pods, only with `podDisruptionBudget.enabled` and more than one replica |
| ServiceMonitor | `<release>-dns-rs` | Scrapes `/metrics` of the http Service, only with `serviceMonitor.enabled` |
| NetworkPolicy | `<release>-dns-rs` | Ingress rules, only with `networkPolicy.enabled` |

If the release name already contains `dns-rs`, the prefix is not repeated
(release `dns-rs` gives `dns-rs`, `dns-rs-dns` and `dns-rs-http`). Run
`helm template` to see the exact names.

## Values

| Value | Default | Meaning |
|---|---|---|
| `replicaCount` | `2` | Number of replicas, at least 1 |
| `image.repository` | `ghcr.io/evanndev/dns-rs` | Image repository, see [Container image](container.md) |
| `image.tag` | `""` | Image tag; empty means the chart's `appVersion` |
| `image.pullPolicy` | `IfNotPresent` | `Always`, `IfNotPresent` or `Never` |
| `imagePullSecrets` | `[]` | Pull secrets |
| `upstream.server` | `1.1.1.1:53` | Upstream resolver (`DNS_RS_UPSTREAM`); the port defaults to 53 |
| `upstream.timeoutMs` | `2000` | Upstream timeout in milliseconds (`DNS_RS_UPSTREAM_TIMEOUT_MS`) |
| `cache.size` | `10000` | Maximum number of cached responses (`DNS_RS_CACHE_SIZE`) |
| `config` | `[blocking]` with `mode = "null"` | The reloaded part of the configuration file, as TOML text |
| `service.dns.type` | `ClusterIP` | `ClusterIP`, `NodePort` or `LoadBalancer` |
| `service.dns.port` | `53` | Service port for DNS (UDP and TCP) |
| `service.dns.externalTrafficPolicy` | `""` | `Cluster` or `Local`; empty leaves the Kubernetes default; the schema rejects it on a `ClusterIP` Service |
| `service.dns.annotations` | `{}` | Service annotations |
| `service.http.type` | `ClusterIP` | `ClusterIP`, `NodePort` or `LoadBalancer` |
| `service.http.port` | `8080` | Service port for HTTP |
| `service.http.annotations` | `{}` | Service annotations |
| `api.token` | `""` | API token, at least 16 characters (the schema rejects shorter ones); the chart stores it in a Secret. Prefer `api.existingSecret`: a token in values ends up in Helm's release history |
| `api.existingSecret` | `""` | Name of a Secret you manage; set it or `api.token`, not both (the chart fails to render otherwise) |
| `api.existingSecretKey` | `token` | Key of the token in `api.existingSecret` |
| `podDisruptionBudget.enabled` | `true` | Renders a PodDisruptionBudget, only with more than one replica |
| `podDisruptionBudget.maxUnavailable` | `1` | Pods that may be unavailable during voluntary disruptions |
| `topologySpread.enabled` | `true` | Spreads replicas across nodes (`kubernetes.io/hostname`, `maxSkew: 1`, `ScheduleAnyway`) |
| `serviceMonitor.enabled` | `false` | Renders a Prometheus Operator ServiceMonitor for `/metrics` |
| `serviceMonitor.interval` | `30s` | Scrape interval |
| `serviceMonitor.labels` | `{}` | Extra labels, for example to match a Prometheus `serviceMonitorSelector` |
| `networkPolicy.enabled` | `false` | Renders a NetworkPolicy (ingress only) |
| `networkPolicy.dns.from` | `[]` | NetworkPolicyPeers allowed to query DNS (port 5353); empty means everyone |
| `networkPolicy.http.from` | `[]` | NetworkPolicyPeers allowed on port 8080 (metrics, API); empty means nobody |
| `tests.enabled` | `true` | Renders the `helm test` pod, see [Testing a release](#testing-a-release) |
| `tests.image` | `registry.k8s.io/e2e-test-images/jessie-dnsutils:1.7` | Image with `dig` for the test pod |
| `tests.query` | `example.com` | Name the test pod asks for |
| `resources` | requests 50m CPU and 128Mi memory, limit 256Mi memory | Container resources |
| `podAnnotations`, `podLabels`, `nodeSelector`, `tolerations`, `affinity` | empty | Passed to the pod template |

`values.schema.json` rejects unknown keys and invalid values at `helm install`
and `helm lint`.

## Configuration

`config` holds the `[blocking]` part of `dns-rs.toml` (see
[Configuration](configuration.md) and
[`dns-rs.example.toml`](../dns-rs.example.toml)):

```yaml
config: |
  [blocking]
  mode = "nxdomain"
  lists = ["https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"]
  deny = ["ads.example.com"]
```

It is TOML text, not a YAML map: Helm's `toToml` writes integers as floats
(`cache.size = 20000.0`), which dns-rs rejects. See
[ADR 0014](adr/0014-helm-config-as-toml-text.md).

Startup settings do not go in `config`. The chart fails to render if `config`
holds a `[server]`, `[http]`, `[upstream]` or `[cache]` section (or a dotted
key or assignment such as `cache.size = 1` or `cache = { size = 1 }`). Set `upstream.server`, `upstream.timeoutMs` and
`cache.size` in the values instead: the chart passes them to the pods as
environment variables (`DNS_RS_UPSTREAM`, `DNS_RS_UPSTREAM_TIMEOUT_MS`,
`DNS_RS_CACHE_SIZE`). The chart also sets `DNS_RS_LISTEN=0.0.0.0:5353` and
`DNS_RS_HTTP_LISTEN=0.0.0.0:8080` to match the container ports; see
[Container image](container.md#ports).

### Changing the configuration

A change to `config` does not restart pods. dns-rs reads the mounted file
every 10 seconds and applies `[blocking]` changes on the running pods; see
[Reload without restart](configuration.md#reload-without-restart). The kubelet
needs some time to refresh a mounted ConfigMap, so a change can take longer
than 10 seconds to reach a pod.

A change to `upstream.*` or `cache.size` edits the pod template, so Kubernetes
rolls every replica and they never run different values.

## Clients and the DNS Service

Use `service.dns.type: LoadBalancer` with `externalTrafficPolicy: Local` to
keep client IP addresses, which the query log shows
([ADR 0002](adr/0002-stateless-replicas.md)). Do not expose the DNS Service
to the Internet: an open resolver is abused for amplification attacks. See
the warning in [Container image](container.md#run).

## API token

Without `api.token` or `api.existingSecret`, `/api/*` answers `403` (see
[Authentication](metrics.md#authentication)). `/healthz`, `/readyz` and
`/metrics` work without it.

The chart mounts the Secret as a file at `/run/secrets/dns-rs/api-token` and
sets `DNS_RS_API_TOKEN_FILE` to that path. The token is not in the pod spec.
dns-rs reads the file again every 10 seconds, so a rotated Secret reaches
every replica after the kubelet refreshes the mounted file (about a minute),
without restarting pods; this applies to chart-managed and existing Secrets
alike. See [ADR 0015](adr/0015-api-token-file-is-reloaded.md). Removing the
token does not disable the API until pods restart.

## Availability and network

- With more than one replica, the PodDisruptionBudget keeps all but
  `maxUnavailable` pods up during node drains. With one replica it is not
  rendered, so it never blocks a drain.
- Replicas are spread across nodes when possible; `ScheduleAnyway` means the
  scheduler still places them together if it has to.
- The ServiceMonitor selects the http Service through the label
  `app.kubernetes.io/component: http`, which both Services now carry. It needs
  the Prometheus Operator CRDs. With `networkPolicy.enabled`, the chart fails
  to render unless `networkPolicy.http.from` lets Prometheus reach port 8080.
- The NetworkPolicy restricts ingress only; egress stays open because dns-rs
  queries its upstream and downloads blocklists. DNS is open to everyone unless
  `networkPolicy.dns.from` lists peers; port 8080 is closed unless
  `networkPolicy.http.from` lists peers. Kubelet probes come from the node and
  are usually allowed by the CNI regardless.

## Pod security

The pods run as the numeric user and group 65532 with `runAsNonRoot`, a
read-only root filesystem, no privilege escalation, all capabilities dropped
and the `RuntimeDefault` seccomp profile. The user is numeric because the
kubelet cannot check `runAsNonRoot` against a user name such as `nonroot`.
The liveness probe uses `/healthz` and the readiness probe `/readyz`, both on
the `http` port. dns-rs starts its HTTP server before it loads the blocklists
(up to 30 seconds per list), so liveness answers while lists load and
readiness stays `503` until the first policy is installed.

## Testing a release

`helm test <release> --logs` runs a pod that queries the DNS Service with
`dig`, first over UDP, then over TCP. It passes when dns-rs answers, whatever
the answer: `dig` exits 0 on any response (including NXDOMAIN and SERVFAIL)
and 9 when there is none, so the result does not depend on the upstream. Set
`tests.enabled=false` to not render the pod.

With `networkPolicy.dns.from` set, allow pods labelled
`app.kubernetes.io/component=test`, or the test cannot reach the Service.

## Checks in CI

The `chart` job runs `helm lint`, the helm-unittest suites in
`charts/dns-rs/tests` and `kubeconform -strict` against Kubernetes 1.34 on
the rendered manifests, with the default values and with every feature on
(`charts/dns-rs/ci/all-features-values.yaml`).

The `e2e` job installs the chart in a kind cluster with the image built by CI
(`.github/scripts/e2e-kind.sh`). The upstream is the cluster's own DNS, so no
query leaves the cluster. It checks `helm test`, resolution through the
Service, blocking of a denied name, and hot reload: after a `helm upgrade`
that changes `config`, every replica, queried on its pod IP, applies the new
rule with the same pods and no restart. The script refuses any context that
is not `kind-*`. The job is not a required check yet.
