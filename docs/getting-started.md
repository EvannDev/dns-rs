# Getting started

This page takes you from nothing to a dns-rs that answers queries and blocks
a domain, first with the container image, then with Helm.

## Run the container

Write a minimal configuration, `dns-rs.toml`. Every key is optional; this
one blocks one name and loads one public blocklist:

```toml
[blocking]
lists = ["https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"]
deny = ["ads.example.com"]
```

Start the image, publishing the DNS port on a private address of the host
(replace `192.168.1.10` with yours):

```sh
docker run -d --name dns-rs \
  -p 192.168.1.10:53:5353/udp -p 192.168.1.10:53:5353/tcp -p 127.0.0.1:8080:8080 \
  -v "$PWD/dns-rs.toml:/etc/dns-rs/dns-rs.toml:ro" -e DNS_RS_CONFIG=/etc/dns-rs/dns-rs.toml \
  ghcr.io/evanndev/dns-rs:edge
```

`edge` follows the `main` branch. Released versions are tagged `X.Y.Z` and
`X.Y`; see [Container image](container.md#published-images). Inside the
container dns-rs listens on 5353, which is why the host port 53 maps to it.

Do not publish the DNS port to the Internet: an open resolver is abused for
denial-of-service amplification.

## Check that it answers

```sh
dig @192.168.1.10 example.com
dig @192.168.1.10 ads.example.com
```

The first query is forwarded to the upstream (`1.1.1.1:53` by default). The
second is blocked and gets `0.0.0.0`, the default blocking mode. Watch the
log with `docker logs dns-rs`: each query is one line with its source
(`blocked`, `cache`, `upstream`...); see [Logging](logging.md#query-log). The
probe `curl http://127.0.0.1:8080/readyz` answers `ready` once the sockets are
bound and the first blocking policy is installed; see
[Metrics and probes](metrics.md).

## Point your clients at it

dns-rs has no DHCP server ([ADR 0004](adr/0004-no-dhcp-server.md)). Use one
of these:

- In your router's DHCP settings, set the DNS server announced to clients to
  the address of the host running dns-rs. This covers the whole network.
- Or set the DNS server on a single device to try it first.

Then query from a client and confirm the entries appear in the log.

## Run it on Kubernetes

The Helm chart is published as an OCI artifact on a `v*` tag (see
[Releasing](releasing.md)). Replace the version with the one you want:

```sh
helm install dns-rs oci://ghcr.io/evanndev/charts/dns-rs --version 0.1.0 \
  --namespace dns --create-namespace
```

The configuration goes in the `config` value as TOML text, for example in a
`values.yaml`:

```yaml
config: |
  [blocking]
  lists = ["https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"]
```

Apply it with `-f values.yaml`. The chart runs two replicas behind a Service
on port 53, with probes, a PodDisruptionBudget and `helm test`. See
[Kubernetes](kubernetes.md) for the values, the client-IP setup and the API
token.

## Next steps

- [Configuration](configuration.md): every setting, and what reloads without
  a restart.
- [Blocklists](blocklists.md): formats, your own rules, blocking modes.
- Coming from Pi-hole? Read [Migrating from Pi-hole](migrating-from-pihole.md).
- The commented
  [`dns-rs.example.toml`](https://github.com/EvannDev/dns-rs/blob/main/dns-rs.example.toml)
  lists every key with its default.
