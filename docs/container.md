# Container image

The image is built from the [`Dockerfile`](../Dockerfile) at the repository
root. It builds with the toolchain pinned in `rust-toolchain.toml` and ships
the binary on `gcr.io/distroless/cc-debian13:nonroot`: no shell, no package
manager, CA certificates for HTTPS blocklists, and the `nonroot` user
(UID 65532). The base images are pinned by digest and Dependabot keeps the
digests up to date.

## Published images

The `Image` workflow publishes `ghcr.io/evanndev/dns-rs` for `linux/amd64`
and `linux/arm64` as one multi-platform manifest.

| Tag | Published from |
|---|---|
| `edge` | Every push to `main` |
| `sha-<commit>` | Every push to `main` |
| `X.Y.Z` and `X.Y` | A `v*` tag |

The workflow can also be started manually. Pull requests build the image and
smoke-test it in CI but do not publish it.

## Run

```sh
docker run -d -p 53:5353/udp -p 53:5353/tcp -p 8080:8080 \
  -v "$PWD/dns-rs.toml:/etc/dns-rs/dns-rs.toml:ro" -e DNS_RS_CONFIG=/etc/dns-rs/dns-rs.toml \
  ghcr.io/evanndev/dns-rs:edge
```

Do not publish the DNS port to the Internet. dns-rs answers any client, so
an exposed port makes it an open resolver: attackers use those to amplify
denial-of-service attacks. Keep it on your LAN (publish on a private
address, `-p 192.168.1.10:53:5353/udp`), or restrict it with a firewall or a
Kubernetes NetworkPolicy.

Without `DNS_RS_CONFIG` the defaults apply (see
[Configuration](configuration.md)).

## Ports

The image sets two environment variables so that it runs without
capabilities or sysctls:

| Variable | Value in the image | Serves |
|---|---|---|
| `DNS_RS_LISTEN` | `0.0.0.0:5353` | DNS, UDP and TCP |
| `DNS_RS_HTTP_LISTEN` | `0.0.0.0:8080` | Probes, metrics and API |

Publish the DNS port as 53 on the host (`-p 53:5353/udp -p 53:5353/tcp`). In
Kubernetes, use a Service with `port: 53` and `targetPort: 5353`.

Environment variables override the configuration file, so `server.listen` and
`http.listen` in a mounted file have no effect unless you also override these
variables (for example `-e DNS_RS_LISTEN=0.0.0.0:53`).

## Signals

`SIGTERM` (sent by `docker stop`) and Ctrl-C stop dns-rs. `SIGHUP` reloads the
configuration, as described in
[Configuration](configuration.md#reload-without-restart).
