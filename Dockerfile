# syntax=docker/dockerfile:1

# Build with the toolchain pinned in rust-toolchain.toml, on the same Debian
# release as the runtime so the glibc matches.
FROM rust:1.99.1-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin dns-rs \
    && cp target/release/dns-rs /dns-rs

# No shell, no package manager; CA certificates for HTTPS blocklists; runs as
# the nonroot user (UID 65532).
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:83b9b50586253821cf63ffcec87d3d94265a093ad30da232039af962dd8f4edf

LABEL org.opencontainers.image.title="dns-rs" \
      org.opencontainers.image.description="Network-wide DNS sinkhole in Rust" \
      org.opencontainers.image.source="https://github.com/EvannDev/dns-rs" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /dns-rs /usr/local/bin/dns-rs

# DNS on an unprivileged port, so the image runs without capabilities:
# publish it as 53 (docker run -p 53:5353/udp -p 53:5353/tcp, or a
# Kubernetes Service with port 53 and targetPort 5353).
ENV DNS_RS_LISTEN=0.0.0.0:5353 \
    DNS_RS_HTTP_LISTEN=0.0.0.0:8080
EXPOSE 5353/udp 5353/tcp 8080/tcp

# Numeric, so Kubernetes can verify runAsNonRoot: true (the "nonroot" name
# cannot be checked without reading the image's /etc/passwd).
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/dns-rs"]
