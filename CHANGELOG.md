# Changelog

All notable changes to dns-rs are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Caching DNS forwarder over UDP and TCP, with a TOML configuration file
  and `DNS_RS_*` environment overrides.
- Blocking of domains from blocklists and from `allow`, `deny`,
  `allow_regex` and `deny_regex` rules, with four blocking modes (#2).
- One log line per answered query, under the `dns_rs::query` target (#2).
- Blocklists downloaded over HTTPS or HTTP, with a timeout, a size limit,
  bounded concurrency and no HTTPS-to-HTTP redirects (#7).
- Wildcard blocklists: `*.domain` lines and `{ url = "…", wildcard = true }`
  list entries (#8).

### Fixed

- Hosts files with IPv6 zone IDs (`fe80::1%lo0`) are accepted (#2).
