# Changelog

All notable changes to dns-rs are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Hot reload: the configuration file is read every 10 seconds (compared by
  content) and on `SIGHUP`. `[blocking]` changes apply without a restart;
  changes to `server.listen`, `upstream.*` and `cache.size` are logged once as
  needing a restart. An invalid or missing file is rejected and the previous
  configuration keeps working (#13).
- `blocking.refresh` (default `24h`, at least `1m`): blocklists are downloaded
  again on this schedule. A list that fails keeps its last valid version (#13).

### Changed

- Configuration parse errors are one line with their position, for example
  `line 4, column 1: unknown field ...` (#13).
- `blocking.deny_regex` and `blocking.allow_regex` are also validated as a
  whole: a list whose patterns compile alone but are too large together is
  rejected at startup or on reload, naming the key (#13).
