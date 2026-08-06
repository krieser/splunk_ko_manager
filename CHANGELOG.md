# Changelog

All notable changes to `splunk_ko_manager.py` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-08-06

### Added

- **`export-savedsearches` mode** — export keys defined in `local/savedsearches.conf` for a single saved search; no `--keys` required.
- **REST local key discovery** — identifies local keys via baseline diff and `appcontext=true` fallback (no `btool` or `SPLUNK_HOME`).
- **`--debug-local-keys`** — optional stderr diagnostics for local key discovery.

### Changed

- Replaced **`export`** mode and **`--keys`** / **`--include-inherited-keys`** with the dedicated `export-savedsearches` workflow.
- Consolidated HTTP helpers and removed unused code paths (`localonly=true`, duplicate fetch utilities).
- Status and debug messages go to stderr; JSON export stays on stdout or `--output`.

### Fixed

- False positives when Splunk `defaultcontext` responses contain merged effective config instead of true `default/` layer content.
- Extra inherited keys (for example `disabled=false`) filtered from appcontext discovery to match `btool` local validation.

## [1.0.0] - 2026-08-06

First official release of the Splunk Knowledge Object Manager CLI.

### Added

- **`export` mode** — fetch selected fields from a Splunk REST endpoint using a dynamic `--keys` list.
- **`endpointreview` mode** — dump all non-null key/value pairs from an endpoint for discovery and troubleshooting.
- **`update` and `post` modes** — apply JSON payload files to Splunk REST endpoints.
- **Nested and dotted key resolution** — supports Splunk fields such as `action.email.to` and `eai:acl.sharing`.
- **ACL alias lookup** — `--keys sharing` resolves `content.eai:acl.sharing` and `entry.acl.sharing`.
- **Atom-style content normalization** — handles list-shaped Splunk REST `content` payloads.
- **Dry-run support** — `--dry-run` prints an equivalent masked `curl` command without making requests.
- **404 diagnostics** — clearer errors when a saved search URL is wrong (owner/app/name mismatch).
- **Missing-key hints** — warns when requested export keys are absent and suggests similar field names.
- **`--version` flag** — prints the installed script version.
- **`requirements.txt`** — documents runtime dependencies (`requests`, `urllib3`).

### Changed

- Export output uses legible JSON (`indent=2`, sorted keys, UTF-8).
- `endpointreview` filters out `null` values recursively before printing.

[1.2.0]: #
[1.0.0]: #
