# Changelog

All notable changes to `splunk_ko_manager.py` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.7.0] - 2026-08-17

### Added

- **`--mode delete`** — DELETE a single Splunk REST entity via `--endpoint` for all supported KO types (saved searches, props, transforms, macros, views); resolves view URLs to `data/ui/views`; rejects collection-only URLs; supports `--dry-run`.

## [1.6.1] - 2026-08-13

### Changed

- **Local export REST minimization** — probe default/ collection + `appcontext=true` first; fetch `defaultonly=true` and merged effective config only when needed.
- **`--default_only` REST minimization** — list default/ stanzas before per-stanza fetch; reuse `defaultonly` discovery response for export values; skip merged on happy path; views probe `defaultcontext` before `appcontext`/effective.
- **`--mode export --keys`** — for conf/KO endpoints, export only keys defined in `local/` (inherited/merged keys omitted with stderr warning).

### Added

- **`.gitignore`** — ignore local Splunk test scratch files and export snapshots.

## [1.6.0] - 2026-08-09

### Added

- **`--default_only` flag** for all `export-*` modes — export app **`default/`** layer only via REST `defaultonly=true` (with `defaultcontext` fallback); local keys and local view overrides are suppressed.
- **`DefaultDiscoveryResult`** — tracks `default_keys`, `default_collection_stanzas` (all stanzas in app default/ for that conf type), and `local_only_keys` (suppressed).
- **`DefaultViewDiscoveryResult`** — default-layer dashboard discovery with local override suppression.

## [1.5.0] - 2026-08-07

### Added

- **`export-macros` mode** — export locally-defined keys from `macros.conf` via `/saved/macros/{name}` or `/configs/conf-macros/{name}`.
- **`export-views` mode** — export local-only dashboard XML/definition via `data/ui/views` (`eai:data`); rejects `default/data/ui/views/` dashboards.
- Direct **`configs/conf-*`** URL support for KO types (macros, saved searches) in addition to KO collection URLs.

### Changed

- **`export-views`** fetches dashboard XML from `data/ui/views` instead of local `views.conf` keys (dashboards are stored as XML/JSON files, not conf stanzas).
- **`export-views`** exports **local-only** dashboards (`local/data/ui/views/`) and rejects app-shipped `default/` views.
- **View `update`/`post`** strips unsupported fields (`label`, `description`, etc.); Splunk accepts only `eai:data` and `name` (post).

## [1.4.3] - 2026-08-07

### Fixed

- **Props `pulldown_type`** — no longer filtered when `=1`; btool includes explicit local assignments even at default values.

## [1.4.2] - 2026-08-07

### Fixed

- **`export-*` stdout is flat local key JSON only** — migration envelope writes to `--output` when requested, never replaces stdout.
- **Props inherited noise** — filter `disabled=false` only; keep `pulldown_type=1` when present in appcontext (matches btool local/).
- Success messages and file-write confirmations go to stderr, not stdout.

## [1.4.1] - 2026-08-07

### Added

- **Strict local-only export** — all `export-*` modes reject candidate key sets that look like merged effective config.
- **Baseline ∩ appcontext cross-check** — local keys require agreement when both discovery paths are available.
- **Always-on local discovery logging** — stderr summary for every `export-*` run; `--debug-local-keys` adds btool validation hints.
- **`discovery_method` field** in migration envelope.

### Changed

- Local export values always fetched from `configs/conf-*` stanza endpoints, not KO collection URLs.
- Local export output omits null/missing keys; only discovered local keys with values are written.

## [1.4.0] - 2026-08-07

### Added

- **`export-props` mode** — export locally-defined keys from `props.conf` stanzas via REST.
- **`export-transforms` mode** — export locally-defined keys from `transforms.conf` stanzas via REST.

### Changed

- Conf-only export modes use `/configs/conf-{type}/{stanza}` endpoints (URL-encoded stanzas supported).
- 404 errors include mode-specific endpoint format hints.

## [1.3.0] - 2026-08-07

### Added

- **`ConfTypeSpec` registry** — conf-type metadata for savedsearches and future types (props, transforms, macros, views).
- **Generic local conf discovery** — `discover_local_conf_keys()` replaces savedsearches-specific logic.
- **`--migration-envelope`** — optional migration JSON wrapper for local export output.
- **`run_export_local()`** — shared export path for all future `export-*` local modes.

### Changed

- Savedsearch export behavior unchanged by default (flat JSON without `--migration-envelope`).
- Discovery, baseline fetch, and appcontext filtering driven by registry per conf type.

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

[1.7.0]: https://github.com/krieser/splunk_ko_manager/releases/tag/v1.7.0
[1.6.1]: https://github.com/krieser/splunk_ko_manager/releases/tag/v1.6.1
[1.6.0]: https://github.com/krieser/splunk_ko_manager/releases/tag/v1.6.0
[1.5.0]: #
[1.4.3]: #
[1.4.2]: #
[1.4.1]: #
[1.4.0]: #
[1.3.0]: #
[1.2.0]: #
[1.0.0]: #
