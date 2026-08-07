# Splunk KO Manager

CLI tool for exporting, reviewing, and migrating Splunk knowledge objects and `.conf` stanzas via the REST API.

## Requirements

- Python 3.9+
- `requests` and `urllib3` (see `requirements.txt`)

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python splunk_ko_manager.py --version

# Saved search — SPL provides KO endpoint (/saved/searches/{name})
python splunk_ko_manager.py \
  --mode export-savedsearches \
  --endpoint 'https://127.0.0.1:8089/servicesNS/nobody/recon/saved/searches/my_search' \
  --credentials user 'admin:password'

# Props — SPL provides conf endpoint (/configs/conf-props/{stanza})
python splunk_ko_manager.py \
  --mode export-props \
  --endpoint 'https://127.0.0.1:8089/servicesNS/nobody/myapp/configs/conf-props/sourcetype%3A%3Aaws%3Acloudtrail' \
  --credentials user 'admin:password' \
  --migration-envelope

# Transforms — SPL provides conf endpoint (/configs/conf-transforms/{stanza})
python splunk_ko_manager.py \
  --mode export-transforms \
  --endpoint 'https://127.0.0.1:8089/servicesNS/nobody/myapp/configs/conf-transforms/my_transform' \
  --credentials user 'admin:password'

# Manual key export (any endpoint)
python splunk_ko_manager.py \
  --mode export \
  --endpoint 'https://127.0.0.1:8089/servicesNS/nobody/recon/saved/searches/my_search' \
  --credentials user 'admin:password' \
  --keys 'search,cron_schedule,description'
```

## Modes

| Mode | Endpoint format | Description |
|------|-----------------|-------------|
| `export` | Any REST URL | Export explicit `--keys` list |
| `export-savedsearches` | `/saved/searches/{name}` | Local `savedsearches.conf` keys |
| `export-props` | `/configs/conf-props/{stanza}` | Local `props.conf` keys |
| `export-transforms` | `/configs/conf-transforms/{stanza}` | Local `transforms.conf` keys |
| `endpointreview` | Any REST URL | All non-null fields (discovery) |
| `update` | Target REST URL | POST JSON from `--input` |
| `post` | Target REST URL | POST JSON from `--input` + `--name` |

## Local key discovery

All `export-*` modes export **only keys from `local/{conf_file}`** — never the full merged effective configuration.

Discovery (stderr always logs a summary; `--debug-local-keys` adds btool validation hints):

1. Fetch merged stanza and `appcontext=true` from the conf REST endpoint.
2. Build inherited baseline (system `[default]` + app `default/` when available).
3. Compute baseline diff; cross-check with appcontext and prefer intersection when both are trustworthy.
4. **Reject** sets that look like merged config (≥15% of merged keys or ≥20 keys).
5. Export values from the **conf stanza endpoint only**.

Example stderr:

```text
Local export [savedsearches.conf] app='recon' stanza='my_search'
  merged_keys=157 baseline_keys=0 baseline_diff=0 appcontext=4
  method=appcontext local_keys=4
  keys=['cron_schedule', 'description', 'search', 'auto_summarize.command']
  source=REST (appcontext app-local keys)
```

### Props and transforms endpoint notes

- SPL inventory searches should emit **URL-encoded** conf stanza paths.
- Example stanza `[sourcetype::aws:cloudtrail]` → encode as `%5Bsourcetype%3A%3Aaws%3Acloudtrail%5D` in the endpoint URL.
- Props often reference transforms by name — include both in migration manifests and migrate transforms before props.

### Migration envelope

**Stdout is always flat local key JSON** for all `export-*` modes:

```json
{
  "LINE_BREAKER": "([\\r\\n]+)",
  "NO_BINARY_CHECK": "1",
  "category": "Custom"
}
```

Use `--migration-envelope --output manifest.json` to **additionally** write metadata to a file. Discovery logs always go to stderr.

## Conf type registry

| Conf type | CLI mode | Status |
|-----------|----------|--------|
| savedsearches | `export-savedsearches` | Available |
| props | `export-props` | Available |
| transforms | `export-transforms` | Available |
| macros | — | Phase 3 |
| views | — | Phase 3 |

## Credentials

```bash
--credentials user 'username:password'
--credentials token 'your-bearer-token'
```
