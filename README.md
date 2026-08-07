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

# Macro — SPL provides KO or conf endpoint
python splunk_ko_manager.py \
  --mode export-macros \
  --endpoint 'https://127.0.0.1:8089/servicesNS/nobody/myapp/saved/macros/my_macro' \
  --credentials user 'admin:password'

# View — SPL provides saved/views, data/ui/views, or conf-views endpoint
python splunk_ko_manager.py \
  --mode export-views \
  --endpoint 'https://127.0.0.1:8089/servicesNS/nobody/myapp/saved/views/my_view' \
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
| `export-macros` | `/saved/macros/{name}` or `/configs/conf-macros/{name}` | Local `macros.conf` keys |
| `export-views` | `/saved/views/{name}`, `/data/ui/views/{name}`, or `/configs/conf-views/{name}` | Local-only dashboard XML (`eai:data`) from `local/data/ui/views/` |
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

### Macros and views endpoint notes

- **Macros:** SPL may emit `/saved/macros/{name}` or `/configs/conf-macros/{name}`.
- **Views:** SPL may emit `/saved/views/{name}`, `/data/ui/views/{name}`, or `/configs/conf-views/{name}`. Export resolves to **`data/ui/views`**, verifies the dashboard exists in a **`local/data/ui/views/`** layer (REST-only), then returns **`eai:data`**. App-shipped **`default/data/ui/views/`** dashboards are **rejected**.

**Local view discovery (stderr; `--debug-local-keys` adds filesystem validation hints):**

1. Prefer `appcontext=true` / `defaultcontext=true` when Splunk supports them on `data/ui/views`.
2. Otherwise use `local.meta` stanza probes (`[views/{name}]`) and REST entry path hints.
3. Reject when no local layer can be confirmed (likely `default/data/ui/views/` only).

Example stderr:

```text
View export [local/data/ui/views] app='recon' owner='nobody' view='my_dashboard'
  effective=true appcontext=true defaultcontext=true
  method=appcontext source=REST (appcontext local/data/ui/views)
  xml_bytes=4821
```

**View migration workflow:**

```bash
# Export (source)
python splunk_ko_manager.py --mode export-views \
  --endpoint 'https://127.0.0.1:8089/servicesNS/nobody/myapp/saved/views/my_dashboard' \
  --credentials user 'admin:password' \
  --output my_dashboard.json

# Update existing view (target)
python splunk_ko_manager.py --mode update \
  --endpoint 'https://target:8089/servicesNS/nobody/myapp/data/ui/views/my_dashboard' \
  --credentials user 'admin:password' \
  --input my_dashboard.json

# Create new view (target) — POST needs collection URL + --name
python splunk_ko_manager.py --mode post \
  --endpoint 'https://target:8089/servicesNS/nobody/myapp/data/ui/views' \
  --credentials user 'admin:password' \
  --name my_dashboard \
  --input my_dashboard.json
```

The export JSON includes `eai:data` (required) and `name`. Dashboard title/description are inside the XML. On `update`/`post` to `data/ui/views`, unsupported fields like `label` are stripped automatically.

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
| macros | `export-macros` | Available |
| views | `export-views` | Available |

## Credentials

```bash
--credentials user 'username:password'
--credentials token 'your-bearer-token'
```
