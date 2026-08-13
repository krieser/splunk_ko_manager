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

# Manual key export — only keys defined in local/ are returned for conf/KO endpoints
python splunk_ko_manager.py \
  --mode export \
  --endpoint 'https://127.0.0.1:8089/servicesNS/nobody/recon/saved/searches/my_search' \
  --credentials user 'admin:password' \
  --keys 'search,cron_schedule,description'
```

## Modes

| Mode | Endpoint format | Description |
|------|-----------------|-------------|
| `export` | Any REST URL | Export explicit `--keys`; for conf/KO URLs, **local/** keys only (inherited/merged keys omitted) |
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

1. List app `default/` stanzas (collection `defaultonly=true`) and fetch `appcontext=true`.
2. **Local-only stanza** (not in app `default/`): export refined appcontext keys — **2 REST GETs**, no merged fetch when fewer than 20 keys.
3. **Default/ stanza**: diff `appcontext` vs `defaultonly` — **3 REST GETs**, no merged fetch.
4. **Fallback** (large appcontext set or default layer fetch failed): fetch merged effective config and inherited baseline; cross-check and reject merged-looking sets (≥15% of merged keys or ≥20 keys).
5. Export values from the **conf stanza endpoint only**.

Example stderr:

```text
Local export [savedsearches.conf] app='recon' stanza='my_search'
  merged_keys=157 baseline_keys=0 baseline_diff=0 appcontext=4
  method=appcontext local_keys=4
  keys=['cron_schedule', 'description', 'search', 'auto_summarize.command']
  source=REST (appcontext app-local keys)
```

## Default-layer export (`--default_only`)

Use **`--default_only`** with any **`export-*`** mode to export the app **`default/`** layer instead of `local/`. Does **not** apply to `export`, `update`, `post`, or `endpointreview`.

| Behavior | Default (local export) | `--default_only` |
|----------|------------------------|------------------|
| Conf keys | `appcontext=true` / baseline diff | `defaultonly=true` (falls back to `defaultcontext` on older builds) |
| Default-only stanzas | **Rejected** (no output; use `--default_only`) | Exported |
| Local keys | Exported | **Suppressed** (listed in stderr as `local_only_suppressed`) |
| Views | `local/data/ui/views/` XML | `default/data/ui/views/` XML; local overrides suppressed |
| Inventory | Per stanza | Also logs `default_collection_stanzas` — all stanzas in app default/ for that conf type |

Discovery minimizes REST calls:

1. List app `default/` stanzas (collection `defaultonly=true`).
2. If stanza **not listed** → reject (local-only); optional `appcontext` + merged only to refine the error.
3. If stanza **listed** → fetch `defaultonly=true` for that stanza (reuses the same response for export values).
4. Optional `appcontext=true` for `local_only_suppressed` stderr audit keys.
5. **Views:** probe `defaultcontext` first, then `appcontext`, then effective only as fallback.

Example stderr (conf):

```text
Default export [props.conf] app='myapp' stanza='firewall'
  merged_keys=0 default_layer_keys=12 appcontext_suppressed=3 local_only_suppressed=3
  method=defaultonly default_keys=12 default_collection_stanzas=847
  keys=['TRANSFORMS', 'SHOULD_LINEMERGE', ...]
  suppressed_local_only_keys=['description']
```

```bash
# Shipped props stanza from app default/
python splunk_ko_manager.py --mode export-props --default_only \
  --endpoint 'https://127.0.0.1:8089/servicesNS/nobody/SA-NetworkProtection/configs/conf-props/firewall' \
  --credentials user 'admin:password'

# Shipped ES dashboard from default/data/ui/views/
python splunk_ko_manager.py --mode export-views --default_only \
  --endpoint 'https://127.0.0.1:8089/servicesNS/nobody/SplunkEnterpriseSecuritySuite/data/ui/views/aaa' \
  --credentials user 'admin:password' \
  --output aaa_default.json
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
