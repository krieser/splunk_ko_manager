# Splunk KO Manager

CLI tool for exporting, reviewing, and updating Splunk saved searches via the REST API.

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

# Export only keys defined in local/savedsearches.conf (no --keys required)
python splunk_ko_manager.py \
  --mode export-savedsearches \
  --endpoint 'https://127.0.0.1:8089/servicesNS/nobody/recon/saved/searches/my_search' \
  --credentials user 'admin:password'

# Write JSON to a file
python splunk_ko_manager.py \
  --mode export-savedsearches \
  --endpoint 'https://127.0.0.1:8089/servicesNS/nobody/recon/saved/searches/my_search' \
  --credentials user 'admin:password' \
  --output my_search.local.json

# Dump all non-null REST fields (discovery / troubleshooting)
python splunk_ko_manager.py \
  --mode endpointreview \
  --endpoint 'https://127.0.0.1:8089/servicesNS/nobody/recon/saved/searches/my_search' \
  --credentials user 'admin:password'
```

## Modes

| Mode | Description |
|------|-------------|
| `export-savedsearches` | Export keys defined in `local/savedsearches.conf` for one saved search (REST discovery; stdout or `--output`) |
| `endpointreview` | List all non-null fields returned by the endpoint |
| `update` | POST a JSON payload from `--input` |
| `post` | Create/update with `--input` and `--name` |

## Local key discovery

`export-savedsearches` discovers local keys using Splunk REST only (no `btool` or filesystem access). When inherited baseline endpoints are unavailable, it falls back to `appcontext=true` discovery and filters inherited noise (for example `disabled=false`).

Use `--debug-local-keys` to print discovery details on stderr. JSON output remains clean on stdout.

## Credentials

```bash
--credentials user 'username:password'
--credentials token 'your-bearer-token'
```
