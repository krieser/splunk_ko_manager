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

python splunk_ko_manager.py \
  --mode export \
  --endpoint 'https://127.0.0.1:8089/servicesNS/nobody/recon/saved/searches/my_search' \
  --credentials user 'admin:password' \
  --keys "search,cron_schedule,sharing"

python splunk_ko_manager.py \
  --mode endpointreview \
  --endpoint 'https://127.0.0.1:8089/servicesNS/nobody/recon/saved/searches/my_search' \
  --credentials user 'admin:password'
```

## Modes

| Mode | Description |
|------|-------------|
| `export` | Export specific keys (`--keys` required) |
| `endpointreview` | List all non-null fields returned by the endpoint |
| `update` | POST a JSON payload from `--input` |
| `post` | Create/update with `--input` and `--name` |
