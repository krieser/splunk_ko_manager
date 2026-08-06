import argparse
import json
import os
import sys
from typing import Dict, Tuple, Optional

DEFAULT_TIMEOUT = 30  # seconds
_MISSING = object()

def parse_requested_keys(keys_arg: str) -> list:
    """Parse comma-separated key list, ignoring empty segments."""
    if not keys_arg:
        return []
    return [k.strip() for k in keys_arg.split(",") if k.strip()]

def normalize_content(content) -> dict:
    """Normalize Splunk REST content to a flat string-keyed dict."""
    if isinstance(content, dict):
        return content
    if isinstance(content, list):
        normalized = {}
        for item in content:
            if not isinstance(item, dict):
                continue
            key = item.get("name") or item.get("key")
            if key is not None and "value" in item:
                normalized[str(key)] = item["value"]
        return normalized
    return {}

def splunk_key_candidates(requested_key: str) -> list:
    """Return Splunk REST lookup paths for common ACL and config aliases."""
    candidates = [requested_key]
    if requested_key == "sharing":
        candidates.extend(["eai:acl.sharing", "acl.sharing"])
    elif requested_key == "owner":
        candidates.extend(["eai:acl.owner", "acl.owner"])
    elif requested_key.startswith("eai:acl."):
        candidates.append(f"acl.{requested_key.split('.', 1)[1]}")
    elif requested_key.startswith("acl."):
        candidates.append(f"eai:acl.{requested_key.split('.', 1)[1]}")
    return candidates

def get_field_value(source: dict, key: str):
    """Look up a field by flat key or dotted nested path."""
    if not isinstance(source, dict) or not key:
        return _MISSING
    if key in source:
        return source[key]
    if "." not in key:
        return _MISSING

    current = source
    for part in key.split("."):
        if not isinstance(current, dict) or part not in current:
            return _MISSING
        current = current[part]
    return current

def export_requested_keys(entry: dict, requested_keys: list) -> Tuple[dict, list]:
    """Export requested keys from a Splunk REST entry object."""
    content = normalize_content(entry.get("content", {}))
    entry_fields = {k: v for k, v in entry.items() if k != "content"}
    lookup_sources = (content, entry_fields, entry)

    out_p = {}
    missing_keys = []
    for key in requested_keys:
        value = _MISSING
        for candidate in splunk_key_candidates(key):
            for source in lookup_sources:
                candidate_value = get_field_value(source, candidate)
                if candidate_value is not _MISSING:
                    value = candidate_value
                    break
            if value is not _MISSING:
                break
        if value is _MISSING:
            missing_keys.append(key)
            out_p[key] = None
        else:
            out_p[key] = value

    return out_p, missing_keys

def suggest_similar_keys(missing_keys: list, available_keys: list) -> dict:
    """Suggest close key names for missing exports."""
    suggestions = {}
    for missing in missing_keys:
        prefix = missing.split(".")[0]
        matches = sorted(
            k for k in available_keys
            if k == missing or k.startswith(f"{prefix}.") or prefix in k
        )
        if matches:
            suggestions[missing] = matches[:5]
    return suggestions

def _load_http_deps():
    """Import requests/urllib3 only when live HTTP is needed."""
    try:
        import requests
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        import urllib3
        return requests, HTTPAdapter, Retry, urllib3
    except ImportError:
        print(
            "Error: 'requests' is required for live HTTP operations.\n"
            "Install dependencies with:\n"
            "  python3 -m venv .venv && source .venv/bin/activate\n"
            "  pip install -r requirements.txt\n"
            "Then run this script with the venv Python (or an activated venv).",
            file=sys.stderr,
        )
        sys.exit(1)

def create_http_session(retries: int = 3, backoff_factor: float = 0.5):
    """Creates a requests Session configured with retry logic for transient failures."""
    requests, HTTPAdapter, Retry, _urllib3 = _load_http_deps()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session = requests.Session()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def get_auth_config(credentials_args: list) -> Tuple[Optional[Tuple[str, str]], Dict[str, str]]:
    """Parses credentials args or falls back to environment variables."""
    if len(credentials_args) != 2:
        print("Error: --credentials requires two values, e.g., 'user admin:pass' or 'token <string>'", file=sys.stderr)
        sys.exit(1)
        
    cred_type, cred_value = credentials_args[0].lower(), credentials_args[1]

    # Check environment variable overrides if placeholder value provided
    if cred_type == "user":
        if ":" not in cred_value:
            # Check environment fallback
            env_pass = os.environ.get("SPLUNK_PASSWORD")
            if env_pass:
                cred_value = f"{cred_value}:{env_pass}"
            else:
                print("Error: For 'user' type, format must be 'username:password' or set SPLUNK_PASSWORD environment variable.", file=sys.stderr)
                sys.exit(1)
        user, password = cred_value.split(":", 1)
        return (user, password), {}
        
    elif cred_type == "token":
        token = os.environ.get("SPLUNK_TOKEN", cred_value)
        return None, {"Authorization": f"Bearer {token}"}
        
    print("Error: Invalid credential type. Must be 'user' or 'token'.", file=sys.stderr)
    sys.exit(1)

def generate_curl_dry_run(method: str, url: str, auth: Optional[Tuple[str, str]], headers: dict, payload: dict = None, insecure: bool = True) -> str:
    """Generates a clean, copy-pasteable bash/curl command equivalent with masked secrets."""
    parts = ["curl"]
    if insecure:
        parts.append("-k")
    if method not in ("GET", "POST"):
        parts.append(f"-X {method}")
    if auth:
        parts.append(f"-u '{auth[0]}:****'")
    for k, v in headers.items():
        if k.lower() == "authorization":
            parts.append("-H 'Authorization: Bearer ****'")
        else:
            parts.append(f"-H '{k}: {v}'")
            
    separator = '&' if '?' in url else '?'
    full_url = f"{url}{separator}output_mode=json"
    
    if payload:
        for k, v in payload.items():
            escaped_value = str(v).replace("'", "'\\''")
            parts.append(f"-d '{k}={escaped_value}'")
    parts.append(f"'{full_url}'")
    return " \\\n  ".join(parts)

def print_summary(mode: str, payload: dict):
    """Prints a clean summary indicating processed parameters."""
    print(f"\n========================================\n SUCCESS SUMMARY ({mode.upper()} OPERATION)\n========================================")
    print("The following parameters were successfully processed:")
    for k, v in payload.items():
        val = str(v).replace('\n', ' ')
        print(f" -> {k}: {val[:57] + '...' if len(val) > 60 else val}")
    print("========================================\n")

def main():
    parser = argparse.ArgumentParser(description="Unified Splunk Search Manager (Export, Update, and Post).")
    parser.add_argument("--mode", required=True, choices=["export", "update", "post"])
    parser.add_argument("--endpoint", required=True, help="The Splunk REST endpoint URL.")
    parser.add_argument("--credentials", required=True, nargs=2, metavar=('{user,token}', 'VALUE'))
    parser.add_argument("--keys", help="Required for export mode. Comma-separated keys.")
    parser.add_argument("--input", help="Required for update/post modes. Source payload file path.")
    parser.add_argument("--output", help="Optional for export mode. Destination file path (defaults to STDOUT).")
    parser.add_argument("--name", help="Required for post mode. New resource name identifier.")
    parser.add_argument("--insecure", "-k", action="store_true", default=True, help="Disable SSL verification (default: True).")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help=f"HTTP request timeout in seconds (default: {DEFAULT_TIMEOUT}).")
    parser.add_argument("--dry-run", action="store_true", help="Print equivalent curl statement without making requests.")
    args = parser.parse_args()

    auth, headers = get_auth_config(args.credentials)
    payload = {}

    if args.mode in ("update", "post"):
        if not args.input:
            print(f"Error: --input is required to specify the payload file when using '--mode {args.mode}'", file=sys.stderr)
            sys.exit(1)
        if not os.path.exists(args.input):
            print(f"Error: Input file '{args.input}' does not exist.", file=sys.stderr)
            sys.exit(1)
        try:
            with open(args.input, "r") as f:
                payload = json.load(f)
        except Exception as e:
            print(f"Error parsing JSON payload file '{args.input}': {e}", file=sys.stderr)
            sys.exit(1)
            
        if args.mode == "post":
            if not args.name:
                print("Error: --name is required when using '--mode post'", file=sys.stderr)
                sys.exit(1)
            payload["name"] = args.name

    if args.dry_run:
        if args.mode == "export" and not args.keys:
            print("Error: --keys is required when using '--mode export'", file=sys.stderr)
            sys.exit(1)
        method = "GET" if args.mode == "export" else "POST"
        print(f"\n--- DRY RUN: Equivalent Curl Command for {args.mode.upper()} ---")
        print(generate_curl_dry_run(method, args.endpoint, auth, headers, payload, insecure=args.insecure))
        if args.mode == "export":
            dest = args.output if args.output else "STDOUT"
            print(f"\nNOTE: Live run writes keys [{args.keys}] to: {dest}\n")
        return

    requests, _HTTPAdapter, _Retry, urllib3 = _load_http_deps()

    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = create_http_session()

    try:
        if args.mode == "export":
            requested_keys = parse_requested_keys(args.keys)
            if not requested_keys:
                print("Error: --keys is required when using '--mode export'", file=sys.stderr)
                sys.exit(1)
                
            res = session.get(
                args.endpoint,
                auth=auth,
                headers=headers,
                params={"output_mode": "json"},
                verify=not args.insecure,
                timeout=args.timeout
            )
            res.raise_for_status()
            
            data = res.json()
            entries = data.get("entry", [])
            if not entries:
                print("Error: No search entries found in response.", file=sys.stderr)
                sys.exit(1)
            
            target_entry = entries[0] if isinstance(entries, list) else entries
            out_p, missing_keys = export_requested_keys(target_entry, requested_keys)

            if missing_keys:
                content = normalize_content(target_entry.get("content", {}))
                available_keys = sorted(set(content.keys()) | set(target_entry.keys()) - {"content"})
                suggestions = suggest_similar_keys(missing_keys, available_keys)
                print(
                    f"Warning: The following keys were not found in the endpoint response: {missing_keys}",
                    file=sys.stderr,
                )
                for missing, matches in suggestions.items():
                    print(f"  Hint for '{missing}': did you mean one of {matches}?", file=sys.stderr)

            if args.output:
                with open(args.output, "w") as f:
                    json.dump(out_p, f, indent=2)
                print(f"Successfully exported keys to '{args.output}'")
            else:
                print(json.dumps(out_p, indent=2))
                
        else:
            res = session.post(
                args.endpoint,
                auth=auth,
                headers=headers,
                data=payload,
                params={"output_mode": "json"},
                verify=not args.insecure,
                timeout=args.timeout
            )
            
            print(f"Status Code: {res.status_code}")
            if res.status_code in (200, 201):
                print_summary(args.mode, payload)
            else:
                print("Error response received from Splunk:", file=sys.stderr)
                try:
                    print(json.dumps(res.json(), indent=2), file=sys.stderr)
                except Exception:
                    print(res.text, file=sys.stderr)
                sys.exit(1)  # Signal failure to calling environment/CI pipeline

    except requests.exceptions.RequestException as e:
        print(f"HTTP Operation failed: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
