import argparse
import json
import os
import sys
from typing import Dict, Tuple, Optional

__version__ = "1.0.0"

_MISSING = object()

def parse_requested_keys(keys_arg: str) -> list:
    if not keys_arg:
        return []
    return [k.strip() for k in keys_arg.split(",") if k.strip()]

def normalize_content(content) -> dict:
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

_OMIT = object()

def remove_null_values(value):
    """Recursively drop None/null values from dicts and lists."""
    if value is None:
        return _OMIT
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            cleaned_item = remove_null_values(item)
            if cleaned_item is not _OMIT:
                cleaned[key] = cleaned_item
        return cleaned
    if isinstance(value, list):
        cleaned = []
        for item in value:
            cleaned_item = remove_null_values(item)
            if cleaned_item is not _OMIT:
                cleaned.append(cleaned_item)
        return cleaned
    return value

def export_all_fields(entry: dict) -> dict:
    """Export non-null key/value pairs from Splunk REST entry content and metadata."""
    content = normalize_content(entry.get("content", {}))
    out = dict(sorted(content.items()))
    for key in sorted(entry.keys()):
        if key in ("content", "links"):
            continue
        if key not in out:
            out[key] = entry[key]
    cleaned = remove_null_values(out)
    return cleaned if isinstance(cleaned, dict) else {}

def fetch_target_entry(endpoint: str, auth, headers: dict):
    import requests
    res = requests.get(endpoint, auth=auth, headers=headers, params={"output_mode": "json"}, verify=False)
    res.raise_for_status()
    entries = res.json().get("entry", [])
    if not entries:
        print("Error: No search entries found.", file=sys.stderr)
        sys.exit(1)
    return entries[0] if isinstance(entries, list) else entries

def write_json_output(data, output_path: Optional[str], success_message: str = None):
    json_kwargs = {"indent": 2, "ensure_ascii": False, "sort_keys": True}
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, **json_kwargs)
            f.write("\n")
        if success_message:
            print(success_message.format(output_path))
    else:
        print(json.dumps(data, **json_kwargs))

def get_auth_config(credentials_args):
    """Parses the --credentials tuple and returns (auth_tuple, headers_dict)."""
    if len(credentials_args) != 2:
        print("Error: --credentials requires two values. E.g., 'user admin:pass' or 'token <string>'")
        sys.exit(1)
    cred_type, cred_value = credentials_args[0].lower(), credentials_args[1]
    if cred_type == "user":
        if ":" not in cred_value:
            print("Error: For 'user' type, credentials must be in the format 'username:password'")
            sys.exit(1)
        return tuple(cred_value.split(":", 1)), {}
    elif cred_type == "token":
        return None, {"Authorization": f"Bearer {cred_value}"}
    print("Error: Invalid credential type. Must be 'user' or 'token'.")
    sys.exit(1)

def generate_curl_dry_run(method: str, url: str, auth: tuple, headers: dict, payload: dict = None) -> str:
    """Generates a clean, copy-pasteable bash/curl command equivalent."""
    parts = ["curl -k"]
    if method not in ("GET", "POST"):
        parts.append(f"-X {method}")
    if auth:
        parts.append(f"-u '{auth[0]}:{auth[1]}'")
    for k, v in headers.items():
        parts.append(f"-H '{k}: {v}'")
    full_url = f"{url}{'&' if '?' in url else '?'}output_mode=json"
    if payload:
        for k, v in payload.items():
            escaped_value = str(v).replace("'", "'\\''")
            parts.append(f"-d '{k}={escaped_value}'")
    parts.append(f"'{full_url}'")
    return " \\\n  ".join(parts)

def print_summary(mode: str, payload: dict):
    """Prints a clean summary indicating exactly which parameters were altered or added."""
    print(f"\n========================================\n SUCCESS SUMMARY ({mode.upper()} OPERATION)\n========================================")
    print("The following parameters were successfully processed:")
    for k, v in payload.items():
        val = str(v).replace('\n', ' ')
        print(f" -> {k}: {val[:57] + '...' if len(val) > 60 else val}")
    print("========================================\n")

def main():
    parser = argparse.ArgumentParser(
        description="Unified Splunk Knowledge Object Manager (Export, Update, and Post).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--mode", required=True, choices=["export", "endpointreview", "update", "post"])
    parser.add_argument("--endpoint", required=True, help="The Splunk REST endpoint URL.")
    parser.add_argument("--credentials", required=True, nargs=2, metavar=('{user,token}', 'VALUE'))
    parser.add_argument("--keys", help="Required for export mode. Comma-separated keys. Ignored for endpointreview.")
    # Segregated parameters for clean interface control
    parser.add_argument("--input", help="Required for update/post modes. Source payload file path.")
    parser.add_argument("--output", help="Optional for export mode. Destination file path (defaults to STDOUT).")
    parser.add_argument("--name", help="Required for post mode. New resource name identifier.")
    parser.add_argument("--dry-run", action="store_true", help="Print equivalent curl statement.")
    args = parser.parse_args()

    auth, headers = get_auth_config(args.credentials)
    payload = {}

    if args.mode in ("update", "post"):
        if not args.input:
            print(f"Error: --input is required to specify the payload file when using '--mode {args.mode}'")
            sys.exit(1)
        try:
            with open(args.input, "r") as f:
                payload = json.load(f)
        except Exception as e:
            print(f"Error loading payload file '{args.input}': {e}")
            sys.exit(1)
        if args.mode == "post":
            if not args.name:
                print("Error: --name is required when using '--mode post'")
                sys.exit(1)
            payload["name"] = args.name

    if args.dry_run:
        method = "GET" if args.mode in ("export", "endpointreview") else "POST"
        print(f"\n--- DRY RUN: Equivalent Curl Command for {args.mode.upper()} ---")
        print(generate_curl_dry_run(method, args.endpoint, auth, headers, payload))
        if args.mode == "export":
            dest = args.output if args.output else "STDOUT"
            print(f"\nNOTE: Live run writes keys [{args.keys}] to: {dest}\n")
        elif args.mode == "endpointreview":
            dest = args.output if args.output else "STDOUT"
            print(f"\nNOTE: Live run writes all non-null key/value pairs to: {dest}\n")
        return

    import requests, urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        if args.mode == "export":
            requested_keys = parse_requested_keys(args.keys)
            if not requested_keys:
                print("Error: --keys is required when using '--mode export'")
                sys.exit(1)
            target_entry = fetch_target_entry(args.endpoint, auth, headers)
            out_p, missing_keys = export_requested_keys(target_entry, requested_keys)

            if missing_keys:
                content = normalize_content(target_entry.get("content", {}))
                available_keys = sorted(set(content.keys()) | set(target_entry.keys()) - {"content"})
                suggestions = suggest_similar_keys(missing_keys, available_keys)
                print(f"Warning: The following keys were not found in the endpoint response: {missing_keys}", file=sys.stderr)
                for missing, matches in suggestions.items():
                    print(f"  Hint for '{missing}': did you mean one of {matches}?", file=sys.stderr)

            write_json_output(out_p, args.output, "Successfully exported keys to '{}'")

        elif args.mode == "endpointreview":
            target_entry = fetch_target_entry(args.endpoint, auth, headers)
            out_p = export_all_fields(target_entry)
            print(f"Found {len(out_p)} non-null keys on endpoint.", file=sys.stderr)
            write_json_output(out_p, args.output, "Successfully exported all fields to '{}'")

        else:
            res = requests.post(args.endpoint, auth=auth, headers=headers, data=payload, verify=False, params={"output_mode": "json"})
            print(f"Status Code: {res.status_code}")
            if res.status_code in (200, 201):
                print_summary(args.mode, payload)
            else:
                print("Response JSON:\n", json.dumps(res.json(), indent=2) if res.text else res.text)
    except Exception as e:
        if "404" in str(e):
            print("Operation failed: saved search not found at this endpoint (404).", file=sys.stderr)
            print("Check owner/app/search name. Splunk URLs look like:", file=sys.stderr)
            print("  /servicesNS/{owner}/{app}/saved/searches/{exact_search_name}", file=sys.stderr)
            print("List available searches with:", file=sys.stderr)
            print("  curl -sk -u 'admin:pass' 'https://127.0.0.1:8089/servicesNS/nobody/recon/saved/searches?output_mode=json' \\")
            print("    | python3 -c \"import json,sys; [print(e['name']) for e in json.load(sys.stdin).get('entry',[])]\"")
        print(f"Operation failed: {e}")

if __name__ == "__main__":
    main()

