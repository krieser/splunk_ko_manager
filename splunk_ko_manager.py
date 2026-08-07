#!/usr/bin/env python3
"""Splunk Knowledge Object Manager — REST CLI for saved searches and related KOs."""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import List, Optional, Set, Tuple
from urllib.parse import quote, unquote, urlparse, urlunparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__version__ = "1.2.1"

_MISSING = object()
_SAVEDSEARCH_ENDPOINT_RE = re.compile(
    r"/servicesNS/([^/]+)/([^/]+)/saved/searches/([^/?#]+)/?$"
)
_CONF_ENDPOINT_RE = re.compile(
    r"^(?P<prefix>https?://[^/]+/servicesNS/)(?P<owner>[^/]+)/(?P<app>[^/]+)/configs/conf-savedsearches/"
)
_CONF_METADATA_KEY_PREFIXES = ("eai:",)
# Keys Splunk usually omits from local/ unless explicitly overridden to a non-default value.
_INHERITED_UNLESS_NONDEFAULT = frozenset({"disabled", "enableSched", "counttype"})

def parse_requested_keys(keys_arg: Optional[str]) -> List[str]:
    if not keys_arg:
        return []
    return [k.strip() for k in keys_arg.split(",") if k.strip()]

def parse_savedsearch_endpoint(endpoint: str) -> Optional[Tuple[str, str, str]]:
    """Parse owner, app, and saved search name from a Splunk REST endpoint."""
    match = _SAVEDSEARCH_ENDPOINT_RE.search(urlparse(endpoint).path)
    if not match:
        return None
    owner, app, search_name = match.groups()
    return unquote(owner), unquote(app), unquote(search_name)

def normalize_conf_owner(owner: str) -> str:
    """Map REST wildcard owner to app-shared namespace used by configs endpoints."""
    return "nobody" if owner in ("-", "nobody") else owner

def build_conf_savedsearch_endpoint(endpoint: str) -> Optional[str]:
    """Build configs/conf-savedsearches endpoint from a saved/searches URL."""
    parsed = urlparse(endpoint)
    parts = parse_savedsearch_endpoint(endpoint)
    if not parts:
        return None
    owner, app, stanza_name = parts
    owner = normalize_conf_owner(owner)
    path = f"/servicesNS/{quote(owner, safe='')}/{quote(app, safe='')}/configs/conf-savedsearches/{quote(stanza_name, safe='')}"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))

def build_conf_stanza_endpoint(conf_endpoint: str, stanza_name: str, owner: Optional[str] = None, app: Optional[str] = None) -> Optional[str]:
    """Build a configs/conf-savedsearches URL for another stanza and/or namespace."""
    match = _CONF_ENDPOINT_RE.match(conf_endpoint)
    if not match:
        return None
    owner = owner if owner is not None else match.group("owner")
    app = app if app is not None else match.group("app")
    prefix = match.group("prefix")
    return f"{prefix}{quote(owner, safe='')}/{quote(app, safe='')}/configs/conf-savedsearches/{quote(stanza_name, safe='')}"

def is_conf_metadata_key(key: str) -> bool:
    return any(key.startswith(prefix) for prefix in _CONF_METADATA_KEY_PREFIXES)

def normalize_conf_value(value) -> str:
    """Normalize Splunk conf values for inherited-vs-local comparison."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return str(value)
    return str(value).strip()

def is_empty_conf_value(value) -> bool:
    """Match btool validation that drops blank assignments (grep -v ' = $')."""
    if value is None:
        return True
    if isinstance(value, str) and value.strip() == "":
        return True
    return False

def extract_conf_content(entry: Optional[dict]) -> dict:
    if not entry:
        return {}
    return normalize_content(entry.get("content", {}))

def splunk_get_json(
    endpoint: str,
    auth,
    headers: dict,
    params: Optional[dict] = None,
    *,
    optional: bool = False,
) -> Optional[dict]:
    """GET a Splunk REST endpoint and return parsed JSON."""
    request_params = {"output_mode": "json"}
    if params:
        request_params.update(params)
    response = requests.get(
        endpoint,
        auth=auth,
        headers=headers,
        params=request_params,
        verify=False,
    )
    if optional and response.status_code == 404:
        return None
    response.raise_for_status()
    return response.json()

def fetch_rest_entry(
    endpoint: str,
    auth,
    headers: dict,
    params: Optional[dict] = None,
    *,
    optional: bool = False,
) -> Optional[dict]:
    """Return the first REST entry document, or None when optional and missing."""
    payload = splunk_get_json(endpoint, auth, headers, params=params, optional=optional)
    if not payload:
        return None
    entries = payload.get("entry", [])
    if not entries:
        return None
    return entries[0] if isinstance(entries, list) else entries

def keys_defined_locally(app_content: dict, baseline: dict) -> List[str]:
    """
    Keys Splunk would write to local/ because they are absent from or differ
    from lower-precedence layers (system/app default), mirroring btool local/.
    """
    local_keys = []
    for key, value in app_content.items():
        if is_conf_metadata_key(key):
            continue
        if is_empty_conf_value(value):
            continue
        if key not in baseline:
            local_keys.append(key)
        elif normalize_conf_value(value) != normalize_conf_value(baseline[key]):
            local_keys.append(key)
    return sorted(local_keys)

def looks_like_merged_config(candidate: dict, merged_content: dict) -> bool:
    """Detect when a defaultcontext response is actually merged effective config."""
    if not candidate or not merged_content:
        return False
    if len(candidate) >= max(20, int(len(merged_content) * 0.9)):
        return True
    shared_keys = [key for key in candidate if key in merged_content]
    if not shared_keys:
        return False
    matching = sum(
        1
        for key in shared_keys
        if normalize_conf_value(candidate[key]) == normalize_conf_value(merged_content[key])
    )
    return matching / len(shared_keys) >= 0.95

def is_likely_inherited_default_key(key: str, value) -> bool:
    """Drop common inherited keys that appcontext still surfaces as false/0/null."""
    if key not in _INHERITED_UNLESS_NONDEFAULT:
        return False
    return normalize_conf_value(value) in ("", "0", "false")

def refine_appcontext_local_keys(app_content: dict) -> List[str]:
    keys = []
    for key, value in app_content.items():
        if is_conf_metadata_key(key) or is_empty_conf_value(value):
            continue
        if is_likely_inherited_default_key(key, value):
            continue
        keys.append(key)
    return sorted(keys)

def conf_collection_endpoint(conf_endpoint: str) -> str:
    return conf_endpoint.rsplit("/", 1)[0]

def conf_stanza_name(conf_endpoint: str) -> str:
    return unquote(conf_endpoint.rsplit("/", 1)[-1])

def conf_server_origin(conf_endpoint: str) -> str:
    parsed = urlparse(conf_endpoint)
    return f"{parsed.scheme}://{parsed.netloc}"

def list_conf_stanza_names(
    collection_endpoint: str,
    auth,
    headers: dict,
    params: Optional[dict] = None,
) -> Set[str]:
    request_params = {"count": 0}
    if params:
        request_params.update(params)
    try:
        payload = splunk_get_json(collection_endpoint, auth, headers, params=request_params)
    except Exception:
        return set()
    return {
        entry.get("name")
        for entry in payload.get("entry", [])
        if entry.get("name")
    }

def find_conf_collection_entry(
    collection_endpoint: str,
    stanza_name: str,
    auth,
    headers: dict,
    params: Optional[dict] = None,
) -> Optional[dict]:
    request_params = {"count": 0}
    if params:
        request_params.update(params)
    try:
        payload = splunk_get_json(collection_endpoint, auth, headers, params=request_params)
    except Exception:
        return None
    for entry in payload.get("entry", []):
        if entry.get("name") == stanza_name:
            return entry
    return None

def fetch_global_default_layers(
    conf_endpoint: str,
    auth,
    headers: dict,
    debug: bool = False,
) -> dict:
    """Collect system/app [default] stanza settings from several REST paths."""
    origin = conf_server_origin(conf_endpoint)
    layers = {}
    sources = []

    candidates: List[Tuple[str, Optional[str], Optional[dict]]] = [
        ("system-ns-default", build_conf_stanza_endpoint(conf_endpoint, "default", owner="nobody", app="system"), None),
        ("system-ns-bracket", build_conf_stanza_endpoint(conf_endpoint, "[default]", owner="nobody", app="system"), None),
        ("system-ns-coll-default", f"{origin}/servicesNS/nobody/system/configs/conf-savedsearches", None),
        ("system-ns-wildcard-default", f"{origin}/servicesNS/-/-/configs/conf-savedsearches/default", None),
        ("system-svc-default", f"{origin}/services/configs/conf-savedsearches/default", None),
        ("system-svc-bracket", f"{origin}/services/configs/conf-savedsearches/%5Bdefault%5D", None),
        ("app-default-ctx", build_conf_stanza_endpoint(conf_endpoint, "default"), {"defaultcontext": "true"}),
        ("app-bracket-ctx", build_conf_stanza_endpoint(conf_endpoint, "[default]"), {"defaultcontext": "true"}),
        (
            "system-props-default",
            f"{origin}/servicesNS/nobody/system/properties/savedsearches/default",
            None,
        ),
        (
            "system-props-bracket",
            f"{origin}/servicesNS/nobody/system/properties/savedsearches/%5Bdefault%5D",
            None,
        ),
    ]

    for source_name, url, params in candidates:
        if not url:
            continue
        if source_name == "system-ns-coll-default":
            for stanza in ("default", "[default]"):
                entry = find_conf_collection_entry(url, stanza, auth, headers, params=params)
                content = extract_conf_content(entry)
                if content:
                    before = len(layers)
                    layers.update(content)
                    if len(layers) > before:
                        sources.append(f"{source_name}:{stanza}")
            continue
        content = extract_conf_content(fetch_rest_entry(url, auth, headers, params=params, optional=True))
        if content:
            before = len(layers)
            layers.update(content)
            if len(layers) > before:
                sources.append(source_name)

    if debug:
        print(
            f"Debug inherited [default] sources: {sources or 'none'} keys={len(layers)}",
            file=sys.stderr,
        )

    return layers

def fetch_app_default_stanza_layer(
    conf_endpoint: str,
    stanza_name: str,
    merged_content: dict,
    auth,
    headers: dict,
    debug: bool = False,
) -> Tuple[dict, bool]:
    """
    Return app default/ settings for a stanza when that stanza exists in default/.
    Use the collection listing; reject entries that look like merged effective config.
    """
    collection = conf_collection_endpoint(conf_endpoint)
    default_names = list_conf_stanza_names(
        collection, auth, headers, params={"defaultcontext": "true"}
    )
    if stanza_name not in default_names:
        if debug:
            print(
                f"Debug: stanza '{stanza_name}' is not listed in app default/savedsearches.conf",
                file=sys.stderr,
            )
        return {}, False

    entry = find_conf_collection_entry(
        collection, stanza_name, auth, headers, params={"defaultcontext": "true"}
    )
    content = extract_conf_content(entry)
    if looks_like_merged_config(content, merged_content):
        if debug:
            print(
                f"Debug: ignoring app default/ listing for '{stanza_name}' "
                f"({len(content)} keys matches merged effective config)",
                file=sys.stderr,
            )
        return {}, False

    if debug:
        print(
            f"Debug: stanza '{stanza_name}' uses app default/ layer with {len(content)} keys",
            file=sys.stderr,
        )
    return content, True

def discover_local_keys_via_appcontext(
    conf_endpoint: str,
    merged_content: dict,
    auth,
    headers: dict,
    debug: bool = False,
) -> List[str]:
    """Discover local keys using appcontext when baseline diff is unavailable."""
    app_content = extract_conf_content(
        fetch_rest_entry(conf_endpoint, auth, headers, params={"appcontext": "true"}, optional=True)
    )
    if not app_content:
        return []

    app_keys = refine_appcontext_local_keys(app_content)
    if not app_keys:
        return []

    if len(app_keys) >= max(20, int(len(merged_content) * 0.15)):
        if debug:
            print(
                f"Debug: appcontext discovery rejected ({len(app_keys)} keys vs merged {len(merged_content)})",
                file=sys.stderr,
            )
        return []

    if debug:
        print(f"Debug: appcontext discovery accepted keys={app_keys}", file=sys.stderr)
    return app_keys

def build_inherited_savedsearch_baseline(
    conf_endpoint: str,
    stanza_name: str,
    merged_content: dict,
    auth,
    headers: dict,
    debug: bool = False,
) -> Tuple[dict, bool]:
    """Build lower-precedence savedsearches.conf layers for local diff."""
    inherited_baseline = fetch_global_default_layers(conf_endpoint, auth, headers, debug=debug)
    app_default_layer, has_app_default_stanza = fetch_app_default_stanza_layer(
        conf_endpoint, stanza_name, merged_content, auth, headers, debug=debug
    )

    baseline = dict(inherited_baseline)
    if has_app_default_stanza:
        baseline.update(app_default_layer)

    if debug:
        print(
            f"Debug baseline: inherited={len(inherited_baseline)} "
            f"app_default={'yes' if has_app_default_stanza else 'no'} "
            f"total={len(baseline)}",
            file=sys.stderr,
        )
        if not inherited_baseline:
            print(
                "Debug: inherited [default] baseline empty; will use appcontext discovery if needed.",
                file=sys.stderr,
            )

    return baseline, has_app_default_stanza

def discover_local_savedsearch_keys(
    conf_endpoint: str,
    auth,
    headers: dict,
    debug: bool = False,
) -> Tuple[Optional[List[str]], Optional[str]]:
    """
    Discover keys defined in local savedsearches.conf using REST only.

    Splunk omits unchanged inherited settings from local/. Compare the merged
    stanza against lower-precedence layers when available, otherwise use
    appcontext discovery (validated against btool local/ output).
    """
    merged_entry = fetch_rest_entry(conf_endpoint, auth, headers, optional=True)
    if not merged_entry:
        return None, None

    stanza_name = conf_stanza_name(conf_endpoint)
    merged_content = extract_conf_content(merged_entry)
    if not merged_content:
        return [], "REST (merged stanza minus inherited baseline)"

    baseline, has_app_default_stanza = build_inherited_savedsearch_baseline(
        conf_endpoint, stanza_name, merged_content, auth, headers, debug=debug
    )

    baseline_is_merged = looks_like_merged_config(baseline, merged_content)
    if baseline and not baseline_is_merged:
        local_keys = keys_defined_locally(merged_content, baseline)
        if has_app_default_stanza:
            source = "REST (merged stanza minus app default/ + inherited)"
        else:
            source = "REST (merged stanza minus inherited defaults)"
    else:
        local_keys = []
        if baseline_is_merged and debug:
            print(
                "Debug: baseline matches merged effective config; using appcontext discovery",
                file=sys.stderr,
            )
        source = "REST (appcontext app-local keys)"

    if not local_keys:
        local_keys = discover_local_keys_via_appcontext(
            conf_endpoint, merged_content, auth, headers, debug=debug
        )
        if local_keys:
            source = "REST (appcontext app-local keys)"

    if debug:
        print(
            f"Debug local discovery: merged={len(merged_content)} "
            f"baseline={len(baseline)} local={local_keys}",
            file=sys.stderr,
        )

    return local_keys, source

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

def fetch_target_entry(endpoint: str, auth, headers: dict) -> dict:
    entry = fetch_rest_entry(endpoint, auth, headers)
    if not entry:
        print("Error: No search entries found.", file=sys.stderr)
        sys.exit(1)
    return entry

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

def parse_requested_keys(keys_arg: Optional[str]) -> List[str]:
    if not keys_arg:
        return []
    return [k.strip() for k in keys_arg.split(",") if k.strip()]

def run_export(args, auth, headers) -> None:
    """Export an explicit comma-separated key list from any REST endpoint."""
    requested_keys = parse_requested_keys(args.keys)
    if not requested_keys:
        print("Error: --keys is required when using '--mode export'", file=sys.stderr)
        sys.exit(1)

    target_entry = fetch_target_entry(args.endpoint, auth, headers)
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

    write_json_output(out_p, args.output, "Successfully exported keys to '{}'")

def run_export_savedsearches(args, auth, headers) -> None:
    """Export locally-defined savedsearches.conf keys for one saved search."""
    endpoint_parts = parse_savedsearch_endpoint(args.endpoint)
    if not endpoint_parts:
        print(
            "Error: export-savedsearches requires a saved search endpoint "
            "(/servicesNS/{owner}/{app}/saved/searches/{name}).",
            file=sys.stderr,
        )
        sys.exit(1)

    _owner, app, stanza_name = endpoint_parts
    conf_endpoint = build_conf_savedsearch_endpoint(args.endpoint)
    if not conf_endpoint:
        print("Error: could not build configs/conf-savedsearches endpoint.", file=sys.stderr)
        sys.exit(1)

    local_keys, local_source = discover_local_savedsearch_keys(
        conf_endpoint, auth, headers, debug=args.debug_local_keys
    )

    if local_keys is None:
        print(
            "Error: REST local key discovery failed for "
            f"stanza '{stanza_name}' in app '{app}'.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not local_keys:
        print(
            f"Error: no locally-defined savedsearches.conf keys found for "
            f"stanza '{stanza_name}' in app '{app}'.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(
        f"Exported {len(local_keys)} local keys for '{stanza_name}' ({local_source}).",
        file=sys.stderr,
    )

    target_entry = fetch_target_entry(args.endpoint, auth, headers)
    out_p, missing_keys = export_requested_keys(target_entry, local_keys)

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

    write_json_output(out_p, args.output, "Successfully exported local saved search keys to '{}'")

def main():
    parser = argparse.ArgumentParser(
        description="Splunk Knowledge Object Manager — export, review, update, and post via REST.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--mode",
        required=True,
        choices=["export", "export-savedsearches", "endpointreview", "update", "post"],
    )
    parser.add_argument("--endpoint", required=True, help="The Splunk REST endpoint URL.")
    parser.add_argument("--credentials", required=True, nargs=2, metavar=('{user,token}', 'VALUE'))
    parser.add_argument(
        "--keys",
        help="Required for export mode. Comma-separated keys to fetch from the endpoint.",
    )
    parser.add_argument(
        "--debug-local-keys",
        action="store_true",
        help="Print REST local-key discovery details to stderr (export-savedsearches).",
    )
    # Segregated parameters for clean interface control
    parser.add_argument("--input", help="Required for update/post modes. Source payload file path.")
    parser.add_argument(
        "--output",
        help="Optional for export, export-savedsearches, and endpointreview. Destination file path (defaults to STDOUT).",
    )
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
        method = "GET" if args.mode in ("export", "export-savedsearches", "endpointreview") else "POST"
        print(f"\n--- DRY RUN: Equivalent Curl Command for {args.mode.upper()} ---")
        print(generate_curl_dry_run(method, args.endpoint, auth, headers, payload))
        if args.mode == "export":
            dest = args.output if args.output else "STDOUT"
            print(f"\nNOTE: Live run writes keys [{args.keys}] to: {dest}\n")
        elif args.mode == "export-savedsearches":
            dest = args.output if args.output else "STDOUT"
            print(
                "\nNOTE: Live run discovers local savedsearches.conf keys via REST "
                f"and writes JSON to: {dest}\n"
            )
        elif args.mode == "endpointreview":
            dest = args.output if args.output else "STDOUT"
            print(f"\nNOTE: Live run writes all non-null key/value pairs to: {dest}\n")
        return

    try:
        if args.mode == "export":
            run_export(args, auth, headers)

        elif args.mode == "export-savedsearches":
            run_export_savedsearches(args, auth, headers)

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

