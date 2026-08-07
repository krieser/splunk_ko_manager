#!/usr/bin/env python3
"""Splunk Knowledge Object Manager — REST CLI for Splunk conf/KO migration."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple
from urllib.parse import quote, unquote, urlparse, urlunparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__version__ = "1.5.0"
MIGRATION_ENVELOPE_VERSION = "1"

_DATA_UI_VIEWS_RE = re.compile(
    r"/servicesNS/([^/]+)/([^/]+)/data/ui/views/([^/?#]+)/?$"
)
_MISSING = object()
_DEFAULT_METADATA_PREFIXES = ("eai:",)
# Reject candidate local-key sets that look like merged effective config, not local/.
_LOCAL_KEY_MERGED_RATIO = 0.15
_LOCAL_KEY_MERGED_MIN = 20


@dataclass(frozen=True)
class ConfTypeSpec:
    """Registry entry describing one Splunk .conf migration type."""

    name: str
    conf_file: str
    conf_rest: str
    system_properties_name: str
    ko_collection: Optional[str] = None
    inherited_noise_keys: FrozenSet[str] = field(default_factory=frozenset)
    inherited_noise_defaults: Dict[str, FrozenSet[str]] = field(default_factory=dict)
    metadata_key_prefixes: Tuple[str, ...] = _DEFAULT_METADATA_PREFIXES

    def ko_endpoint_pattern(self) -> re.Pattern[str]:
        if not self.ko_collection:
            raise ValueError(f"conf type '{self.name}' has no KO collection path")
        return re.compile(
            rf"/servicesNS/([^/]+)/([^/]+)/{re.escape(self.ko_collection)}/([^/?#]+)/?$"
        )

    def conf_endpoint_pattern(self) -> re.Pattern[str]:
        return re.compile(
            rf"^(?P<prefix>https?://[^/]+/servicesNS/)"
            rf"(?P<owner>[^/]+)/(?P<app>[^/]+)/configs/{re.escape(self.conf_rest)}/"
        )


@dataclass
class LocalDiscoveryResult:
    """Outcome of REST local-key discovery for one conf stanza."""

    local_keys: List[str]
    source: str
    method: str
    merged_key_count: int
    baseline_key_count: int
    baseline_diff_keys: List[str]
    appcontext_keys: List[str]
    rejected_reason: Optional[str] = None


def _spec(
    name: str,
    conf_file: str,
    conf_rest: str,
    system_properties_name: str,
    *,
    ko_collection: Optional[str] = None,
    inherited_noise_keys: Optional[FrozenSet[str]] = None,
    inherited_noise_defaults: Optional[Dict[str, FrozenSet[str]]] = None,
) -> ConfTypeSpec:
    return ConfTypeSpec(
        name=name,
        conf_file=conf_file,
        conf_rest=conf_rest,
        system_properties_name=system_properties_name,
        ko_collection=ko_collection,
        inherited_noise_keys=inherited_noise_keys or frozenset(),
        inherited_noise_defaults=inherited_noise_defaults or {},
    )


CONF_TYPE_REGISTRY: Dict[str, ConfTypeSpec] = {
    "savedsearches": _spec(
        "savedsearches",
        "savedsearches.conf",
        "conf-savedsearches",
        "savedsearches",
        ko_collection="saved/searches",
        inherited_noise_keys=frozenset({"disabled", "enableSched", "counttype"}),
    ),
    "props": _spec(
        "props",
        "props.conf",
        "conf-props",
        "props",
        inherited_noise_keys=frozenset({"disabled"}),
    ),
    "transforms": _spec(
        "transforms",
        "transforms.conf",
        "conf-transforms",
        "transforms",
        inherited_noise_keys=frozenset({"disabled"}),
    ),
    "macros": _spec(
        "macros",
        "macros.conf",
        "conf-macros",
        "macros",
        ko_collection="saved/macros",
        inherited_noise_keys=frozenset({"disabled"}),
    ),
    "views": _spec(
        "views",
        "views.conf",
        "conf-views",
        "views",
        ko_collection="saved/views",
        inherited_noise_keys=frozenset({"disabled"}),
    ),
}

EXPORT_MODE_TO_CONF_TYPE: Dict[str, str] = {
    "export-savedsearches": "savedsearches",
    "export-props": "props",
    "export-transforms": "transforms",
    "export-macros": "macros",
    "export-views": "views",
}


def get_conf_type(name: str) -> ConfTypeSpec:
    spec = CONF_TYPE_REGISTRY.get(name)
    if not spec:
        known = ", ".join(sorted(CONF_TYPE_REGISTRY))
        raise ValueError(f"Unknown conf type '{name}'. Known types: {known}")
    return spec


def local_key_count_threshold(merged_key_count: int) -> int:
    """Max local keys before treating a candidate set as merged effective config."""
    return max(_LOCAL_KEY_MERGED_MIN, int(merged_key_count * _LOCAL_KEY_MERGED_RATIO))


def keys_look_like_merged_effective(local_key_count: int, merged_key_count: int) -> bool:
    if merged_key_count == 0:
        return local_key_count >= _LOCAL_KEY_MERGED_MIN
    return local_key_count >= local_key_count_threshold(merged_key_count)


def parse_requested_keys(keys_arg: Optional[str]) -> List[str]:
    if not keys_arg:
        return []
    return [k.strip() for k in keys_arg.split(",") if k.strip()]


def parse_data_ui_views_endpoint(endpoint: str) -> Optional[Tuple[str, str, str]]:
    """Parse owner, app, and view name from a data/ui/views REST endpoint."""
    match = _DATA_UI_VIEWS_RE.search(urlparse(endpoint).path)
    if not match:
        return None
    owner, app, view_name = match.groups()
    return unquote(owner), unquote(app), unquote(view_name)


def parse_ko_endpoint(endpoint: str, spec: ConfTypeSpec) -> Optional[Tuple[str, str, str]]:
    """Parse owner, app, and stanza name from a Splunk KO REST endpoint."""
    if not spec.ko_collection:
        return None
    match = spec.ko_endpoint_pattern().search(urlparse(endpoint).path)
    if not match:
        return None
    owner, app, stanza_name = match.groups()
    return unquote(owner), unquote(app), unquote(stanza_name)


def parse_conf_endpoint(endpoint: str, spec: ConfTypeSpec) -> Optional[Tuple[str, str, str]]:
    """Parse owner, app, and stanza from a configs/conf-* REST endpoint."""
    path = urlparse(endpoint).path
    match = spec.conf_endpoint_pattern().match(endpoint)
    if not match:
        return None
    owner = unquote(match.group("owner"))
    app = unquote(match.group("app"))
    stanza = unquote(path.rsplit("/", 1)[-1])
    return owner, app, stanza


def normalize_conf_owner(owner: str) -> str:
    """Map REST wildcard owner to app-shared namespace used by configs endpoints."""
    return "nobody" if owner in ("-", "nobody") else owner


def build_conf_stanza_url(
    origin: str,
    owner: str,
    app: str,
    spec: ConfTypeSpec,
    stanza_name: str,
) -> str:
    owner = normalize_conf_owner(owner)
    path = (
        f"/servicesNS/{quote(owner, safe='')}/{quote(app, safe='')}"
        f"/configs/{spec.conf_rest}/{quote(stanza_name, safe='')}"
    )
    parsed = urlparse(origin if "://" in origin else f"https://{origin}")
    if "://" in origin:
        return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))
    return path


def build_conf_endpoint_from_ko(
    endpoint: str,
    spec: ConfTypeSpec,
    owner: Optional[str] = None,
    app: Optional[str] = None,
    stanza_name: Optional[str] = None,
) -> Optional[str]:
    """Build configs/conf-* endpoint from a KO or data/ui/views URL."""
    parsed = urlparse(endpoint)
    if owner is None or app is None or stanza_name is None:
        parts = parse_ko_endpoint(endpoint, spec)
        if not parts and spec.name == "views":
            parts = parse_data_ui_views_endpoint(endpoint)
        if not parts:
            return None
        owner, app, stanza_name = parts
    return build_conf_stanza_url(
        f"{parsed.scheme}://{parsed.netloc}",
        owner,
        app,
        spec,
        stanza_name,
    )


def build_conf_stanza_endpoint(
    conf_endpoint: str,
    stanza_name: str,
    spec: ConfTypeSpec,
    owner: Optional[str] = None,
    app: Optional[str] = None,
) -> Optional[str]:
    """Build a configs/conf-* URL for another stanza and/or namespace."""
    match = spec.conf_endpoint_pattern().match(conf_endpoint)
    if not match:
        return None
    resolved_owner = owner if owner is not None else match.group("owner")
    resolved_app = app if app is not None else match.group("app")
    prefix = match.group("prefix")
    return (
        f"{prefix}{quote(resolved_owner, safe='')}/{quote(resolved_app, safe='')}"
        f"/configs/{spec.conf_rest}/{quote(stanza_name, safe='')}"
    )


def resolve_local_export_context(
    endpoint: str,
    spec: ConfTypeSpec,
) -> Optional[Tuple[str, str, str, str]]:
    """
    Resolve owner, app, stanza, and conf REST endpoint for local export.

    Accepts KO endpoints (saved/*), direct configs/conf-* URLs, or for views
    also data/ui/views/{name}.
    """
    conf_parts = parse_conf_endpoint(endpoint, spec)
    if conf_parts:
        owner, app, stanza_name = conf_parts
        return owner, app, stanza_name, endpoint

    if spec.ko_collection:
        parts = parse_ko_endpoint(endpoint, spec)
        if not parts and spec.name == "views":
            parts = parse_data_ui_views_endpoint(endpoint)
        if not parts:
            return None
        owner, app, stanza_name = parts
        conf_endpoint = build_conf_endpoint_from_ko(
            endpoint, spec, owner, app, stanza_name
        )
        if not conf_endpoint:
            return None
        return owner, app, stanza_name, conf_endpoint

    return None


def is_conf_metadata_key(key: str, spec: ConfTypeSpec) -> bool:
    return any(key.startswith(prefix) for prefix in spec.metadata_key_prefixes)


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


def keys_defined_locally(app_content: dict, baseline: dict, spec: ConfTypeSpec) -> List[str]:
    """
    Keys Splunk would write to local/ because they are absent from or differ
    from lower-precedence layers (system/app default), mirroring btool local/.
    """
    local_keys = []
    for key, value in app_content.items():
        if is_conf_metadata_key(key, spec):
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


def is_likely_inherited_default_key(key: str, value, spec: ConfTypeSpec) -> bool:
    """Drop inherited keys that appcontext surfaces at default values."""
    if key not in spec.inherited_noise_keys:
        return False
    normalized = normalize_conf_value(value)
    if key in spec.inherited_noise_defaults:
        return normalized in spec.inherited_noise_defaults[key]
    return normalized in ("", "0", "false")


def build_flat_local_export(content: dict, local_keys: List[str]) -> dict:
    """Build stdout/file JSON: only local keys that have values, in discovery order."""
    return {key: content[key] for key in local_keys if key in content}


def refine_appcontext_local_keys(app_content: dict, spec: ConfTypeSpec) -> List[str]:
    keys = []
    for key, value in app_content.items():
        if is_conf_metadata_key(key, spec) or is_empty_conf_value(value):
            continue
        if is_likely_inherited_default_key(key, value, spec):
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
    spec: ConfTypeSpec,
    auth,
    headers: dict,
    debug: bool = False,
) -> dict:
    """Collect system/app [default] stanza settings from several REST paths."""
    origin = conf_server_origin(conf_endpoint)
    layers = {}
    sources = []
    conf_collection = f"{origin}/servicesNS/nobody/system/configs/{spec.conf_rest}"

    candidates: List[Tuple[str, Optional[str], Optional[dict]]] = [
        ("system-ns-default", build_conf_stanza_endpoint(conf_endpoint, "default", spec, owner="nobody", app="system"), None),
        ("system-ns-bracket", build_conf_stanza_endpoint(conf_endpoint, "[default]", spec, owner="nobody", app="system"), None),
        ("system-ns-coll-default", conf_collection, None),
        ("system-ns-wildcard-default", f"{origin}/servicesNS/-/-/configs/{spec.conf_rest}/default", None),
        ("system-svc-default", f"{origin}/services/configs/{spec.conf_rest}/default", None),
        ("system-svc-bracket", f"{origin}/services/configs/{spec.conf_rest}/%5Bdefault%5D", None),
        ("app-default-ctx", build_conf_stanza_endpoint(conf_endpoint, "default", spec), {"defaultcontext": "true"}),
        ("app-bracket-ctx", build_conf_stanza_endpoint(conf_endpoint, "[default]", spec), {"defaultcontext": "true"}),
        (
            "system-props-default",
            f"{origin}/servicesNS/nobody/system/properties/{spec.system_properties_name}/default",
            None,
        ),
        (
            "system-props-bracket",
            f"{origin}/servicesNS/nobody/system/properties/{spec.system_properties_name}/%5Bdefault%5D",
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
    spec: ConfTypeSpec,
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
                f"Debug: stanza '{stanza_name}' is not listed in app default/{spec.conf_file}",
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


def build_inherited_conf_baseline(
    conf_endpoint: str,
    stanza_name: str,
    merged_content: dict,
    spec: ConfTypeSpec,
    auth,
    headers: dict,
    debug: bool = False,
) -> Tuple[dict, bool]:
    """Build lower-precedence conf layers for local diff."""
    inherited_baseline = fetch_global_default_layers(conf_endpoint, spec, auth, headers, debug=debug)
    app_default_layer, has_app_default_stanza = fetch_app_default_stanza_layer(
        conf_endpoint, stanza_name, merged_content, spec, auth, headers, debug=debug
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


def fetch_appcontext_content(
    conf_endpoint: str,
    auth,
    headers: dict,
) -> dict:
    """Return appcontext=true conf content for a stanza."""
    return extract_conf_content(
        fetch_rest_entry(conf_endpoint, auth, headers, params={"appcontext": "true"}, optional=True)
    )


def discover_local_conf_keys(
    conf_endpoint: str,
    spec: ConfTypeSpec,
    auth,
    headers: dict,
    debug: bool = False,
) -> Optional[LocalDiscoveryResult]:
    """
    Discover keys defined in local/{conf_file} using REST only.

    Never returns the full merged stanza key set. Uses baseline diff when
    trustworthy, always cross-checks appcontext when available, and rejects
    candidate sets that look like merged effective configuration.
    """
    merged_entry = fetch_rest_entry(conf_endpoint, auth, headers, optional=True)
    if not merged_entry:
        return None

    stanza_name = conf_stanza_name(conf_endpoint)
    merged_content = extract_conf_content(merged_entry)
    merged_key_count = len(merged_content)
    if not merged_content:
        return LocalDiscoveryResult(
            local_keys=[],
            source="REST (empty merged stanza)",
            method="none",
            merged_key_count=0,
            baseline_key_count=0,
            baseline_diff_keys=[],
            appcontext_keys=[],
            rejected_reason="merged stanza returned no content keys",
        )

    threshold = local_key_count_threshold(merged_key_count)

    appcontext_content = fetch_appcontext_content(conf_endpoint, auth, headers)
    appcontext_keys = refine_appcontext_local_keys(appcontext_content, spec)
    appcontext_rejected = None
    if keys_look_like_merged_effective(len(appcontext_keys), merged_key_count):
        appcontext_rejected = (
            f"appcontext returned {len(appcontext_keys)} keys "
            f"(>= local threshold {threshold} for merged {merged_key_count})"
        )
        if debug:
            print(f"Debug: {appcontext_rejected}", file=sys.stderr)
        appcontext_keys = []

    baseline, has_app_default_stanza = build_inherited_conf_baseline(
        conf_endpoint, stanza_name, merged_content, spec, auth, headers, debug=debug
    )
    baseline_key_count = len(baseline)
    baseline_is_merged = looks_like_merged_config(baseline, merged_content)

    baseline_diff_keys: List[str] = []
    if baseline and not baseline_is_merged:
        baseline_diff_keys = keys_defined_locally(merged_content, baseline, spec)

    baseline_suspicious = keys_look_like_merged_effective(len(baseline_diff_keys), merged_key_count)
    if baseline_suspicious and debug:
        print(
            f"Debug: baseline diff returned {len(baseline_diff_keys)} keys "
            f"(>= local threshold {threshold}); will not use alone",
            file=sys.stderr,
        )

    local_keys: List[str] = []
    method = "none"
    source = "REST (no local keys identified)"
    rejected_reason = appcontext_rejected

    if baseline_diff_keys and appcontext_keys:
        intersect = sorted(set(baseline_diff_keys) & set(appcontext_keys))
        if baseline_suspicious:
            local_keys = appcontext_keys
            method = "appcontext"
            source = "REST (appcontext; baseline diff rejected as too broad)"
        elif intersect:
            local_keys = intersect
            method = "baseline-intersect-appcontext"
            source = "REST (baseline diff ∩ appcontext)"
        else:
            # Small baseline diff with no appcontext overlap — prefer the smaller set.
            if len(appcontext_keys) <= len(baseline_diff_keys):
                local_keys = appcontext_keys
                method = "appcontext"
                source = "REST (appcontext; no baseline overlap)"
            else:
                local_keys = baseline_diff_keys
                method = "baseline-diff"
                source = (
                    "REST (merged stanza minus app default/ + inherited)"
                    if has_app_default_stanza
                    else "REST (merged stanza minus inherited defaults)"
                )
    elif baseline_diff_keys and not baseline_suspicious:
        local_keys = baseline_diff_keys
        method = "baseline-diff"
        source = (
            "REST (merged stanza minus app default/ + inherited)"
            if has_app_default_stanza
            else "REST (merged stanza minus inherited defaults)"
        )
    elif appcontext_keys:
        local_keys = appcontext_keys
        method = "appcontext"
        source = "REST (appcontext app-local keys)"
    elif baseline_suspicious:
        rejected_reason = (
            rejected_reason or
            f"baseline diff returned {len(baseline_diff_keys)} keys (>= local threshold {threshold})"
        )

    if keys_look_like_merged_effective(len(local_keys), merged_key_count):
        rejected_reason = (
            rejected_reason or
            f"final local key set still too large ({len(local_keys)} keys vs merged {merged_key_count})"
        )
        local_keys = []
        method = "rejected"
        source = "REST (rejected — looks like merged effective config, not local/)"

    if debug:
        print(
            f"Debug local discovery [{spec.name}/{stanza_name}]: "
            f"merged={merged_key_count} baseline={baseline_key_count} "
            f"baseline_diff={len(baseline_diff_keys)} appcontext={len(appcontext_keys)} "
            f"final={local_keys} method={method}",
            file=sys.stderr,
        )

    return LocalDiscoveryResult(
        local_keys=local_keys,
        source=source,
        method=method,
        merged_key_count=merged_key_count,
        baseline_key_count=baseline_key_count,
        baseline_diff_keys=baseline_diff_keys,
        appcontext_keys=appcontext_keys,
        rejected_reason=rejected_reason,
    )


def log_local_discovery_report(
    spec: ConfTypeSpec,
    *,
    app: str,
    stanza: str,
    discovery: LocalDiscoveryResult,
    verbose: bool = False,
) -> None:
    """Always print a concise stderr summary of local-key discovery."""
    print(
        f"Local export [{spec.conf_file}] app='{app}' stanza='{stanza}'",
        file=sys.stderr,
    )
    print(
        f"  merged_keys={discovery.merged_key_count} "
        f"baseline_keys={discovery.baseline_key_count} "
        f"baseline_diff={len(discovery.baseline_diff_keys)} "
        f"appcontext={len(discovery.appcontext_keys)}",
        file=sys.stderr,
    )
    print(
        f"  method={discovery.method} local_keys={len(discovery.local_keys)}",
        file=sys.stderr,
    )
    if discovery.local_keys:
        print(f"  keys={discovery.local_keys}", file=sys.stderr)
    if discovery.rejected_reason:
        print(f"  rejected={discovery.rejected_reason}", file=sys.stderr)
    print(f"  source={discovery.source}", file=sys.stderr)
    if verbose:
        if discovery.baseline_diff_keys:
            print(f"  baseline_diff_keys={discovery.baseline_diff_keys}", file=sys.stderr)
        if discovery.appcontext_keys:
            print(f"  appcontext_keys={discovery.appcontext_keys}", file=sys.stderr)
        print(
            f"  validate: splunk btool {spec.name} list --debug \"{stanza}\" "
            f"| grep \"etc/apps/{app}/local\" | grep -v \" = $\"",
            file=sys.stderr,
        )


def export_local_conf_values(
    conf_endpoint: str,
    local_keys: List[str],
    auth,
    headers: dict,
) -> Tuple[dict, List[str], dict]:
    """
    Export values for local keys from the conf stanza REST endpoint only.

    Output contains exactly the requested local keys that have non-null values.
    """
    entry = fetch_rest_entry(conf_endpoint, auth, headers)
    raw_content, _missing = export_requested_keys(entry, local_keys)
    content = {
        key: value
        for key, value in raw_content.items()
        if key in local_keys and value is not None
    }
    missing_keys = [key for key in local_keys if key not in content]
    return content, missing_keys, entry


def build_migration_envelope(
    spec: ConfTypeSpec,
    *,
    endpoint: str,
    owner: str,
    app: str,
    stanza: str,
    local_keys: List[str],
    content: dict,
    discovery_source: str,
    discovery_method: str = "",
) -> dict:
    parsed = urlparse(endpoint)
    return {
        "migration_version": MIGRATION_ENVELOPE_VERSION,
        "tool_version": __version__,
        "conf_type": spec.name,
        "conf_file": spec.conf_file,
        "source": {
            "host": parsed.netloc,
            "endpoint": endpoint,
            "owner": owner,
            "app": app,
        },
        "stanza": stanza,
        "local_keys": local_keys,
        "discovery_source": discovery_source,
        "discovery_method": discovery_method,
        "content": content,
    }


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
        print("Error: No REST entries found at endpoint.", file=sys.stderr)
        sys.exit(1)
    return entry


def write_json_output(
    data,
    output_path: Optional[str],
    success_message: str = None,
    *,
    stream=sys.stdout,
):
    json_kwargs = {"indent": 2, "ensure_ascii": False, "sort_keys": True}
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, **json_kwargs)
            f.write("\n")
        if success_message:
            print(success_message.format(output_path), file=sys.stderr)
    else:
        json.dump(data, stream, **json_kwargs)
        stream.write("\n")
        stream.flush()


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


def warn_missing_keys(target_entry: dict, missing_keys: list) -> None:
    if not missing_keys:
        return
    content = normalize_content(target_entry.get("content", {}))
    available_keys = sorted(set(content.keys()) | set(target_entry.keys()) - {"content"})
    suggestions = suggest_similar_keys(missing_keys, available_keys)
    print(
        f"Warning: The following keys were not found in the endpoint response: {missing_keys}",
        file=sys.stderr,
    )
    for missing, matches in suggestions.items():
        print(f"  Hint for '{missing}': did you mean one of {matches}?", file=sys.stderr)


def run_export(args, auth, headers) -> None:
    """Export an explicit comma-separated key list from any REST endpoint."""
    requested_keys = parse_requested_keys(args.keys)
    if not requested_keys:
        print("Error: --keys is required when using '--mode export'", file=sys.stderr)
        sys.exit(1)

    target_entry = fetch_target_entry(args.endpoint, auth, headers)
    out_p, missing_keys = export_requested_keys(target_entry, requested_keys)
    warn_missing_keys(target_entry, missing_keys)
    write_json_output(out_p, args.output, "Successfully exported keys to '{}'")


def endpoint_hint_for_mode(mode: str) -> str:
    """Return a one-line endpoint format hint for CLI errors."""
    conf_type_name = EXPORT_MODE_TO_CONF_TYPE.get(mode)
    if not conf_type_name:
        return "/servicesNS/{owner}/{app}/..."
    spec = CONF_TYPE_REGISTRY[conf_type_name]
    if spec.name == "views":
        return (
            f"/servicesNS/{{owner}}/{{app}}/{spec.ko_collection}/{{name}} or "
            f"/servicesNS/{{owner}}/{{app}}/data/ui/views/{{name}} or "
            f"/servicesNS/{{owner}}/{{app}}/configs/{spec.conf_rest}/{{stanza}}"
        )
    if spec.ko_collection:
        return (
            f"/servicesNS/{{owner}}/{{app}}/{spec.ko_collection}/{{name}} or "
            f"/servicesNS/{{owner}}/{{app}}/configs/{spec.conf_rest}/{{stanza}}"
        )
    return f"/servicesNS/{{owner}}/{{app}}/configs/{spec.conf_rest}/{{stanza}}"


def run_export_local(spec: ConfTypeSpec, args, auth, headers) -> None:
    """Export locally-defined conf keys for one stanza/KO (local/ layer only)."""
    ctx = resolve_local_export_context(args.endpoint, spec)
    if not ctx:
        if spec.ko_collection:
            print(
                f"Error: {args.mode} requires a {spec.ko_collection} endpoint "
                f"(/servicesNS/{{owner}}/{{app}}/{spec.ko_collection}/{{name}}).",
                file=sys.stderr,
            )
        else:
            print(
                f"Error: {args.mode} requires a configs/{spec.conf_rest}/{{stanza}} endpoint.",
                file=sys.stderr,
            )
        sys.exit(1)

    owner, app, stanza_name, conf_endpoint = ctx

    discovery = discover_local_conf_keys(
        conf_endpoint, spec, auth, headers, debug=args.debug_local_keys
    )

    if discovery is None:
        print(
            "Error: REST local key discovery failed for "
            f"stanza '{stanza_name}' in app '{app}'.",
            file=sys.stderr,
        )
        sys.exit(1)

    log_local_discovery_report(
        spec,
        app=app,
        stanza=stanza_name,
        discovery=discovery,
        verbose=args.debug_local_keys,
    )

    if not discovery.local_keys:
        if discovery.rejected_reason:
            print(
                f"Error: local key discovery rejected for stanza '{stanza_name}' "
                f"in app '{app}': {discovery.rejected_reason}",
                file=sys.stderr,
            )
        else:
            print(
                f"Error: no locally-defined {spec.conf_file} keys found for "
                f"stanza '{stanza_name}' in app '{app}'.",
                file=sys.stderr,
            )
        sys.exit(1)

    # Values always come from the conf stanza endpoint — never the full merged KO view.
    content, missing_keys, conf_entry = export_local_conf_values(
        conf_endpoint, discovery.local_keys, auth, headers
    )
    warn_missing_keys(conf_entry, missing_keys)

    flat_output = build_flat_local_export(content, discovery.local_keys)

    if args.migration_envelope:
        if not args.output:
            print(
                "Warning: --migration-envelope requires --output; "
                "writing flat local keys to stdout only.",
                file=sys.stderr,
            )
            write_json_output(flat_output, None)
        else:
            envelope = build_migration_envelope(
                spec,
                endpoint=args.endpoint,
                owner=owner,
                app=app,
                stanza=stanza_name,
                local_keys=discovery.local_keys,
                content=flat_output,
                discovery_source=discovery.source,
                discovery_method=discovery.method,
            )
            write_json_output(flat_output, None)
            write_json_output(
                envelope,
                args.output,
                f"Successfully wrote migration envelope to '{{}}'",
            )
    else:
        write_json_output(
            flat_output,
            args.output,
            f"Successfully exported {len(flat_output)} local {spec.conf_file} keys to '{{}}'",
        )


def main():
    parser = argparse.ArgumentParser(
        description="Splunk Knowledge Object Manager — export, review, update, and post via REST.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--mode",
        required=True,
        choices=["export", *EXPORT_MODE_TO_CONF_TYPE.keys(), "endpointreview", "update", "post"],
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
        help="Verbose stderr logging for local-key discovery (export-* local modes).",
    )
    parser.add_argument(
        "--migration-envelope",
        action="store_true",
        help=(
            "Also write migration metadata envelope to --output (export-* modes). "
            "Stdout always receives flat local key JSON only."
        ),
    )
    parser.add_argument("--input", help="Required for update/post modes. Source payload file path.")
    parser.add_argument(
        "--output",
        help="Optional for export modes and endpointreview. Destination file path (defaults to STDOUT).",
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

    local_export_modes = set(EXPORT_MODE_TO_CONF_TYPE.keys())
    if args.dry_run:
        method = "GET" if args.mode in ("export", *local_export_modes, "endpointreview") else "POST"
        print(f"\n--- DRY RUN: Equivalent Curl Command for {args.mode.upper()} ---")
        print(generate_curl_dry_run(method, args.endpoint, auth, headers, payload))
        if args.mode == "export":
            dest = args.output if args.output else "STDOUT"
            print(f"\nNOTE: Live run writes keys [{args.keys}] to: {dest}\n")
        elif args.mode in local_export_modes:
            dest = args.output if args.output else "STDOUT"
            conf_type = EXPORT_MODE_TO_CONF_TYPE[args.mode]
            print(
                f"\nNOTE: Live run discovers local {CONF_TYPE_REGISTRY[conf_type].conf_file} keys via REST "
                f"and writes JSON to: {dest}\n"
            )
        elif args.mode == "endpointreview":
            dest = args.output if args.output else "STDOUT"
            print(f"\nNOTE: Live run writes all non-null key/value pairs to: {dest}\n")
        return

    try:
        if args.mode == "export":
            run_export(args, auth, headers)

        elif args.mode in local_export_modes:
            conf_type_name = EXPORT_MODE_TO_CONF_TYPE[args.mode]
            run_export_local(get_conf_type(conf_type_name), args, auth, headers)

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
            print("Operation failed: resource not found at this endpoint (404).", file=sys.stderr)
            print("Check owner/app/stanza name. Expected URL format:", file=sys.stderr)
            print(f"  {endpoint_hint_for_mode(args.mode)}", file=sys.stderr)
        print(f"Operation failed: {e}")


if __name__ == "__main__":
    main()
