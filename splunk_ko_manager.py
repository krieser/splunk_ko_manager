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

__version__ = "1.7.0"
MIGRATION_ENVELOPE_VERSION = "1"

_DATA_UI_VIEWS_RE = re.compile(
    r"/servicesNS/([^/]+)/([^/]+)/data/ui/views/([^/?#]+)/?$"
)
_SAVED_VIEWS_RE = re.compile(
    r"/servicesNS/([^/]+)/([^/]+)/saved/views/([^/?#]+)/?$"
)
_CONF_VIEWS_RE = re.compile(
    r"/servicesNS/([^/]+)/([^/]+)/configs/conf-views/([^/?#]+)/?$"
)
VIEW_EXPORT_MODE = "export-views"
VIEW_MIGRATION_FIELDS = ("name", "eai:data")
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


@dataclass
class DefaultDiscoveryResult:
    """Outcome of REST default-layer discovery for one conf stanza."""

    default_keys: List[str]
    source: str
    method: str
    merged_key_count: int
    default_key_count: int
    appcontext_keys: List[str]
    local_only_keys: List[str]
    default_collection_stanzas: List[str]
    rejected_reason: Optional[str] = None
    default_layer_entry: Optional[dict] = None


@dataclass
class DefaultViewDiscoveryResult:
    """Outcome of REST default-layer discovery for one dashboard view."""

    is_default: bool
    source: str
    method: str
    entry: Optional[dict]
    rejected_reason: Optional[str] = None
    defaultcontext_present: bool = False
    appcontext_present: bool = False
    effective_present: bool = False
    local_override: bool = False


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
}

EXPORT_MODE_TO_CONF_TYPE: Dict[str, str] = {
    "export-savedsearches": "savedsearches",
    "export-props": "props",
    "export-transforms": "transforms",
    "export-macros": "macros",
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


def build_data_ui_views_url(
    origin: str,
    owner: str,
    app: str,
    view_name: str,
) -> str:
    owner = normalize_conf_owner(owner)
    path = (
        f"/servicesNS/{quote(owner, safe='')}/{quote(app, safe='')}"
        f"/data/ui/views/{quote(view_name, safe='')}"
    )
    parsed = urlparse(origin if "://" in origin else f"https://{origin}")
    if "://" in origin:
        return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))
    return path


def resolve_view_export_context(
    endpoint: str,
) -> Optional[Tuple[str, str, str, str]]:
    """
    Resolve owner, app, view name, and data/ui/views REST URL for view export.

    Accepts saved/views, data/ui/views, or configs/conf-views URLs from SPL inventory.
    """
    parsed = urlparse(endpoint)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path

    for pattern in (_DATA_UI_VIEWS_RE, _SAVED_VIEWS_RE, _CONF_VIEWS_RE):
        match = pattern.search(path)
        if match:
            owner, app, view_name = match.groups()
            owner, app, view_name = unquote(owner), unquote(app), unquote(view_name)
            return (
                owner,
                app,
                view_name,
                build_data_ui_views_url(origin, owner, app, view_name),
            )
    return None


@dataclass
class ViewDiscoveryResult:
    """Outcome of REST local-view discovery for one dashboard."""

    is_local: bool
    source: str
    method: str
    entry: Optional[dict]
    rejected_reason: Optional[str] = None
    appcontext_present: bool = False
    defaultcontext_present: bool = False
    effective_present: bool = False


def is_user_namespace_owner(owner: str) -> bool:
    return owner not in ("-", "nobody")


def normalize_view_xml(value: str) -> str:
    return str(value).replace("\r\n", "\n").strip()


def view_meta_stanza_candidates(view_name: str) -> List[str]:
    return [
        f"views/{view_name}",
        f"[views/{view_name}]",
    ]


def entry_indicates_local_view_path(entry: Optional[dict]) -> bool:
    if not entry:
        return False
    blob = json.dumps(entry, default=str).lower()
    return "local/data/ui/views/" in blob or "local\\data\\ui\\views\\" in blob


def probe_local_meta_view_stanza(
    origin: str,
    app: str,
    view_name: str,
    auth,
    headers: dict,
    debug: bool = False,
) -> bool:
    """Return True when local.meta appears to define this view stanza."""
    for stanza in view_meta_stanza_candidates(view_name):
        bracket_stanza = stanza
        if not (stanza.startswith("[") and stanza.endswith("]")):
            bracket_stanza = f"[{stanza}]"
        for encoded_stanza in {stanza, bracket_stanza}:
            url = (
                f"{origin}/servicesNS/nobody/{quote(app, safe='')}"
                f"/configs/conf-local.meta/{quote(encoded_stanza, safe='')}"
            )
            entry = fetch_rest_entry(url, auth, headers, optional=True)
            if entry:
                if debug:
                    print(f"Debug: local.meta stanza found at {url}", file=sys.stderr)
                return True
    return False


def fetch_view_layer_entry(
    data_ui_views_url: str,
    auth,
    headers: dict,
    layer_param: Optional[str],
    debug: bool = False,
) -> Tuple[Optional[dict], Optional[str]]:
    """
    Try appcontext/defaultcontext layer probes on data/ui/views.

    Splunk often returns 400 for these params on view endpoints (conf-only feature).
    """
    if not layer_param:
        return fetch_rest_entry(data_ui_views_url, auth, headers, optional=True), None

    params = {layer_param: "true"}
    entry = fetch_rest_entry(
        data_ui_views_url,
        auth,
        headers,
        params=params,
        optional=True,
    )
    if entry:
        return entry, layer_param

    if debug:
        print(
            f"Debug: {layer_param}=true unsupported or empty for {data_ui_views_url}",
            file=sys.stderr,
        )
    return None, f"{layer_param}_unsupported"


def extract_view_eai_data(entry: Optional[dict]) -> Optional[str]:
    if not entry:
        return None
    content = normalize_content(entry.get("content", {}))
    data = content.get("eai:data")
    if data is None:
        candidate = get_field_value(entry, "eai:data")
        if candidate is not _MISSING:
            data = candidate
    if data is None:
        return None
    return str(data)


def discover_local_view(
    data_ui_views_url: str,
    owner: str,
    app: str,
    view_name: str,
    origin: str,
    auth,
    headers: dict,
    debug: bool = False,
) -> Optional[ViewDiscoveryResult]:
    """
    Determine whether a dashboard exists in a local/data/ui/views layer.

    data/ui/views does not support configs-style appcontext/defaultcontext on all
    Splunk versions (often HTTP 400). When those probes are unavailable, fall back
    to local.meta stanza detection and REST entry path hints.
    """
    effective_entry, _ = fetch_view_layer_entry(
        data_ui_views_url, auth, headers, None, debug=debug
    )
    effective_data = extract_view_eai_data(effective_entry)

    appcontext_entry, appcontext_status = fetch_view_layer_entry(
        data_ui_views_url, auth, headers, "appcontext", debug=debug
    )
    appcontext_data = extract_view_eai_data(appcontext_entry)

    defaultcontext_entry, defaultcontext_status = fetch_view_layer_entry(
        data_ui_views_url, auth, headers, "defaultcontext", debug=debug
    )
    defaultcontext_data = extract_view_eai_data(defaultcontext_entry)

    appcontext_present = bool(appcontext_data)
    defaultcontext_present = bool(defaultcontext_data)
    effective_present = bool(effective_data)
    local_meta_present = probe_local_meta_view_stanza(
        origin, app, view_name, auth, headers, debug=debug
    )
    entry_local_hint = entry_indicates_local_view_path(effective_entry)

    if debug:
        print(
            f"Debug view discovery [{view_name}]: effective={effective_present} "
            f"appcontext={appcontext_present} defaultcontext={defaultcontext_present} "
            f"local_meta={local_meta_present} entry_local_hint={entry_local_hint}",
            file=sys.stderr,
        )

    if not effective_present and not appcontext_present:
        return None

    if appcontext_present:
        return ViewDiscoveryResult(
            is_local=True,
            source="REST (appcontext local/data/ui/views)",
            method="appcontext",
            entry=appcontext_entry or effective_entry,
            appcontext_present=True,
            defaultcontext_present=defaultcontext_present,
            effective_present=effective_present,
        )

    if not effective_present:
        return None

    if defaultcontext_present:
        if normalize_view_xml(effective_data) == normalize_view_xml(defaultcontext_data):
            return ViewDiscoveryResult(
                is_local=False,
                source="REST (default/ only — matches defaultcontext)",
                method="default_only",
                entry=effective_entry,
                rejected_reason=(
                    f"view '{view_name}' exists only in default/data/ui/views/, not local/"
                ),
                appcontext_present=False,
                defaultcontext_present=True,
                effective_present=True,
            )
        return ViewDiscoveryResult(
            is_local=True,
            source="REST (local override — effective differs from defaultcontext)",
            method="baseline_diff",
            entry=effective_entry,
            appcontext_present=False,
            defaultcontext_present=True,
            effective_present=True,
        )

    if local_meta_present or entry_local_hint:
        return ViewDiscoveryResult(
            is_local=True,
            source="REST (local.meta or entry path indicates local/data/ui/views)",
            method="local_meta" if local_meta_present else "entry_path",
            entry=effective_entry,
            effective_present=True,
        )

    if is_user_namespace_owner(owner):
        nobody_url = build_data_ui_views_url(origin, "nobody", app, view_name)
        nobody_data = extract_view_eai_data(
            fetch_rest_entry(nobody_url, auth, headers, optional=True)
        )
        if nobody_data and normalize_view_xml(effective_data) == normalize_view_xml(nobody_data):
            return ViewDiscoveryResult(
                is_local=False,
                source="REST (user namespace inherits app view — no local layer)",
                method="rejected",
                entry=effective_entry,
                rejected_reason=(
                    f"view '{view_name}' for user '{owner}' has no local/data/ui/views/ file "
                    "(matches app-level effective view)"
                ),
                effective_present=True,
            )

    layer_note = ", ".join(
        status
        for status in (appcontext_status, defaultcontext_status)
        if status and status.endswith("_unsupported")
    )
    suffix = f" ({layer_note})" if layer_note else ""
    return ViewDiscoveryResult(
        is_local=False,
        source="REST (cannot confirm local/data/ui/views layer)",
        method="rejected",
        entry=effective_entry,
        rejected_reason=(
            f"view '{view_name}' in app '{app}' has no confirmed local/data/ui/views/ layer{suffix}; "
            "likely default/ only. Verify with: "
            f"ls $SPLUNK_HOME/etc/apps/{app}/local/data/ui/views/{view_name}.xml"
        ),
        effective_present=True,
    )


def discover_default_view(
    data_ui_views_url: str,
    owner: str,
    app: str,
    view_name: str,
    auth,
    headers: dict,
    debug: bool = False,
) -> Optional[DefaultViewDiscoveryResult]:
    """
    Determine whether a dashboard exists in default/data/ui/views and export that layer.

    Minimizes REST calls: probes defaultcontext first, then appcontext, then effective.
    """
    defaultcontext_entry, defaultcontext_status = fetch_view_layer_entry(
        data_ui_views_url, auth, headers, "defaultcontext", debug=debug
    )
    defaultcontext_data = extract_view_eai_data(defaultcontext_entry)
    defaultcontext_present = bool(defaultcontext_data)

    if defaultcontext_present:
        appcontext_entry, _ = fetch_view_layer_entry(
            data_ui_views_url, auth, headers, "appcontext", debug=debug
        )
        appcontext_data = extract_view_eai_data(appcontext_entry)
        appcontext_present = bool(appcontext_data)
        local_override = bool(
            appcontext_present
            and normalize_view_xml(appcontext_data) != normalize_view_xml(defaultcontext_data)
        )
        if debug:
            print(
                f"Debug default view discovery [{view_name}]: defaultcontext=true "
                f"appcontext={appcontext_present} local_override={local_override}",
                file=sys.stderr,
            )
        return DefaultViewDiscoveryResult(
            is_default=True,
            source="REST (defaultcontext default/data/ui/views)",
            method="defaultcontext",
            entry=defaultcontext_entry,
            defaultcontext_present=True,
            appcontext_present=appcontext_present,
            effective_present=False,
            local_override=local_override,
        )

    appcontext_entry, _ = fetch_view_layer_entry(
        data_ui_views_url, auth, headers, "appcontext", debug=debug
    )
    appcontext_data = extract_view_eai_data(appcontext_entry)
    appcontext_present = bool(appcontext_data)

    if appcontext_present:
        if debug:
            print(
                f"Debug default view discovery [{view_name}]: defaultcontext=false "
                f"appcontext=true (local-only)",
                file=sys.stderr,
            )
        return DefaultViewDiscoveryResult(
            is_default=False,
            source="REST (local-only view — no default/ layer)",
            method="rejected",
            entry=appcontext_entry,
            rejected_reason=(
                f"view '{view_name}' in app '{app}' has local/data/ui/views/ content "
                "but no default/ layer via REST"
            ),
            appcontext_present=True,
            effective_present=False,
        )

    effective_entry, _ = fetch_view_layer_entry(
        data_ui_views_url, auth, headers, None, debug=debug
    )
    effective_data = extract_view_eai_data(effective_entry)
    effective_present = bool(effective_data)

    if debug:
        print(
            f"Debug default view discovery [{view_name}]: defaultcontext=false "
            f"appcontext=false effective={effective_present}",
            file=sys.stderr,
        )

    if effective_present:
        return DefaultViewDiscoveryResult(
            is_default=True,
            source="REST (effective view; no local override detected)",
            method="effective_as_default",
            entry=effective_entry,
            defaultcontext_present=False,
            appcontext_present=False,
            effective_present=True,
        )

    layer_note = (
        f" ({defaultcontext_status})"
        if defaultcontext_status and defaultcontext_status.endswith("_unsupported")
        else ""
    )
    return DefaultViewDiscoveryResult(
        is_default=False,
        source="REST (cannot confirm default/data/ui/views layer)",
        method="rejected",
        entry=effective_entry,
        rejected_reason=(
            f"view '{view_name}' in app '{app}' has no confirmed default/data/ui/views/ layer"
            f"{layer_note}"
        ),
        effective_present=effective_present,
    )


def log_view_discovery_report(
    *,
    app: str,
    view_name: str,
    owner: str,
    discovery: ViewDiscoveryResult,
    verbose: bool = False,
) -> None:
    print(
        f"View export [local/data/ui/views] app='{app}' owner='{owner}' view='{view_name}'",
        file=sys.stderr,
    )
    print(
        f"  effective={discovery.effective_present} "
        f"appcontext={discovery.appcontext_present} "
        f"defaultcontext={discovery.defaultcontext_present}",
        file=sys.stderr,
    )
    print(f"  method={discovery.method} source={discovery.source}", file=sys.stderr)
    if verbose:
        print(
            f"  Validate: ls $SPLUNK_HOME/etc/apps/{app}/local/data/ui/views/{view_name}.xml "
            f"(app-local) or etc/users/{owner}/{app}/local/data/ui/views/ (user-local)",
            file=sys.stderr,
        )


def log_default_view_discovery_report(
    *,
    app: str,
    view_name: str,
    owner: str,
    discovery: DefaultViewDiscoveryResult,
    verbose: bool = False,
) -> None:
    print(
        f"Default view export [default/data/ui/views] app='{app}' "
        f"owner='{owner}' view='{view_name}'",
        file=sys.stderr,
    )
    print(
        f"  effective={discovery.effective_present} "
        f"defaultcontext={discovery.defaultcontext_present} "
        f"appcontext_suppressed={discovery.appcontext_present} "
        f"local_override={discovery.local_override}",
        file=sys.stderr,
    )
    print(f"  method={discovery.method} source={discovery.source}", file=sys.stderr)
    if discovery.rejected_reason:
        print(f"  rejected={discovery.rejected_reason}", file=sys.stderr)
    if verbose:
        print(
            f"  Validate: ls $SPLUNK_HOME/etc/apps/{app}/default/data/ui/views/{view_name}.xml",
            file=sys.stderr,
        )


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
    """Build configs/conf-* endpoint from a KO URL."""
    parsed = urlparse(endpoint)
    if owner is None or app is None or stanza_name is None:
        parts = parse_ko_endpoint(endpoint, spec)
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

    Accepts KO endpoints (saved/*) or direct configs/conf-* URLs.
    """
    conf_parts = parse_conf_endpoint(endpoint, spec)
    if conf_parts:
        owner, app, stanza_name = conf_parts
        return owner, app, stanza_name, endpoint

    if spec.ko_collection:
        parts = parse_ko_endpoint(endpoint, spec)
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
    optional_statuses: Tuple[int, ...] = (404, 400),
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
    if optional and response.status_code in optional_statuses:
        return None
    response.raise_for_status()
    return response.json()


def splunk_delete_json(
    endpoint: str,
    auth,
    headers: dict,
) -> Tuple[int, Optional[dict]]:
    """DELETE a Splunk REST entity and return (status_code, parsed JSON if any)."""
    response = requests.delete(
        endpoint,
        auth=auth,
        headers=headers,
        params={"output_mode": "json"},
        verify=False,
    )
    payload: Optional[dict] = None
    if response.text:
        try:
            payload = response.json()
        except json.JSONDecodeError:
            payload = {"raw": response.text}
    return response.status_code, payload


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
    """Detect when a layer response is actually merged effective config."""
    if not candidate or not merged_content:
        return False
    if len(candidate) <= 15:
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


def build_flat_key_export(content: dict, keys: List[str]) -> dict:
    """Build stdout/file JSON: only listed keys that have values, in discovery order."""
    return {key: content[key] for key in keys if key in content}


def build_flat_local_export(content: dict, local_keys: List[str]) -> dict:
    """Build stdout/file JSON: only local keys that have values, in discovery order."""
    return build_flat_key_export(content, local_keys)


def refine_layer_conf_keys(app_content: dict, spec: ConfTypeSpec) -> List[str]:
    """Extract meaningful conf keys from a single layer (local or default) response."""
    keys = []
    for key, value in app_content.items():
        if is_conf_metadata_key(key, spec) or is_empty_conf_value(value):
            continue
        if is_likely_inherited_default_key(key, value, spec):
            continue
        keys.append(key)
    return sorted(keys)


def refine_appcontext_local_keys(app_content: dict, spec: ConfTypeSpec) -> List[str]:
    return refine_layer_conf_keys(app_content, spec)


def refine_defaultcontext_keys(default_content: dict, spec: ConfTypeSpec) -> List[str]:
    return refine_layer_conf_keys(default_content, spec)


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
) -> Tuple[dict, bool, str]:
    """
    Return app default/ settings for a stanza when that stanza exists in default/.

    Prefer defaultonly=true (physical default/ layer). Fall back to defaultcontext
    collection entries on older Splunk builds that omit defaultonly support.
    """
    collection = conf_collection_endpoint(conf_endpoint)
    defaultonly_names = list_conf_stanza_names(
        collection, auth, headers, params={"defaultonly": "true"}
    )
    if stanza_name in defaultonly_names:
        entry = fetch_rest_entry(
            conf_endpoint,
            auth,
            headers,
            params={"defaultonly": "true"},
            optional=True,
        )
        content = extract_conf_content(entry)
        if content and not looks_like_merged_config(content, merged_content):
            if debug:
                print(
                    f"Debug: stanza '{stanza_name}' uses app default/ layer via "
                    f"defaultonly ({len(content)} keys)",
                    file=sys.stderr,
                )
            return content, True, "defaultonly"

    default_names = list_conf_stanza_names(
        collection, auth, headers, params={"defaultcontext": "true"}
    )
    if stanza_name not in default_names:
        if debug:
            print(
                f"Debug: stanza '{stanza_name}' is not listed in app default/{spec.conf_file}",
                file=sys.stderr,
            )
        return {}, False, "none"

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
        return {}, False, "none"

    if debug:
        print(
            f"Debug: stanza '{stanza_name}' uses app default/ layer with {len(content)} keys",
            file=sys.stderr,
        )
    return content, True, "defaultcontext"


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
    app_default_layer, has_app_default_stanza, _default_method = fetch_app_default_stanza_layer(
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


def fetch_defaultonly_content(
    conf_endpoint: str,
    auth,
    headers: dict,
) -> dict:
    """Return defaultonly=true conf content for a stanza (physical app default/ layer)."""
    return extract_conf_content(
        fetch_rest_entry(
            conf_endpoint,
            auth,
            headers,
            params={"defaultonly": "true"},
            optional=True,
        )
    )


def fetch_defaultcontext_content(
    conf_endpoint: str,
    auth,
    headers: dict,
) -> dict:
    """Return defaultcontext=true conf content for a stanza."""
    return extract_conf_content(
        fetch_rest_entry(
            conf_endpoint,
            auth,
            headers,
            params={"defaultcontext": "true"},
            optional=True,
        )
    )


def list_default_conf_stanza_names(
    conf_endpoint: str,
    auth,
    headers: dict,
) -> List[str]:
    """List stanza names present in the app's default/ layer for this conf collection."""
    collection = conf_collection_endpoint(conf_endpoint)
    names = list_conf_stanza_names(
        collection, auth, headers, params={"defaultonly": "true"}
    )
    if not names:
        names = list_conf_stanza_names(
            collection, auth, headers, params={"defaultcontext": "true"}
        )
    return sorted(name for name in names if name)


def _discover_default_conf_keys_defaultcontext_fallback(
    conf_endpoint: str,
    stanza_name: str,
    spec: ConfTypeSpec,
    auth,
    headers: dict,
    default_collection_stanzas: List[str],
    debug: bool = False,
) -> Optional[DefaultDiscoveryResult]:
    """Fallback when stanza is listed in default/ but defaultonly stanza GET is empty."""
    collection = conf_collection_endpoint(conf_endpoint)
    entry = find_conf_collection_entry(
        collection, stanza_name, auth, headers, params={"defaultcontext": "true"}
    )
    if not entry:
        entry = fetch_rest_entry(
            conf_endpoint,
            auth,
            headers,
            params={"defaultcontext": "true"},
            optional=True,
        )
    content = extract_conf_content(entry)
    merged_key_count = 0
    if content and len(content) > 15:
        merged_entry = fetch_rest_entry(conf_endpoint, auth, headers, optional=True)
        merged_content = extract_conf_content(merged_entry) if merged_entry else {}
        merged_key_count = len(merged_content)
        if looks_like_merged_config(content, merged_content):
            content = {}
            entry = None

    default_keys = refine_defaultcontext_keys(content, spec)
    appcontext_keys = refine_appcontext_local_keys(
        fetch_appcontext_content(conf_endpoint, auth, headers), spec
    )
    local_only_keys = sorted(set(appcontext_keys) - set(default_keys))

    if not default_keys:
        rejected_reason = (
            f"stanza '{stanza_name}' listed in app default/{spec.conf_file} collection "
            "but no exportable default/ keys via REST"
        )
        if debug:
            print(
                f"Debug default discovery [{spec.name}/{stanza_name}]: "
                f"defaultcontext fallback empty; rejected",
                file=sys.stderr,
            )
        return DefaultDiscoveryResult(
            default_keys=[],
            source="REST (rejected — no exportable default/ keys)",
            method="rejected",
            merged_key_count=merged_key_count,
            default_key_count=0,
            appcontext_keys=appcontext_keys,
            local_only_keys=local_only_keys,
            default_collection_stanzas=default_collection_stanzas,
            rejected_reason=rejected_reason,
        )

    if debug:
        print(
            f"Debug default discovery [{spec.name}/{stanza_name}]: "
            f"defaultcontext fallback default={len(default_keys)} "
            f"appcontext={len(appcontext_keys)}",
            file=sys.stderr,
        )
    return DefaultDiscoveryResult(
        default_keys=default_keys,
        source="REST (defaultcontext app default/ keys)",
        method="defaultcontext",
        merged_key_count=merged_key_count,
        default_key_count=len(default_keys),
        appcontext_keys=appcontext_keys,
        local_only_keys=local_only_keys,
        default_collection_stanzas=default_collection_stanzas,
        default_layer_entry=entry,
    )


def discover_default_conf_keys(
    conf_endpoint: str,
    spec: ConfTypeSpec,
    auth,
    headers: dict,
    debug: bool = False,
) -> Optional[DefaultDiscoveryResult]:
    """
    Discover keys defined in default/{conf_file} using REST only.

    Minimizes REST calls:
    1. List default/ stanzas (collection defaultonly=true, one GET)
    2. defaultonly=true per stanza when listed (one GET)
    3. appcontext=true only for local-only audit keys (optional third GET)

    Merged effective config is not fetched on the defaultonly happy path.
    """
    stanza_name = conf_stanza_name(conf_endpoint)
    default_collection_stanzas = list_default_conf_stanza_names(conf_endpoint, auth, headers)
    stanza_in_default = stanza_name in set(default_collection_stanzas)

    if not stanza_in_default:
        appcontext_keys = refine_appcontext_local_keys(
            fetch_appcontext_content(conf_endpoint, auth, headers), spec
        )
        if not appcontext_keys:
            merged_entry = fetch_rest_entry(conf_endpoint, auth, headers, optional=True)
            if not merged_entry:
                return None
            if not extract_conf_content(merged_entry):
                return None
        rejected_reason = (
            f"stanza '{stanza_name}' appears local-only "
            f"(appcontext keys present, no app default/{spec.conf_file} layer via REST)"
            if appcontext_keys
            else f"stanza '{stanza_name}' not found in app default/{spec.conf_file}"
        )
        if debug:
            print(
                f"Debug default discovery [{spec.name}/{stanza_name}]: "
                f"not in default/ collection; appcontext={len(appcontext_keys)}",
                file=sys.stderr,
            )
        return DefaultDiscoveryResult(
            default_keys=[],
            source="REST (rejected — no exportable default/ keys)",
            method="rejected",
            merged_key_count=0,
            default_key_count=0,
            appcontext_keys=appcontext_keys,
            local_only_keys=appcontext_keys,
            default_collection_stanzas=default_collection_stanzas,
            rejected_reason=rejected_reason,
        )

    default_layer_entry = fetch_rest_entry(
        conf_endpoint,
        auth,
        headers,
        params={"defaultonly": "true"},
        optional=True,
    )
    defaultonly_content = extract_conf_content(default_layer_entry)
    default_keys = refine_defaultcontext_keys(defaultonly_content, spec)

    if not default_keys:
        return _discover_default_conf_keys_defaultcontext_fallback(
            conf_endpoint,
            stanza_name,
            spec,
            auth,
            headers,
            default_collection_stanzas,
            debug=debug,
        )

    appcontext_keys = refine_appcontext_local_keys(
        fetch_appcontext_content(conf_endpoint, auth, headers), spec
    )
    local_only_keys = sorted(set(appcontext_keys) - set(default_keys))

    if debug:
        print(
            f"Debug default discovery [{spec.name}/{stanza_name}]: "
            f"defaultonly={len(default_keys)} appcontext={len(appcontext_keys)} "
            f"local_only={len(local_only_keys)} (skipped merged fetch)",
            file=sys.stderr,
        )

    return DefaultDiscoveryResult(
        default_keys=default_keys,
        source="REST (defaultonly app default/ keys)",
        method="defaultonly",
        merged_key_count=0,
        default_key_count=len(default_keys),
        appcontext_keys=appcontext_keys,
        local_only_keys=local_only_keys,
        default_collection_stanzas=default_collection_stanzas,
        default_layer_entry=default_layer_entry,
    )


def keys_defined_in_local_layer(
    appcontext_content: dict,
    defaultonly_content: dict,
    spec: ConfTypeSpec,
) -> List[str]:
    """
    Keys Splunk would write to local/: absent from or differing from app default/.

    When the stanza has no app default/ layer, all app-layer keys are treated as local.
    """
    app_keys = refine_appcontext_local_keys(appcontext_content, spec)
    default_keys = refine_defaultcontext_keys(defaultonly_content, spec)
    if not default_keys:
        return app_keys
    return keys_defined_locally(appcontext_content, defaultonly_content, spec)


def stanza_in_app_default_layer(
    conf_endpoint: str,
    stanza_name: str,
    auth,
    headers: dict,
) -> bool:
    """True when stanza_name is listed in the app's default/ conf layer via REST."""
    return stanza_name in set(list_default_conf_stanza_names(conf_endpoint, auth, headers))


def _discover_local_from_default_layer(
    conf_endpoint: str,
    stanza_name: str,
    spec: ConfTypeSpec,
    auth,
    headers: dict,
    appcontext_content: dict,
    appcontext_keys: List[str],
    debug: bool = False,
) -> Optional[LocalDiscoveryResult]:
    """
    Stanza exists in app default/: diff appcontext vs defaultonly (2 layer GETs
    after collection probe — no merged fetch).

    Returns None when the stanza is listed in default/ but the stanza-level
    defaultonly fetch is empty (caller should fall back to baseline discovery).
    """
    defaultonly_content = fetch_defaultonly_content(conf_endpoint, auth, headers)
    defaultonly_keys = refine_defaultcontext_keys(defaultonly_content, spec)
    if not defaultonly_keys:
        if debug:
            print(
                f"Debug local discovery [{spec.name}/{stanza_name}]: "
                f"listed in default/ collection but defaultonly stanza fetch empty; "
                f"falling back",
                file=sys.stderr,
            )
        return None

    local_keys = keys_defined_in_local_layer(appcontext_content, defaultonly_content, spec)
    rejected_reason: Optional[str] = None
    if local_keys:
        method = "defaultonly-diff"
        source = "REST (appcontext keys absent from or differing vs app default/)"
    else:
        rejected_reason = (
            f"stanza '{stanza_name}' exists only in app default/{spec.conf_file}, not local/"
        )
        local_keys = []
        method = "rejected"
        source = "REST (rejected — default/ only; use --default_only)"
    if debug:
        print(
            f"Debug local discovery [{spec.name}/{stanza_name}]: "
            f"defaultonly={len(defaultonly_keys)} layer_local={len(local_keys)} "
            f"method={method}",
            file=sys.stderr,
        )
    return LocalDiscoveryResult(
        local_keys=local_keys,
        source=source,
        method=method,
        merged_key_count=0,
        baseline_key_count=len(defaultonly_keys),
        baseline_diff_keys=local_keys,
        appcontext_keys=appcontext_keys or refine_appcontext_local_keys(appcontext_content, spec),
        rejected_reason=rejected_reason if not local_keys else None,
    )


def _discover_local_conf_keys_baseline_fallback(
    conf_endpoint: str,
    stanza_name: str,
    spec: ConfTypeSpec,
    auth,
    headers: dict,
    *,
    merged_content: dict,
    merged_key_count: int,
    appcontext_content: dict,
    appcontext_keys: List[str],
    appcontext_rejected: Optional[str],
    debug: bool = False,
) -> LocalDiscoveryResult:
    """Inherited baseline diff cross-checked with appcontext when appcontext alone is inconclusive."""
    threshold = local_key_count_threshold(merged_key_count)

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


def discover_local_conf_keys(
    conf_endpoint: str,
    spec: ConfTypeSpec,
    auth,
    headers: dict,
    debug: bool = False,
) -> Optional[LocalDiscoveryResult]:
    """
    Discover keys defined in local/{conf_file} using REST only.

    Minimizes REST calls for the common local-only case:
    1. List default/ stanzas (collection defaultonly=true, one GET)
    2. appcontext=true for app-layer keys (one GET)
    3. defaultonly=true per stanza only when listed in app default/

    Merged effective config and inherited baseline probes run only when
    appcontext alone is inconclusive or fails merged-config sanity checks.
    """
    stanza_name = conf_stanza_name(conf_endpoint)

    stanza_in_default = stanza_in_app_default_layer(conf_endpoint, stanza_name, auth, headers)

    appcontext_content = fetch_appcontext_content(conf_endpoint, auth, headers)
    appcontext_keys = refine_appcontext_local_keys(appcontext_content, spec)

    if stanza_in_default:
        default_layer_result = _discover_local_from_default_layer(
            conf_endpoint,
            stanza_name,
            spec,
            auth,
            headers,
            appcontext_content,
            appcontext_keys,
            debug=debug,
        )
        if default_layer_result is not None:
            return default_layer_result

    # Local-only stanza (not in app default/): appcontext is sufficient when small.
    if (
        not stanza_in_default
        and appcontext_keys
        and len(appcontext_keys) < _LOCAL_KEY_MERGED_MIN
    ):
        if debug:
            print(
                f"Debug local discovery [{spec.name}/{stanza_name}]: "
                f"appcontext={len(appcontext_keys)} method=appcontext "
                f"(no app default/ stanza; skipped merged fetch)",
                file=sys.stderr,
            )
        return LocalDiscoveryResult(
            local_keys=appcontext_keys,
            source="REST (appcontext app-local keys; no app default/ stanza)",
            method="appcontext",
            merged_key_count=0,
            baseline_key_count=0,
            baseline_diff_keys=[],
            appcontext_keys=appcontext_keys,
        )

    merged_entry = fetch_rest_entry(conf_endpoint, auth, headers, optional=True)
    if not merged_entry:
        return None if not appcontext_keys else LocalDiscoveryResult(
            local_keys=appcontext_keys,
            source="REST (appcontext app-local keys; merged stanza unavailable)",
            method="appcontext",
            merged_key_count=0,
            baseline_key_count=0,
            baseline_diff_keys=[],
            appcontext_keys=appcontext_keys,
        )

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
            appcontext_keys=appcontext_keys,
            rejected_reason="merged stanza returned no content keys",
        )

    appcontext_rejected: Optional[str] = None
    if appcontext_keys and keys_look_like_merged_effective(len(appcontext_keys), merged_key_count):
        threshold = local_key_count_threshold(merged_key_count)
        appcontext_rejected = (
            f"appcontext returned {len(appcontext_keys)} keys "
            f"(>= local threshold {threshold} for merged {merged_key_count})"
        )
        if debug:
            print(f"Debug: {appcontext_rejected}", file=sys.stderr)
        appcontext_keys = []

    if appcontext_keys:
        if debug:
            print(
                f"Debug local discovery [{spec.name}/{stanza_name}]: "
                f"merged={merged_key_count} appcontext={len(appcontext_keys)} "
                f"method=appcontext (no app default/ stanza)",
                file=sys.stderr,
            )
        return LocalDiscoveryResult(
            local_keys=appcontext_keys,
            source="REST (appcontext app-local keys; no app default/ stanza)",
            method="appcontext",
            merged_key_count=merged_key_count,
            baseline_key_count=0,
            baseline_diff_keys=[],
            appcontext_keys=appcontext_keys,
        )

    return _discover_local_conf_keys_baseline_fallback(
        conf_endpoint,
        stanza_name,
        spec,
        auth,
        headers,
        merged_content=merged_content,
        merged_key_count=merged_key_count,
        appcontext_content=appcontext_content,
        appcontext_keys=appcontext_keys,
        appcontext_rejected=appcontext_rejected,
        debug=debug,
    )


def log_default_discovery_report(
    spec: ConfTypeSpec,
    *,
    app: str,
    stanza: str,
    discovery: DefaultDiscoveryResult,
    verbose: bool = False,
) -> None:
    """Print a concise stderr summary of default-layer discovery."""
    print(
        f"Default export [{spec.conf_file}] app='{app}' stanza='{stanza}'",
        file=sys.stderr,
    )
    print(
        f"  merged_keys={discovery.merged_key_count} "
        f"default_layer_keys={discovery.default_key_count} "
        f"appcontext_suppressed={len(discovery.appcontext_keys)} "
        f"local_only_suppressed={len(discovery.local_only_keys)}",
        file=sys.stderr,
    )
    print(
        f"  method={discovery.method} default_keys={len(discovery.default_keys)} "
        f"default_collection_stanzas={len(discovery.default_collection_stanzas)}",
        file=sys.stderr,
    )
    if discovery.default_keys:
        print(f"  keys={discovery.default_keys}", file=sys.stderr)
    if discovery.local_only_keys:
        print(f"  suppressed_local_only_keys={discovery.local_only_keys}", file=sys.stderr)
    if discovery.rejected_reason:
        print(f"  rejected={discovery.rejected_reason}", file=sys.stderr)
    print(f"  source={discovery.source}", file=sys.stderr)
    if verbose:
        if discovery.default_collection_stanzas:
            print(
                f"  default_collection_stanzas={discovery.default_collection_stanzas}",
                file=sys.stderr,
            )
        print(
            f"  validate: splunk btool {spec.name} list --debug \"{stanza}\" "
            f"| grep \"etc/apps/{app}/default\" | grep -v \" = $\"",
            file=sys.stderr,
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


def export_default_conf_values(
    conf_endpoint: str,
    default_keys: List[str],
    auth,
    headers: dict,
    *,
    layer_entry: Optional[dict] = None,
) -> Tuple[dict, List[str], dict]:
    """Export values for default/ keys from defaultonly or defaultcontext layer."""
    if layer_entry is not None:
        raw_content, _missing = export_requested_keys(layer_entry, default_keys)
        content = {
            key: value
            for key, value in raw_content.items()
            if key in default_keys and value is not None
        }
        missing_keys = [key for key in default_keys if key not in content]
        return content, missing_keys, layer_entry

    stanza_name = conf_stanza_name(conf_endpoint)
    collection = conf_collection_endpoint(conf_endpoint)
    entry: Optional[dict] = None
    for layer_param in ("defaultonly", "defaultcontext", "appcontext"):
        entry = fetch_rest_entry(
            conf_endpoint,
            auth,
            headers,
            params={layer_param: "true"},
            optional=True,
        )
        if not entry:
            entry = find_conf_collection_entry(
                collection, stanza_name, auth, headers, params={layer_param: "true"}
            )
        if not entry:
            continue
        raw_content, _missing = export_requested_keys(entry, default_keys)
        content = {
            key: value
            for key, value in raw_content.items()
            if key in default_keys and value is not None
        }
        if len(content) == len(default_keys):
            missing_keys = [key for key in default_keys if key not in content]
            return content, missing_keys, entry
    if not entry:
        entry = fetch_rest_entry(conf_endpoint, auth, headers)
    raw_content, _missing = export_requested_keys(entry, default_keys)
    content = {
        key: value
        for key, value in raw_content.items()
        if key in default_keys and value is not None
    }
    missing_keys = [key for key in default_keys if key not in content]
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


def build_default_migration_envelope(
    spec: ConfTypeSpec,
    *,
    endpoint: str,
    owner: str,
    app: str,
    stanza: str,
    default_keys: List[str],
    default_collection_stanzas: List[str],
    content: dict,
    discovery_source: str,
    discovery_method: str = "",
    local_only_keys: Optional[List[str]] = None,
) -> dict:
    parsed = urlparse(endpoint)
    return {
        "migration_version": MIGRATION_ENVELOPE_VERSION,
        "tool_version": __version__,
        "conf_type": spec.name,
        "conf_file": spec.conf_file,
        "layer": "default",
        "source": {
            "host": parsed.netloc,
            "endpoint": endpoint,
            "owner": owner,
            "app": app,
        },
        "stanza": stanza,
        "default_keys": default_keys,
        "default_collection_stanzas": default_collection_stanzas,
        "suppressed_local_only_keys": local_only_keys or [],
        "discovery_source": discovery_source,
        "discovery_method": discovery_method,
        "content": content,
    }


def build_view_migration_envelope(
    *,
    endpoint: str,
    owner: str,
    app: str,
    view_name: str,
    data_ui_views_url: str,
    content: dict,
    discovery_source: str,
    discovery_method: str,
) -> dict:
    parsed = urlparse(endpoint)
    return {
        "migration_version": MIGRATION_ENVELOPE_VERSION,
        "tool_version": __version__,
        "conf_type": "views",
        "source": {
            "host": parsed.netloc,
            "endpoint": endpoint,
            "data_ui_views_url": data_ui_views_url,
            "owner": owner,
            "app": app,
        },
        "view_name": view_name,
        "discovery_source": discovery_source,
        "discovery_method": discovery_method,
        "content": content,
    }


def build_default_view_migration_envelope(
    *,
    endpoint: str,
    owner: str,
    app: str,
    view_name: str,
    data_ui_views_url: str,
    content: dict,
    discovery_source: str,
    discovery_method: str,
    local_override: bool = False,
) -> dict:
    parsed = urlparse(endpoint)
    return {
        "migration_version": MIGRATION_ENVELOPE_VERSION,
        "tool_version": __version__,
        "conf_type": "views",
        "layer": "default",
        "source": {
            "host": parsed.netloc,
            "endpoint": endpoint,
            "data_ui_views_url": data_ui_views_url,
            "owner": owner,
            "app": app,
        },
        "view_name": view_name,
        "local_override_suppressed": local_override,
        "discovery_source": discovery_source,
        "discovery_method": discovery_method,
        "content": content,
    }


def build_view_export_payload(entry: dict) -> dict:
    """Build migration JSON for a dashboard view (XML in eai:data).

    Splunk data/ui/views POST accepts only name and eai:data; label/description
    live inside the XML body.
    """
    content = normalize_content(entry.get("content", {}))
    entry_fields = {k: v for k, v in entry.items() if k not in ("content", "links")}
    lookup_sources = (content, entry_fields, entry)
    out = {}

    for key in VIEW_MIGRATION_FIELDS:
        value = _MISSING
        for source in lookup_sources:
            candidate_value = get_field_value(source, key)
            if candidate_value is not _MISSING:
                value = candidate_value
                break
        if value is not _MISSING and value is not None:
            out[key] = value

    if "name" not in out and entry.get("name"):
        out["name"] = entry["name"]

    return out


def is_data_ui_views_endpoint(endpoint: str) -> bool:
    return "/data/ui/views" in urlparse(endpoint).path


def sanitize_view_post_payload(payload: dict, mode: str) -> dict:
    """Keep only fields Splunk accepts on data/ui/views POST handlers."""
    if "eai:data" not in payload:
        return payload
    sanitized = {"eai:data": payload["eai:data"]}
    if mode == "post" and payload.get("name"):
        sanitized["name"] = payload["name"]
    dropped = sorted(key for key in payload if key not in sanitized)
    if dropped:
        print(
            f"Note: dropped unsupported data/ui/views POST fields: {dropped}",
            file=sys.stderr,
        )
    return sanitized


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


_COLLECTION_ENTITY_TAIL_NAMES = frozenset({
    "conf-props",
    "conf-transforms",
    "conf-savedsearches",
    "conf-macros",
    "conf-views",
    "searches",
    "macros",
    "views",
})


def is_entity_endpoint(endpoint: str) -> bool:
    """True when endpoint URL targets one REST entity, not a collection listing."""
    path = urlparse(endpoint.split("?")[0]).path.rstrip("/")
    if not re.search(r"/servicesNS/[^/]+/[^/]+/", path):
        return False
    last_segment = unquote(path.rsplit("/", 1)[-1])
    return bool(last_segment) and last_segment not in _COLLECTION_ENTITY_TAIL_NAMES


def resolve_delete_target(endpoint: str) -> Tuple[str, str, str]:
    """
    Return (delete_url, resource_type, resource_name) for DELETE.

    View URLs resolve to data/ui/views (canonical delete target). Conf/KO URLs
    are used as provided when they name a single entity.
    """
    base_endpoint = endpoint.split("?")[0].rstrip("/")

    view_ctx = resolve_view_export_context(endpoint)
    if view_ctx:
        _owner, _app, view_name, data_ui_views_url = view_ctx
        return data_ui_views_url, "view", view_name

    conf_ctx = resolve_conf_export_context(endpoint)
    if conf_ctx:
        spec, _owner, _app, stanza_name, _conf_endpoint = conf_ctx
        if not is_entity_endpoint(base_endpoint):
            collection_hint = spec.ko_collection or f"configs/{spec.conf_rest}"
            raise ValueError(
                f"delete requires a single {spec.conf_file} stanza or "
                f"{collection_hint} entity URL, not a collection"
            )
        return base_endpoint, spec.name, stanza_name

    if not is_entity_endpoint(base_endpoint):
        raise ValueError(
            "delete requires a single REST entity URL (not a collection). "
            "Include owner, app, collection, and resource name in --endpoint."
        )
    resource_name = unquote(base_endpoint.rsplit("/", 1)[-1])
    return base_endpoint, "resource", resource_name


def resolve_conf_export_context(
    endpoint: str,
) -> Optional[Tuple[ConfTypeSpec, str, str, str, str]]:
    """Map a KO or conf REST URL to conf export context, if recognized."""
    for spec in CONF_TYPE_REGISTRY.values():
        ctx = resolve_local_export_context(endpoint, spec)
        if ctx:
            owner, app, stanza_name, conf_endpoint = ctx
            return spec, owner, app, stanza_name, conf_endpoint
    return None


def warn_not_local_keys(not_local_keys: list, spec: ConfTypeSpec) -> None:
    if not not_local_keys:
        return
    print(
        f"Warning: The following requested keys are not defined in local/{spec.conf_file} "
        f"and were omitted: {not_local_keys}",
        file=sys.stderr,
    )


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

    conf_ctx = resolve_conf_export_context(args.endpoint)
    if conf_ctx:
        spec, owner, app, stanza_name, conf_endpoint = conf_ctx
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

        local_key_set = set(discovery.local_keys)
        keys_to_export = [key for key in requested_keys if key in local_key_set]
        not_local_keys = [key for key in requested_keys if key not in local_key_set]
        if not_local_keys:
            warn_not_local_keys(not_local_keys, spec)

        if not keys_to_export:
            if discovery.rejected_reason:
                print(
                    f"Error: local key discovery rejected for stanza '{stanza_name}' "
                    f"in app '{app}': {discovery.rejected_reason}",
                    file=sys.stderr,
                )
            else:
                print(
                    f"Error: none of the requested keys are defined in local/{spec.conf_file} "
                    f"for stanza '{stanza_name}' in app '{app}'.",
                    file=sys.stderr,
                )
            sys.exit(1)

        content, missing_keys, conf_entry = export_local_conf_values(
            conf_endpoint, keys_to_export, auth, headers
        )
        warn_missing_keys(conf_entry, missing_keys)
        out_p = build_flat_key_export(content, keys_to_export)
        write_json_output(out_p, args.output, "Successfully exported keys to '{}'")
        return

    target_entry = fetch_target_entry(args.endpoint, auth, headers)
    out_p, missing_keys = export_requested_keys(target_entry, requested_keys)
    warn_missing_keys(target_entry, missing_keys)
    write_json_output(out_p, args.output, "Successfully exported keys to '{}'")


def print_delete_summary(resource_type: str, resource_name: str, endpoint: str) -> None:
    print(
        "\n========================================\n"
        " SUCCESS SUMMARY (DELETE OPERATION)\n"
        "========================================"
    )
    print(f"Deleted {resource_type} '{resource_name}'")
    print(f" -> endpoint: {endpoint}")
    print("========================================\n")


def run_delete(args, auth, headers) -> None:
    """DELETE a single Splunk REST entity identified by --endpoint."""
    try:
        delete_url, resource_type, resource_name = resolve_delete_target(args.endpoint)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        print(f"Expected URL format: {endpoint_hint_for_mode('delete')}", file=sys.stderr)
        sys.exit(1)

    print(
        f"Delete [{resource_type}] resource='{resource_name}'",
        file=sys.stderr,
    )
    print(f"  endpoint={delete_url}", file=sys.stderr)

    status_code, payload = splunk_delete_json(delete_url, auth, headers)
    print(f"Status Code: {status_code}")

    if status_code in (200, 201, 204):
        print_delete_summary(resource_type, resource_name, delete_url)
        if payload:
            write_json_output(
                payload,
                args.output,
                "Successfully wrote delete response to '{}'",
            )
        elif args.output:
            write_json_output(
                {
                    "deleted": resource_name,
                    "resource_type": resource_type,
                    "endpoint": delete_url,
                },
                args.output,
                "Successfully wrote delete confirmation to '{}'",
            )
        return

    if status_code == 404:
        print("Operation failed: resource not found at this endpoint (404).", file=sys.stderr)
    elif status_code == 403:
        print("Operation failed: permission denied (403).", file=sys.stderr)
    else:
        print(f"Operation failed: DELETE returned HTTP {status_code}.", file=sys.stderr)
    if payload:
        print("Response JSON:\n", json.dumps(payload, indent=2))
    sys.exit(1)


def endpoint_hint_for_mode(mode: str) -> str:
    """Return a one-line endpoint format hint for CLI errors."""
    if mode == "delete":
        return (
            "/servicesNS/{owner}/{app}/saved/searches/{name}, "
            "/servicesNS/{owner}/{app}/configs/conf-savedsearches/{stanza}, "
            "/servicesNS/{owner}/{app}/configs/conf-props/{stanza}, "
            "/servicesNS/{owner}/{app}/configs/conf-transforms/{stanza}, "
            "/servicesNS/{owner}/{app}/saved/macros/{name}, "
            "/servicesNS/{owner}/{app}/configs/conf-macros/{stanza}, "
            "/servicesNS/{owner}/{app}/saved/views/{name} (or data/ui/views/{name})"
        )
    if mode == VIEW_EXPORT_MODE:
        return (
            "/servicesNS/{owner}/{app}/saved/views/{name} or "
            "/servicesNS/{owner}/{app}/data/ui/views/{name} or "
            "/servicesNS/{owner}/{app}/configs/conf-views/{name}"
        )
    conf_type_name = EXPORT_MODE_TO_CONF_TYPE.get(mode)
    if not conf_type_name:
        return "/servicesNS/{owner}/{app}/..."
    spec = CONF_TYPE_REGISTRY[conf_type_name]
    if spec.ko_collection:
        return (
            f"/servicesNS/{{owner}}/{{app}}/{spec.ko_collection}/{{name}} or "
            f"/servicesNS/{{owner}}/{{app}}/configs/{spec.conf_rest}/{{stanza}}"
        )
    return f"/servicesNS/{{owner}}/{{app}}/configs/{spec.conf_rest}/{{stanza}}"


def run_export_default_local(spec: ConfTypeSpec, args, auth, headers) -> None:
    """Export app default/ conf keys for one stanza (default/ layer only)."""
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

    discovery = discover_default_conf_keys(
        conf_endpoint, spec, auth, headers, debug=args.debug_local_keys
    )

    if discovery is None:
        print(
            "Error: REST default-layer discovery failed for "
            f"stanza '{stanza_name}' in app '{app}'.",
            file=sys.stderr,
        )
        sys.exit(1)

    log_default_discovery_report(
        spec,
        app=app,
        stanza=stanza_name,
        discovery=discovery,
        verbose=args.debug_local_keys,
    )

    if not discovery.default_keys:
        if discovery.rejected_reason:
            print(
                f"Error: default-layer discovery rejected for stanza '{stanza_name}' "
                f"in app '{app}': {discovery.rejected_reason}",
                file=sys.stderr,
            )
        else:
            print(
                f"Error: no default/ {spec.conf_file} keys found for "
                f"stanza '{stanza_name}' in app '{app}'.",
                file=sys.stderr,
            )
        sys.exit(1)

    content, missing_keys, conf_entry = export_default_conf_values(
        conf_endpoint,
        discovery.default_keys,
        auth,
        headers,
        layer_entry=discovery.default_layer_entry,
    )
    warn_missing_keys(conf_entry, missing_keys)

    flat_output = build_flat_key_export(content, discovery.default_keys)

    if args.migration_envelope:
        if not args.output:
            print(
                "Warning: --migration-envelope requires --output; "
                "writing flat default keys to stdout only.",
                file=sys.stderr,
            )
            write_json_output(flat_output, None)
        else:
            envelope = build_default_migration_envelope(
                spec,
                endpoint=args.endpoint,
                owner=owner,
                app=app,
                stanza=stanza_name,
                default_keys=discovery.default_keys,
                default_collection_stanzas=discovery.default_collection_stanzas,
                content=flat_output,
                discovery_source=discovery.source,
                discovery_method=discovery.method,
                local_only_keys=discovery.local_only_keys,
            )
            write_json_output(flat_output, None)
            write_json_output(
                envelope,
                args.output,
                f"Successfully wrote default migration envelope to '{{}}'",
            )
    else:
        write_json_output(
            flat_output,
            args.output,
            f"Successfully exported {len(flat_output)} default/ {spec.conf_file} keys to '{{}}'",
        )


def run_export_default_view(args, auth, headers) -> None:
    """Export default-only dashboard XML (eai:data) from data/ui/views."""
    ctx = resolve_view_export_context(args.endpoint)
    if not ctx:
        print(
            f"Error: {VIEW_EXPORT_MODE} requires a saved/views, data/ui/views, "
            "or configs/conf-views endpoint.",
            file=sys.stderr,
        )
        sys.exit(1)

    owner, app, view_name, data_ui_views_url = ctx

    discovery = discover_default_view(
        data_ui_views_url,
        owner,
        app,
        view_name,
        auth,
        headers,
        debug=args.debug_local_keys,
    )

    if discovery is None:
        print(
            f"Error: view '{view_name}' not found in app '{app}' "
            f"at {data_ui_views_url}.",
            file=sys.stderr,
        )
        sys.exit(1)

    log_default_view_discovery_report(
        app=app,
        view_name=view_name,
        owner=owner,
        discovery=discovery,
        verbose=args.debug_local_keys,
    )

    if not discovery.is_default:
        print(
            f"Error: view '{view_name}' in app '{app}' is not a default dashboard: "
            f"{discovery.rejected_reason or discovery.source}",
            file=sys.stderr,
        )
        sys.exit(1)

    if not discovery.entry:
        print(
            f"Error: default view discovery returned no REST entry for '{view_name}'.",
            file=sys.stderr,
        )
        sys.exit(1)

    payload = build_view_export_payload(discovery.entry)

    if not payload.get("eai:data"):
        print(
            f"Error: default view '{view_name}' in app '{app}' has no eai:data (dashboard XML).",
            file=sys.stderr,
        )
        sys.exit(1)

    if discovery.local_override:
        print(
            f"  note=local override suppressed; exporting default/ XML only",
            file=sys.stderr,
        )

    xml_bytes = len(str(payload["eai:data"]).encode("utf-8"))
    print(f"  xml_bytes={xml_bytes}", file=sys.stderr)

    if args.migration_envelope:
        if not args.output:
            print(
                "Warning: --migration-envelope requires --output; "
                "writing flat default view JSON to stdout only.",
                file=sys.stderr,
            )
            write_json_output(payload, None)
        else:
            envelope = build_default_view_migration_envelope(
                endpoint=args.endpoint,
                owner=owner,
                app=app,
                view_name=view_name,
                data_ui_views_url=data_ui_views_url,
                content=payload,
                discovery_source=discovery.source,
                discovery_method=discovery.method,
                local_override=discovery.local_override,
            )
            write_json_output(payload, None)
            write_json_output(
                envelope,
                args.output,
                f"Successfully wrote default migration envelope to '{{}}'",
            )
    else:
        write_json_output(
            payload,
            args.output,
            f"Successfully exported default dashboard XML for view '{view_name}' to '{{}}'",
        )


def run_export_local(spec: ConfTypeSpec, args, auth, headers) -> None:
    """Export locally-defined conf keys for one stanza/KO (local/ layer only)."""
    if args.default_only:
        run_export_default_local(spec, args, auth, headers)
        return

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


def run_export_view(args, auth, headers) -> None:
    """Export local-only dashboard XML (eai:data) from data/ui/views for migration."""
    if args.default_only:
        run_export_default_view(args, auth, headers)
        return

    ctx = resolve_view_export_context(args.endpoint)
    if not ctx:
        print(
            f"Error: {VIEW_EXPORT_MODE} requires a saved/views, data/ui/views, "
            "or configs/conf-views endpoint.",
            file=sys.stderr,
        )
        sys.exit(1)

    owner, app, view_name, data_ui_views_url = ctx
    origin = conf_server_origin(data_ui_views_url)

    discovery = discover_local_view(
        data_ui_views_url,
        owner,
        app,
        view_name,
        origin,
        auth,
        headers,
        debug=args.debug_local_keys,
    )

    if discovery is None:
        print(
            f"Error: view '{view_name}' not found in app '{app}' "
            f"at {data_ui_views_url}.",
            file=sys.stderr,
        )
        sys.exit(1)

    log_view_discovery_report(
        app=app,
        view_name=view_name,
        owner=owner,
        discovery=discovery,
        verbose=args.debug_local_keys,
    )

    if not discovery.is_local:
        print(
            f"Error: view '{view_name}' in app '{app}' is not a local dashboard: "
            f"{discovery.rejected_reason or discovery.source}",
            file=sys.stderr,
        )
        sys.exit(1)

    if not discovery.entry:
        print(
            f"Error: local view discovery returned no REST entry for '{view_name}'.",
            file=sys.stderr,
        )
        sys.exit(1)

    payload = build_view_export_payload(discovery.entry)

    if not payload.get("eai:data"):
        print(
            f"Error: local view '{view_name}' in app '{app}' has no eai:data (dashboard XML).",
            file=sys.stderr,
        )
        sys.exit(1)

    xml_bytes = len(str(payload["eai:data"]).encode("utf-8"))
    print(f"  xml_bytes={xml_bytes}", file=sys.stderr)

    if args.migration_envelope:
        if not args.output:
            print(
                "Warning: --migration-envelope requires --output; "
                "writing flat view JSON to stdout only.",
                file=sys.stderr,
            )
            write_json_output(payload, None)
        else:
            envelope = build_view_migration_envelope(
                endpoint=args.endpoint,
                owner=owner,
                app=app,
                view_name=view_name,
                data_ui_views_url=data_ui_views_url,
                content=payload,
                discovery_source=discovery.source,
                discovery_method=discovery.method,
            )
            write_json_output(payload, None)
            write_json_output(
                envelope,
                args.output,
                f"Successfully wrote migration envelope to '{{}}'",
            )
    else:
        write_json_output(
            payload,
            args.output,
            f"Successfully exported local dashboard XML for view '{view_name}' to '{{}}'",
        )


def main():
    parser = argparse.ArgumentParser(
        description="Splunk Knowledge Object Manager — export, review, update, post, and delete via REST.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--mode",
        required=True,
        choices=[
            "export",
            *EXPORT_MODE_TO_CONF_TYPE.keys(),
            VIEW_EXPORT_MODE,
            "endpointreview",
            "update",
            "post",
            "delete",
        ],
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
        help="Verbose stderr logging for local/default key discovery (export-* modes).",
    )
    parser.add_argument(
        "--default_only",
        action="store_true",
        help=(
            "Export app default/ layer only (export-* modes). "
            "Uses defaultonly/defaultcontext REST discovery; suppresses local/ keys and local view overrides."
        ),
    )
    parser.add_argument(
        "--migration-envelope",
        action="store_true",
        help=(
            "Also write migration metadata envelope to --output (export-* modes). "
            "Stdout always receives flat key/view JSON only."
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

    layer_export_modes = set(EXPORT_MODE_TO_CONF_TYPE.keys()) | {VIEW_EXPORT_MODE}
    if args.default_only and args.mode not in layer_export_modes:
        print(
            "Error: --default_only applies only to export-* modes "
            f"({', '.join(sorted(layer_export_modes))}).",
            file=sys.stderr,
        )
        sys.exit(1)

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
        if is_data_ui_views_endpoint(args.endpoint):
            payload = sanitize_view_post_payload(payload, args.mode)

    local_export_modes = set(EXPORT_MODE_TO_CONF_TYPE.keys())
    export_modes = local_export_modes | {VIEW_EXPORT_MODE}
    if args.dry_run:
        if args.mode == "delete":
            method = "DELETE"
        elif args.mode in ("export", *export_modes, "endpointreview"):
            method = "GET"
        else:
            method = "POST"
        dry_run_endpoint = args.endpoint
        if args.mode == "delete":
            try:
                dry_run_endpoint, resource_type, resource_name = resolve_delete_target(
                    args.endpoint
                )
            except ValueError as exc:
                print(f"Error: {exc}", file=sys.stderr)
                print(f"Expected URL format: {endpoint_hint_for_mode('delete')}", file=sys.stderr)
                sys.exit(1)
        print(f"\n--- DRY RUN: Equivalent Curl Command for {args.mode.upper()} ---")
        print(generate_curl_dry_run(method, dry_run_endpoint, auth, headers, payload))
        if args.mode == "delete":
            print(
                f"\nNOTE: Live run DELETEs {resource_type} '{resource_name}' at:\n"
                f"  {dry_run_endpoint}\n",
            )
        elif args.mode == "export":
            dest = args.output if args.output else "STDOUT"
            print(f"\nNOTE: Live run writes keys [{args.keys}] to: {dest}\n")
        elif args.mode in local_export_modes:
            dest = args.output if args.output else "STDOUT"
            conf_type = EXPORT_MODE_TO_CONF_TYPE[args.mode]
            layer = "default/" if args.default_only else "local/"
            print(
                f"\nNOTE: Live run discovers {layer} {CONF_TYPE_REGISTRY[conf_type].conf_file} keys via REST "
                f"and writes JSON to: {dest}\n"
            )
        elif args.mode == VIEW_EXPORT_MODE:
            dest = args.output if args.output else "STDOUT"
            layer = "default/data/ui/views" if args.default_only else "local/data/ui/views"
            print(
                f"\nNOTE: Live run discovers {layer} XML via REST "
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

        elif args.mode == VIEW_EXPORT_MODE:
            run_export_view(args, auth, headers)

        elif args.mode == "endpointreview":
            target_entry = fetch_target_entry(args.endpoint, auth, headers)
            out_p = export_all_fields(target_entry)
            print(f"Found {len(out_p)} non-null keys on endpoint.", file=sys.stderr)
            write_json_output(out_p, args.output, "Successfully exported all fields to '{}'")

        elif args.mode == "delete":
            run_delete(args, auth, headers)

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
