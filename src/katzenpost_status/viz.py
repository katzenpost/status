# SPDX-FileCopyrightText: Copyright (C) 2025 Katzenpost developers
# SPDX-License-Identifier: AGPL-3.0-only

"""Build a three.js status animation from live consensus data.

This renders a *second* status page alongside the main report. It takes the
real PKI consensus document (node names, roles, topology layers) plus the
network survey (ICMP ping / TCP traceroute) results and writes a set of files
into the output directory:

  * a small static HTML shell,
  * a JSON data file, rewritten every run, that the page fetches on a timer,
  * a directory of static assets (the vendored three.js modules and our
    application JS), only rewritten when their content changes.

Every asset is a local file in the output directory; the page loads nothing
from a third-party CDN.

Colours mirror the terminal/HTML report's scheme: a node in consensus and
reachable is cyan ("ok"); reachable but not in consensus is yellow ("out");
neither is red ("down"); an address we never learned is dim grey ("unknown").
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from html import escape as html_escape
from pathlib import Path
from typing import Any

from .status import (
    decode_node,
    get_icmp_latency_from_survey,
    get_operational_nodes,
    role_tcp_status,
    _survey_entries_for_role,
)
from .viz_geo import GeoResolver, ip_from_uri

ASSETS_DIR = Path(__file__).parent / "assets"
VENDOR_DIR = ASSETS_DIR / "vendor" / "three"
SHELL_PATH = ASSETS_DIR / "viz_shell.html"
APP_JS_PATH = ASSETS_DIR / "viz_app.js"

ASSETS_SUBDIR = "katzenpost-viz"
APP_JS_NAME = "katzenpost-viz.js"

FEATURES_SRC = ASSETS_DIR / "features"
FEATURES_SUBDIR = "features"
FEATURE_BUNDLE_NAME = "features.bundle.js"

VENDOR_SCRIPTS = [
    "three.min.js",
    "OrbitControls.js",
    "CopyShader.js",
    "LuminosityHighPassShader.js",
    "EffectComposer.js",
    "RenderPass.js",
    "ShaderPass.js",
    "UnrealBloomPass.js",
]

STATUS_COLORS = {
    "ok": "#00f3ff",
    "degraded": "#ffcc33",
    "out": "#ffaa00",
    "down": "#ff2d6b",
    "unknown": "#556677",
}


def _fingerprint(value: Any) -> str | None:
    """Short blake2b-256 hex fingerprint of a key's bytes (keys are not
    human-readable, so we show a stable identifier instead)."""
    if not isinstance(value, (bytes, bytearray)):
        return None
    return hashlib.blake2b(bytes(value), digest_size=32).hexdigest()


def _addresses(desc: dict[str, Any]) -> list[str]:
    """Flatten a node descriptor's Addresses map into a list of URIs."""
    out: list[str] = []
    addrs = desc.get("Addresses", {}) or {}
    if isinstance(addrs, dict):
        for transport in ("tcp4", "tcp", "tcp6"):
            for a in addrs.get(transport, []) or []:
                out.append(str(a))
        for transport, lst in addrs.items():
            if transport not in ("tcp4", "tcp", "tcp6"):
                for a in lst or []:
                    out.append(str(a))
    return out


def _node_details(desc: dict[str, Any] | None) -> dict[str, Any]:
    """Human-relevant consensus fields for a node, shown when it is clicked.

    Everything the descriptor carries that is meaningful to display: the service
    capabilities (Kaetzchen), network addresses, version, load weight,
    authentication type, role flags, a key fingerprint, the epochs it holds mix
    or envelope keys for, and the storage replica id."""
    if not desc:
        return {}
    d: dict[str, Any] = {}

    kaetzchen = desc.get("Kaetzchen")
    if isinstance(kaetzchen, dict) and kaetzchen:
        d["capabilities"] = sorted(kaetzchen.keys())

    addrs = _addresses(desc)
    if addrs:
        d["addresses"] = addrs

    if desc.get("Version"):
        d["version"] = desc["Version"]
    if desc.get("AuthenticationType"):
        d["auth_type"] = desc["AuthenticationType"]
    if isinstance(desc.get("LoadWeight"), int):
        d["load_weight"] = desc["LoadWeight"]
    if desc.get("IsGatewayNode"):
        d["is_gateway"] = True
    if desc.get("IsServiceNode"):
        d["is_service"] = True

    fp = _fingerprint(desc.get("IdentityKey"))
    if fp:
        d["identity_fingerprint"] = fp
    link_fp = _fingerprint(desc.get("LinkKey"))
    if link_fp:
        d["link_fingerprint"] = link_fp

    mixkeys = desc.get("MixKeys")
    if isinstance(mixkeys, dict) and mixkeys:
        d["mixkey_epochs"] = sorted(int(e) for e in mixkeys.keys())
    envkeys = desc.get("EnvelopeKeys")
    if isinstance(envkeys, dict) and envkeys:
        d["envelope_key_epochs"] = sorted(int(e) for e in envkeys.keys())
    if isinstance(desc.get("ReplicaID"), int):
        d["replica_id"] = desc["ReplicaID"]

    return d


def _network_consensus(doc: dict[str, Any]) -> dict[str, Any]:
    """Document-level consensus fields worth surfacing in the HUD."""
    out: dict[str, Any] = {}
    for key, dest in (
        ("Epoch", "epoch"),
        ("GenesisEpoch", "genesis_epoch"),
        ("Version", "version"),
        ("PKISignatureScheme", "pki_signature_scheme"),
    ):
        if doc.get(key) not in (None, ""):
            out[dest] = doc[key]
    for key, dest in (
        ("SphinxGeometryHash", "sphinx_geometry_hash"),
        ("SharedRandomValue", "shared_random_value"),
    ):
        fp = _fingerprint(doc.get(key))
        if fp:
            out[dest] = fp
    replica_ids = doc.get("ConfiguredReplicaIDs")
    if isinstance(replica_ids, list) and replica_ids:
        out["configured_replica_ids"] = replica_ids
    out["wire"] = "PQ Noise"
    kem = _link_kem(doc)
    if kem:
        out["link_kem"] = kem
    return out


def _link_kem(doc: dict[str, Any]) -> str | None:
    """Read the link KEM scheme name from an advertised link public key's PEM
    header (for example "KYBER768-X25519 PUBLIC KEY")."""
    header = re.compile(r"-----BEGIN ([A-Z0-9\-]+) PUBLIC KEY-----")
    for raw in doc.get("ServiceNodes", []) or []:
        adv = decode_node(raw).get("KaetzchenAdvertizedData")
        if not isinstance(adv, dict):
            continue
        for entry in adv.values():
            if not isinstance(entry, dict):
                continue
            for value in entry.values():
                if isinstance(value, str):
                    m = header.search(value)
                    if m:
                        return m.group(1)
    return None


def _best_hops(
    name: str,
    category: str,
    survey_results: dict[str, dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Return the traceroute hop list for this node in this role, preferring a
    reachable survey entry. Empty list means no path was recorded."""
    entries = _survey_entries_for_role(name, category, survey_results)
    if not entries:
        return []
    chosen: dict[str, Any] | None = None
    for data in entries:
        tcp = data.get("tcp_traceroute", {}) or {}
        if tcp.get("reachable"):
            chosen = data
            break
    if chosen is None:
        chosen = entries[0]
    hops = (chosen.get("tcp_traceroute", {}) or {}).get("hops", []) or []
    out: list[dict[str, Any]] = []
    for hop in hops:
        out.append(
            {
                "hop": hop.get("hop"),
                "ip": hop.get("ip"),
                "latency_ms": hop.get("latency_ms"),
            }
        )
    return out


def _node_entry(
    name: str,
    node_type: str,
    category: str,
    layer: int | None,
    operational: set[str],
    survey_results: dict[str, dict[str, Any]] | None,
    node_status: dict[str, tuple[bool, float | None]],
    in_consensus: bool,
    descriptor: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble one node's status record for the animation."""
    tcp_up, tcp_lat = role_tcp_status(
        name, category, survey_results, node_status
    )
    icmp_lat = get_icmp_latency_from_survey(name, survey_results, category)
    hops = _best_hops(name, category, survey_results)
    surveyed = bool(_survey_entries_for_role(name, category, survey_results))

    latency = tcp_lat if tcp_lat is not None else icmp_lat

    reachable = bool(tcp_up) or icmp_lat is not None
    if in_consensus:
        status = "ok" if (reachable or not surveyed) else "degraded"
    elif tcp_up:
        status = "out"
    elif surveyed:
        status = "down"
    else:
        status = "unknown"

    return {
        "name": name,
        "type": node_type,
        "layer": layer,
        "status": status,
        "color": STATUS_COLORS[status],
        "in_consensus": in_consensus,
        "reachable": bool(tcp_up),
        "latency_ms": round(latency, 1)
        if isinstance(latency, (int, float))
        else None,
        "hop_count": len(hops),
        "hops": hops,
        "details": _node_details(descriptor),
    }


TRAFFIC_PARAM_NAMES = (
    "SendRatePerMinute",
    "Mu",
    "LambdaP",
    "LambdaL",
    "LambdaD",
    "LambdaM",
    "LambdaG",
    "LambdaR",
)


def _extract_parameters(doc: dict[str, Any]) -> dict[str, float | None]:
    doc_params = doc.get("Parameters", {}) or {}

    def get(name: str) -> Any:
        if name in doc_params:
            return doc_params[name]
        if name in doc:
            return doc[name]
        return None

    out: dict[str, float | None] = {}
    for name in TRAFFIC_PARAM_NAMES:
        val = get(name)
        try:
            out[name] = float(val) if val is not None else None
        except (TypeError, ValueError):
            out[name] = None
    return out


def build_viz_payload(
    doc: dict[str, Any],
    survey_results: dict[str, dict[str, Any]] | None = None,
    node_status: dict[str, tuple[bool, float | None]] | None = None,
    dirauth_status: dict[str, tuple[bool, float | None]] | None = None,
    network_name: str = "namenlos",
    epoch: int | None = None,
    epoch_time_str: str | None = None,
    epoch_end: str | None = None,
    epoch_period_s: float | None = None,
    generated_at: str | None = None,
    geo_resolver: GeoResolver | None = None,
    vantage: dict[str, Any] | None = None,
    clients_per_gateway: int = 3,
) -> dict[str, Any]:
    """Build the JSON-serialisable payload the animation consumes.

    Nodes are keyed per (name, role) so a machine running several roles is not
    conflated (see the dual-role fix in status.py). Reuses the report's
    consensus decoders and role-scoped survey helpers so the animation shows the
    same status the tables do.
    """
    node_status = node_status or {}
    dirauth_status = dirauth_status or {}
    operational = get_operational_nodes(doc)
    if geo_resolver is None:
        geo_resolver = GeoResolver()

    nodes: list[dict[str, Any]] = []

    def decoded_of(raw_nodes: list[Any]) -> list[tuple[str, dict[str, Any]]]:
        out: list[tuple[str, dict[str, Any]]] = []
        for raw in raw_nodes:
            desc = decode_node(raw)
            name = desc.get("Name", "")
            if name:
                out.append((name, desc))
        return out

    dirauth_names = sorted(dirauth_status.keys())
    for name in dirauth_names:
        up, lat = dirauth_status.get(name, (False, None))
        tcp_up, tcp_lat = role_tcp_status(
            name, "dirauth", survey_results, node_status
        )
        reachable = bool(up or tcp_up)
        latency = lat if lat is not None else tcp_lat
        hops = _best_hops(name, "dirauth", survey_results)
        status = "ok" if reachable else "down"
        nodes.append(
            {
                "name": name,
                "type": "dirauth",
                "layer": None,
                "status": status,
                "color": STATUS_COLORS[status],
                "in_consensus": True,
                "reachable": reachable,
                "latency_ms": round(latency, 1)
                if isinstance(latency, (int, float))
                else None,
                "hop_count": len(hops),
                "hops": hops,
                "details": {},
            }
        )

    for name, desc in decoded_of(doc.get("GatewayNodes", [])):
        nodes.append(
            _node_entry(
                name,
                "gateway",
                "gateway",
                None,
                operational,
                survey_results,
                node_status,
                name in operational,
                desc,
            )
        )

    layers: list[list[str]] = []
    for layer_idx, layer in enumerate(doc.get("Topology", [])):
        decoded = decoded_of(layer)
        layers.append([name for name, _ in decoded])
        for name, desc in decoded:
            nodes.append(
                _node_entry(
                    name,
                    "mix",
                    "mix",
                    layer_idx,
                    operational,
                    survey_results,
                    node_status,
                    name in operational,
                    desc,
                )
            )

    for name, desc in decoded_of(doc.get("ServiceNodes", [])):
        nodes.append(
            _node_entry(
                name,
                "service",
                "service",
                None,
                operational,
                survey_results,
                node_status,
                name in operational,
                desc,
            )
        )

    for name, desc in decoded_of(doc.get("StorageReplicas", [])):
        nodes.append(
            _node_entry(
                name,
                "storage",
                "storage",
                None,
                operational,
                survey_results,
                node_status,
                name in operational,
                desc,
            )
        )

    placed = {n["name"] for n in nodes}
    dirauth_set = set(dirauth_names)
    if survey_results:
        out_by_name: dict[str, dict[str, Any]] = {}
        for data in survey_results.values():
            name = data.get("name", "")
            if not name or name in placed or name in dirauth_set:
                continue
            tcp = data.get("tcp_traceroute", {}) or {}
            if not tcp.get("reachable"):
                continue
            raw_type = str(data.get("node_type", "") or "")
            role = (
                "mix" if raw_type.startswith("mix") else (raw_type or "node")
            )
            lat = tcp.get("final_latency_ms")
            hops = tcp.get("hops", []) or []
            cur = out_by_name.get(name)
            better_lat = isinstance(lat, (int, float)) and (
                cur is None
                or cur["latency_ms"] is None
                or lat < cur["latency_ms"]
            )
            if cur is None or better_lat:
                host, port = data.get("host"), data.get("port")
                details: dict[str, Any] = {"role": role}
                if host and host != "unknown" and port:
                    details["addresses"] = [f"tcp://{host}:{port}"]
                out_by_name[name] = {
                    "name": name,
                    "type": "out",
                    "role": role,
                    "layer": None,
                    "status": "out",
                    "color": STATUS_COLORS["out"],
                    "in_consensus": False,
                    "reachable": True,
                    "latency_ms": round(float(lat), 1)
                    if isinstance(lat, (int, float))
                    else None,
                    "hop_count": len(hops),
                    "hops": [
                        {
                            "hop": h.get("hop"),
                            "ip": h.get("ip"),
                            "latency_ms": h.get("latency_ms"),
                        }
                        for h in hops
                    ],
                    "details": details,
                }
        for name in sorted(out_by_name):
            nodes.append(out_by_name[name])

    for n in nodes:
        addrs = (n.get("details") or {}).get("addresses") or []
        ip = ip_from_uri(addrs[0]) if addrs else None
        if ip is None and survey_results:
            for data in survey_results.values():
                host = data.get("host")
                if (
                    data.get("name") == n["name"]
                    and host
                    and host != "unknown"
                ):
                    ip = host
                    break
        location = geo_resolver.resolve(ip, n["name"])
        if location:
            n["geo"] = location
        n_asn = geo_resolver.resolve_asn(ip)
        if n_asn:
            n["asn"] = n_asn.get("asn", "")
            n["net"] = n_asn.get("org", "")
        for hop in n.get("hops", []):
            hip = hop.get("ip")
            if not hip:
                continue
            hg = geo_resolver.resolve(hip, None)
            if hg:
                hop["geo"] = {
                    "lat": hg["lat"],
                    "lon": hg["lon"],
                    "label": hg.get("label", ""),
                }
            asn = geo_resolver.resolve_asn(hip)
            if asn:
                hop["asn"] = asn.get("asn", "")
                hop["net"] = asn.get("org", "")

    def status_counts() -> dict[str, int]:
        counts: dict[str, int] = {"ok": 0, "out": 0, "down": 0, "unknown": 0}
        for n in nodes:
            counts[n["status"]] = counts.get(n["status"], 0) + 1
        return counts

    return {
        "network_name": network_name,
        "epoch": epoch,
        "epoch_time_str": epoch_time_str,
        "epoch_end": epoch_end,
        "epoch_period_s": epoch_period_s,
        "generated_at": generated_at
        or (datetime.utcnow().isoformat(timespec="microseconds") + "Z"),
        "parameters": _extract_parameters(doc),
        "consensus": _network_consensus(doc),
        "vantage": vantage,
        "clients_per_gateway": int(clients_per_gateway),
        "layers": layers,
        "nodes": nodes,
        "counts": {
            "total": len(nodes),
            "layers": len(layers),
            "by_status": status_counts(),
        },
        # Required attribution when a GeoIP database actually placed a node
        # (DB-IP Lite is CC BY 4.0; MaxMind GeoLite2 carries its own notice).
        "geoip_credit": geo_resolver.attribution(),
    }


def render_data_json(payload: dict[str, Any]) -> str:
    """Render the data file: plain JSON. The page fetches this on a timer and
    rebuilds when it changes, so a cron run only rewrites this one file."""
    return json.dumps(payload, separators=(",", ":"))


def _feature_files() -> list[str]:
    """Names of the feature plugin JS files, sorted for a stable load order."""
    if not FEATURES_SRC.is_dir():
        return []
    return sorted(p.name for p in FEATURES_SRC.glob("*.js"))


def _feature_bundle_text() -> str:
    parts = [
        (FEATURES_SRC / name).read_text(encoding="utf-8")
        for name in _feature_files()
    ]
    return "\n;\n".join(parts) + "\n"


def _feature_bundle_url() -> str:
    return f"{ASSETS_SUBDIR}/{FEATURES_SUBDIR}/{FEATURE_BUNDLE_NAME}"


def _asset_version(path: Path) -> str:
    """Short content hash so a changed asset gets a fresh URL (cache-bust)."""
    try:
        return hashlib.md5(path.read_bytes()).hexdigest()[:8]
    except OSError:
        return ""


def _resolve_asset_source(rel_url: str) -> Path | None:
    """Map a shell asset URL (e.g. 'katzenpost-viz/features/9e-geo3d.js') back
    to its source file so we can hash it for cache-busting."""
    prefix = ASSETS_SUBDIR + "/"
    if not rel_url.startswith(prefix):
        return None
    rest = rel_url[len(prefix) :]
    if rest == APP_JS_NAME:
        return APP_JS_PATH
    if rest.startswith(FEATURES_SUBDIR + "/"):
        return FEATURES_SRC / rest.split("/", 1)[1]
    return VENDOR_DIR / rest


def _cache_bust(html: str) -> str:
    """Append a content-hash query string to every local .js asset URL. Feature
    and app files keep fixed names, so without this a browser or CDN serves the
    stale cached copy after a redeploy (e.g. the old routing-less geometry JS);
    a per-file hash re-fetches only what actually changed."""
    pattern = re.compile(
        r'src="(' + re.escape(ASSETS_SUBDIR) + r'/[^"?]+\.js)"'
    )

    def repl(match: re.Match[str]) -> str:
        url = match.group(1)
        if url == _feature_bundle_url():
            ver = hashlib.md5(
                _feature_bundle_text().encode("utf-8")
            ).hexdigest()[:8]
            return f'src="{url}?v={ver}"'
        src = _resolve_asset_source(url)
        if src is None or not src.exists():
            return match.group(0)
        ver = _asset_version(src)
        return f'src="{url}?v={ver}"' if ver else match.group(0)

    return pattern.sub(repl, html)


def render_shell_html(
    network_name: str,
    data_file: str,
    poll_seconds: int,
) -> str:
    """Render the small, static HTML shell that loads the local JS assets and
    the data file. This content does not depend on the live data, so it is the
    same every run (idempotent), apart from the per-asset cache-busting hashes
    which change only when an asset's content changes."""
    shell = SHELL_PATH.read_text(encoding="utf-8")
    feature_tags = f'<script src="{_feature_bundle_url()}"></script>'
    html = (
        shell.replace("__NETWORK_NAME__", html_escape(network_name))
        .replace("__ASSETS_DIR__", ASSETS_SUBDIR)
        .replace("__APP_JS__", APP_JS_NAME)
        .replace("__DATA_FILE__", data_file)
        .replace("__POLL_SECONDS__", str(int(poll_seconds)))
        .replace("__FEATURE_SCRIPTS__", feature_tags)
    )
    return _cache_bust(html)


def _write_if_changed(path: Path, content: str) -> bool:
    """Write content only when it differs from what is already on disk, so the
    static assets keep a stable mtime across cron runs (and browsers can cache
    them). Returns True if the file was written."""
    if path.exists():
        try:
            if path.read_text(encoding="utf-8") == content:
                return False
        except OSError:
            pass
    path.write_text(content, encoding="utf-8")
    return True


def _write_static_assets(assets_dir: Path) -> None:
    """Write the vendored three.js modules and the application JS into the
    assets sub-directory, only when their content has changed."""
    assets_dir.mkdir(parents=True, exist_ok=True)
    for fname in VENDOR_SCRIPTS:
        _write_if_changed(
            assets_dir / fname,
            (VENDOR_DIR / fname).read_text(encoding="utf-8"),
        )
    _write_if_changed(
        assets_dir / APP_JS_NAME, APP_JS_PATH.read_text(encoding="utf-8")
    )
    if _feature_files():
        feat_dir = assets_dir / FEATURES_SUBDIR
        feat_dir.mkdir(parents=True, exist_ok=True)
        _write_if_changed(feat_dir / FEATURE_BUNDLE_NAME, _feature_bundle_text())
    earth_src = ASSETS_DIR / "earth"
    if earth_src.is_dir():
        earth_dir = assets_dir / "earth"
        earth_dir.mkdir(parents=True, exist_ok=True)
        for f in sorted(earth_src.glob("*.json")):
            _write_if_changed(
                earth_dir / f.name, f.read_text(encoding="utf-8")
            )


def _write_history(
    out_dir: Path,
    stem: str,
    payload: dict[str, Any],
    data_json_text: str,
    history_len: int,
) -> None:
    """Keep a rolling window of recent epochs' data snapshots plus a compact
    summary index, so the page can scrub back through recent epochs. Done in
    the normal render (no separate job). Snapshots are keyed by epoch and
    deduped; epoch 0 / no-consensus reuses one rolling slot. Files past the
    window are pruned along with their index entries. The compact index carries
    per-epoch counts and a name/type/status list, so the client computes the
    sparkline and joined/left diff from one fetch, not N snapshot fetches.
    """
    if history_len <= 0:
        return
    hist_dir = out_dir / (stem + "-history")
    hist_dir.mkdir(parents=True, exist_ok=True)
    epoch = int(payload.get("epoch") or 0)
    snap_name = f"{epoch}.json"
    (hist_dir / snap_name).write_text(data_json_text, encoding="utf-8")

    index_path = hist_dir / "index.json"
    try:
        index = json.loads(index_path.read_text(encoding="utf-8"))
        if not isinstance(index, list):
            index = []
    except (OSError, ValueError):
        index = []
    summary = {
        "epoch": epoch,
        "file": snap_name,
        "generated_at": payload.get("generated_at"),
        "epoch_time_str": payload.get("epoch_time_str"),
        "counts": payload.get("counts", {}),
        "nodes": [
            {"name": n["name"], "type": n["type"], "status": n["status"]}
            for n in payload.get("nodes", [])
        ],
    }
    index = [e for e in index if e.get("epoch") != epoch]
    index.append(summary)
    index.sort(key=lambda e: e.get("epoch", 0))
    if len(index) > history_len:
        for stale in index[:-history_len]:
            fname = str(stale.get("file", ""))
            if fname:
                try:
                    (hist_dir / fname).unlink(missing_ok=True)
                except OSError:
                    pass
        index = index[-history_len:]
    index_path.write_text(json.dumps(index), encoding="utf-8")


def generate_viz(
    doc: dict[str, Any],
    output_file: str,
    survey_results: dict[str, dict[str, Any]] | None = None,
    node_status: dict[str, tuple[bool, float | None]] | None = None,
    dirauth_status: dict[str, tuple[bool, float | None]] | None = None,
    network_name: str = "namenlos",
    epoch: int | None = None,
    epoch_time_str: str | None = None,
    epoch_end: str | None = None,
    epoch_period_s: float | None = None,
    poll_seconds: int = 60,
    geoip_db: str | None = None,
    geoip_asn_db: str | None = None,
    asn_whois: bool = False,
    asn_cache_path: str | None = None,
    vantage: dict[str, Any] | None = None,
    clients_per_gateway: int = 3,
    history_len: int = 48,
    write_history: bool = True,
) -> None:
    """Write the animated status page as a set of files in the output directory:

      * ``<name>.html``        - the static shell (this run and every run)
      * ``<name>.data.json``   - the live data (rewritten every run)
      * ``katzenpost-viz/``    - vendored three.js + our app JS (static; only
                                 rewritten when their content changes)

    The browser loads the shell and JS once and then fetches the small JSON data
    file on a timer, so a cron run only needs to rewrite ``<name>.data.json``.
    Nothing is loaded from a third-party CDN - every asset is a local file in
    the output dir. (Fetching JSON requires serving over http; opening the page
    directly from disk via file:// will not load the data.)
    """
    payload = build_viz_payload(
        doc,
        survey_results=survey_results,
        node_status=node_status,
        dirauth_status=dirauth_status,
        network_name=network_name,
        epoch=epoch,
        epoch_time_str=epoch_time_str,
        epoch_end=epoch_end,
        epoch_period_s=epoch_period_s,
        geo_resolver=GeoResolver(
            db_path=geoip_db,
            asn_db_path=geoip_asn_db,
            asn_whois=asn_whois,
            asn_cache_path=asn_cache_path,
        ),
        vantage=vantage,
        clients_per_gateway=clients_per_gateway,
    )

    out_html = Path(output_file)
    out_dir = out_html.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    data_name = out_html.stem + ".data.json"

    _write_static_assets(out_dir / ASSETS_SUBDIR)
    data_json_text = render_data_json(payload)
    (out_dir / data_name).write_text(data_json_text, encoding="utf-8")
    out_html.write_text(
        render_shell_html(network_name, data_name, poll_seconds),
        encoding="utf-8",
    )
    if write_history:
        _write_history(
            out_dir, out_html.stem, payload, data_json_text, history_len
        )
