# SPDX-FileCopyrightText: Copyright (C) 2025 Katzenpost developers
# SPDX-License-Identifier: AGPL-3.0-only

"""Resolve a node's approximate geographic location for the Earth view.

Resolution happens here, in Python, at render time; only the resulting latitude
and longitude are written into the visualization data file. No GeoIP database
is shipped to the browser.

Precedence, most trusted first:

  1. a curated, operator-confirmed table (``data/geoip_overrides.json``), keyed
     by node name or by IP address,
  2. an optional local GeoLite2 (or compatible) database, read with the free
     ``maxminddb`` library, only when a database path is supplied,
  3. nothing -- in which case the browser falls back to a deterministic hash
     placement, exactly as it does for a node whose address it never learned.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

DATA_DIR = Path(__file__).parent / "data"
OVERRIDES_PATH = DATA_DIR / "geoip_overrides.json"

_ADDR_RE = re.compile(r"^(?:tcp://)?\[?([^\]]+?)\]?:\d+$")


def ip_from_uri(uri: str) -> str | None:
    """Pull the host out of a ``tcp://host:port`` address (IPv4 or IPv6)."""
    m = _ADDR_RE.match(uri.strip())
    return m.group(1) if m else None


def load_overrides(path: Path | None = None) -> dict[str, list[Any]]:
    """Load the curated location table: ``{name_or_ip: [lat, lon, "label"]}``."""
    p = path or OVERRIDES_PATH
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _try_open(maxminddb: Any, path: str | None) -> Any:
    """Open a maxminddb database, or return None if the path is missing/bad."""
    if not path or not Path(path).exists():
        return None
    try:
        return maxminddb.open_database(path)
    except (OSError, ValueError):
        return None


class GeoResolver:
    """Resolve IP/name to a location using the curated table, then a database."""

    def __init__(
        self,
        db_path: str | None = None,
        asn_db_path: str | None = None,
        overrides: dict[str, list[Any]] | None = None,
        asn_whois: bool = False,
        asn_cache_path: str | None = None,
    ) -> None:
        self._overrides = (
            overrides if overrides is not None else load_overrides()
        )
        self._db = None
        self._asn = None
        self._asn_whois = asn_whois
        self._asn_cache_path = (
            Path(asn_cache_path) if asn_cache_path else None
        )
        self._asn_cache: dict[str, Any] = {}
        if self._asn_cache_path and self._asn_cache_path.exists():
            try:
                loaded = json.loads(
                    self._asn_cache_path.read_text(encoding="utf-8")
                )
                if isinstance(loaded, dict):
                    self._asn_cache = loaded
            except (OSError, json.JSONDecodeError):
                self._asn_cache = {}
        if db_path or asn_db_path:
            try:
                import maxminddb  # optional dependency; only needed with a database
            except ImportError:
                maxminddb = None  # type: ignore[assignment]
            if maxminddb is not None:
                self._db = _try_open(maxminddb, db_path)
                self._asn = _try_open(maxminddb, asn_db_path)

    def resolve_asn(self, ip: str | None) -> dict[str, Any] | None:
        """Return {asn, org} for an IP: from the ASN database if present, else
        (when enabled) an ipwhois RDAP lookup with an on-disk cache."""
        if not ip:
            return None
        if self._asn is not None:
            try:
                rec: Any = self._asn.get(ip)
            except (ValueError, KeyError):
                rec = None
            if isinstance(rec, dict):
                num = rec.get("autonomous_system_number")
                org = rec.get("autonomous_system_organization")
                if num is not None or org:
                    out: dict[str, Any] = {}
                    if num is not None:
                        out["asn"] = "AS" + str(num)
                    if org:
                        out["org"] = str(org)
                    return out
        if self._asn_whois:
            return self._asn_via_whois(ip)
        return None

    def _asn_via_whois(self, ip: str) -> dict[str, Any] | None:
        """RDAP ASN lookup for an IP, cached on disk. A cached entry (positive
        or the empty negative marker) is reused without a network call."""
        if ip in self._asn_cache:
            hit = self._asn_cache[ip]
            return hit or None
        result: dict[str, Any] | None = None
        try:
            from ipwhois import IPWhois

            rdap = IPWhois(ip).lookup_rdap(depth=0)
            num = str(rdap.get("asn") or "").split()[0].strip()
            desc = (rdap.get("asn_description") or "").split(",")[0].strip()
            if num and num.upper() != "NA":
                result = {"asn": "AS" + num}
                if desc:
                    result["org"] = desc
        except Exception:  # noqa: BLE001 - network/parse failures degrade to none
            result = None
        self._asn_cache[ip] = result or {}
        if self._asn_cache_path:
            try:
                self._asn_cache_path.parent.mkdir(parents=True, exist_ok=True)
                self._asn_cache_path.write_text(
                    json.dumps(self._asn_cache), encoding="utf-8"
                )
            except OSError:
                pass
        return result

    def _from_override(self, key: str | None) -> dict[str, Any] | None:
        if not key or key not in self._overrides:
            return None
        v = self._overrides[key]
        if not isinstance(v, (list, tuple)) or len(v) < 2:
            return None
        label = str(v[2]) if len(v) > 2 and v[2] else ""
        return {
            "lat": float(v[0]),
            "lon": float(v[1]),
            "label": label,
            "source": "curated",
        }

    def _from_db(self, ip: str | None) -> dict[str, Any] | None:
        if not ip or self._db is None:
            return None
        try:
            rec: Any = self._db.get(ip)
        except (ValueError, KeyError):
            return None
        if not isinstance(rec, dict):
            return None
        loc: Any = rec.get("location") or {}
        lat, lon = loc.get("latitude"), loc.get("longitude")
        if lat is None or lon is None:
            return None
        city: Any = ((rec.get("city") or {}).get("names") or {}).get("en", "")
        country: Any = ((rec.get("country") or {}).get("names") or {}).get(
            "en", ""
        )
        label = ", ".join(str(x) for x in (city, country) if x)
        return {
            "lat": float(lat),
            "lon": float(lon),
            "label": label,
            "source": "geoip-db",
        }

    def resolve(
        self, ip: str | None, name: str | None = None
    ) -> dict[str, Any] | None:
        """Return ``{lat, lon, label, source}`` or None. Curated wins over the
        database; a name-keyed override wins over an IP-keyed one."""
        return (
            self._from_override(name)
            or self._from_override(ip)
            or self._from_db(ip)
        )
