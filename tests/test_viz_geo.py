"""Tests for GeoIP resolution used by the Earth view.

These exercise the resolver's precedence (curated table over database) and the
address parsing, with no database and no network.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from katzenpost_status import viz_geo  # noqa: E402


def test_ip_from_uri():
    assert viz_geo.ip_from_uri("tcp://74.50.67.182:30209") == "74.50.67.182"
    assert viz_geo.ip_from_uri("tcp://[2a01:4f9::1]:443") == "2a01:4f9::1"
    assert viz_geo.ip_from_uri("74.50.67.182:30209") == "74.50.67.182"
    assert viz_geo.ip_from_uri("not-an-address") is None


def test_curated_override_by_ip_and_name():
    r = viz_geo.GeoResolver(
        overrides={
            "1.2.3.4": [10.0, 20.0, "City A"],
            "annares": [1.0, 2.0, "Named"],
        }
    )
    assert r.resolve("1.2.3.4") == {
        "lat": 10.0,
        "lon": 20.0,
        "label": "City A",
        "source": "curated",
    }
    # A name-keyed override wins over an IP-keyed one.
    assert r.resolve("1.2.3.4", "annares")["lat"] == 1.0
    assert r.resolve("9.9.9.9", "nobody") is None


def test_shipped_overrides_load_and_are_well_formed():
    ov = viz_geo.load_overrides()
    assert isinstance(ov, dict) and ov, "curated table should ship seeded"
    for key, val in ov.items():
        assert isinstance(val, list) and len(val) >= 2
        assert isinstance(val[0], (int, float)) and isinstance(
            val[1], (int, float)
        )


def test_missing_database_degrades_without_crashing():
    # A configured-but-absent database path must not fail the render; it just
    # means no location from the DB and no AS (the production service points at
    # the standard GeoLite2 path, which may not be installed).
    r = viz_geo.GeoResolver(
        db_path="/no/such/City.mmdb", asn_db_path="/no/such/ASN.mmdb"
    )
    assert r.resolve_asn("8.8.8.8") is None
    # a curated override still resolves without any database
    r2 = viz_geo.GeoResolver(
        db_path="/no/such/City.mmdb", overrides={"nodeX": [1.0, 2.0, "Town"]}
    )
    loc = r2.resolve(None, "nodeX")
    assert loc and loc["lat"] == 1.0 and loc["lon"] == 2.0


def test_asn_whois_uses_cache_without_network(tmp_path):
    import json

    cache = tmp_path / "asn-cache.json"
    cache.write_text(
        json.dumps(
            {
                "1.2.3.4": {
                    "asn": "AS64500",
                    "org": "Test Net",
                },  # positive, cached
                "5.6.7.8": {},  # negative marker, cached
            }
        )
    )
    r = viz_geo.GeoResolver(asn_whois=True, asn_cache_path=str(cache))
    assert r.resolve_asn("1.2.3.4") == {"asn": "AS64500", "org": "Test Net"}
    assert r.resolve_asn("5.6.7.8") is None
    # A whois resolver without a cache entry AND with whois disabled -> None.
    assert viz_geo.GeoResolver(asn_whois=False).resolve_asn("9.9.9.9") is None


def test_geoip_attribution_reflects_database_and_use():
    """The GeoIP credit names the right provider and only appears once a
    database actually placed a node."""
    r = viz_geo.GeoResolver()
    assert r.attribution() is None                       # no database at all

    # DB-IP database, but nothing resolved from it yet -> no credit.
    r._db = object()
    r._db_type = "DBIP-City-Lite"
    assert r.attribution() is None

    # Once the database yields a location, the CC BY credit is required.
    r._db_used = True
    assert "DB-IP" in r.attribution()

    r._db_type = "GeoLite2-City"
    assert "MaxMind" in r.attribution()
