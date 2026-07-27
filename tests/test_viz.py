"""Tests for the visualization payload and multi-file rendering.

Everything is driven by a real namenlos consensus snapshot captured from a live
run (``testdata/consensus_namenlos.json``) - real node names, real service
capabilities, real topology and parameters. Survey reachability is layered on
top of those real names to exercise the status logic.
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from katzenpost_status import viz, viz_geo  # noqa: E402

_SNAPSHOT = json.loads(
    (
        Path(__file__).resolve().parents[1]
        / "testdata"
        / "consensus_namenlos.json"
    ).read_text()
)
DOC = _SNAPSHOT["doc"]
DIRAUTH_STATUS = {name: (True, 5.0) for name in _SNAPSHOT["dirauths"]}


def _tr(reachable, latency, nhops):
    return {
        "reachable": reachable,
        "final_latency_ms": latency,
        "hops": [
            {
                "hop": i + 1,
                "ip": f"10.0.{i}.{i}",
                "latency_ms": round((i + 1) * latency / nhops, 1),
            }
            for i in range(nhops)
        ]
        if reachable
        else [],
    }


def _survey_entry(
    name,
    node_type,
    reachable=True,
    latency=15.0,
    nhops=6,
    host="198.51.100.1",
    port=1,
):
    return {
        f"{name}|{node_type}|{host}:{port}": {
            "name": name,
            "node_type": node_type,
            "host": host,
            "port": port,
            "tcp_traceroute": _tr(reachable, latency, nhops),
            "icmp_ping": {
                "reachable": reachable,
                "latency_ms": latency - 2 if reachable else None,
            },
        }
    }


def _full_survey():
    survey = {}
    survey.update(_survey_entry("windfallgw", "gateway", nhops=25))
    for i, layer in enumerate(DOC["Topology"]):
        for node in layer:
            survey.update(
                _survey_entry(node["Name"], f"mix-L{i}", nhops=8 + i)
            )
    return survey


def _payload(survey_results=None, dirauth_status=None):
    return viz.build_viz_payload(
        DOC,
        survey_results=survey_results,
        dirauth_status=dirauth_status
        if dirauth_status is not None
        else DIRAUTH_STATUS,
        network_name="namenlos",
        epoch=DOC["Epoch"],
        epoch_time_str=_SNAPSHOT["captured_epoch_time"],
        generated_at="2026-09-01T00:00:00Z",
    )


def _index(nodes):
    return {(n["name"], n["type"]): n for n in nodes}


def test_layers_match_real_topology():
    p = _payload()
    expected = [[n["Name"] for n in layer] for layer in DOC["Topology"]]
    assert p["layers"] == expected
    assert p["counts"]["layers"] == len(expected)


def test_dual_role_machines_not_conflated():
    idx = _index(_payload()["nodes"])
    assert ("windfall", "dirauth") in idx and ("windfall", "mix") in idx
    assert ("gnunet", "dirauth") in idx and ("gnunet", "gateway") in idx
    assert ("annares", "dirauth") in idx and ("annares", "service") in idx


def test_service_capabilities_from_consensus():
    # The "kind of service" (Kaetzchen) must reach the node's details.
    svc = _index(_payload()["nodes"])[("annares", "service")]
    assert svc["details"]["capabilities"] == ["courier", "echo"]


def test_node_details_include_addresses_and_keys():
    svc = _index(_payload()["nodes"])[("annares", "service")]
    det = svc["details"]
    assert any(a.startswith("tcp://") for a in det["addresses"])
    assert det.get("mixkey_epochs")  # real key epochs captured
    # storagereplica0 carries a replica id in the consensus
    rep = _index(_payload()["nodes"])[("storagereplica0", "storage")]
    assert rep["details"].get("replica_id") is not None


def test_network_consensus_fields_present():
    cs = _payload()["consensus"]
    assert cs["epoch"] == DOC["Epoch"]
    assert "version" in cs and "pki_signature_scheme" in cs


def test_vantage_and_client_count_in_payload():
    p = viz.build_viz_payload(
        DOC,
        dirauth_status=DIRAUTH_STATUS,
        network_name="namenlos",
        vantage={"lat": 52.0, "lon": 5.0, "label": "monitor"},
        clients_per_gateway=4,
    )
    assert p["vantage"] == {"lat": 52.0, "lon": 5.0, "label": "monitor"}
    assert p["clients_per_gateway"] == 4


def test_node_geo_from_curated_resolver():
    # annares (service) has address tcp://192.87.90.45:... in the fixture.
    r = viz_geo.GeoResolver(
        overrides={"192.87.90.45": [51.44, 5.48, "Eindhoven"]}
    )
    idx = _index(
        viz.build_viz_payload(
            DOC,
            dirauth_status=DIRAUTH_STATUS,
            network_name="namenlos",
            geo_resolver=r,
        )["nodes"]
    )
    geo = idx[("annares", "service")].get("geo")
    assert geo and geo["lat"] == 51.44 and geo["source"] == "curated"


def test_real_parameters_extracted():
    params = _payload()["parameters"]
    assert params["Mu"] == DOC["Parameters"]["Mu"]
    assert params["LambdaP"] == DOC["Parameters"]["LambdaP"]
    assert params["LambdaD"] is None  # absent in this consensus
    assert set(params) == set(viz.TRAFFIC_PARAM_NAMES)


def test_fingerprint_is_stable_hex():
    fp = viz._fingerprint(b"some-key-bytes")
    assert (
        isinstance(fp, str)
        and len(fp) == 64
        and all(c in "0123456789abcdef" for c in fp)
    )
    assert viz._fingerprint("not-bytes") is None


def test_dirauth_status_drives_color():
    das = dict(DIRAUTH_STATUS)
    das["respectmy"] = (False, None)
    idx = _index(_payload(dirauth_status=das)["nodes"])
    assert idx[("gnunet", "dirauth")]["status"] == "ok"
    assert idx[("respectmy", "dirauth")]["status"] == "down"
    assert idx[("respectmy", "dirauth")]["color"] == viz.STATUS_COLORS["down"]


def test_in_consensus_node_is_ok_and_carries_path():
    survey = _survey_entry(
        "windfallgw", "gateway", reachable=True, latency=12.3, nhops=25
    )
    gw = _index(_payload(survey_results=survey)["nodes"])[
        ("windfallgw", "gateway")
    ]
    assert (
        gw["status"] == "ok"
        and gw["reachable"]
        and gw["hop_count"] == 25
        and gw["latency_ms"] == 12.3
    )


def test_dropped_reachable_node_is_out_with_address():
    survey = _survey_entry(
        "mixy",
        "mix-L1",
        reachable=True,
        latency=30.0,
        nhops=9,
        host="203.0.113.9",
    )
    doc = json.loads(json.dumps(DOC))
    doc["Topology"][1] = [
        n for n in doc["Topology"][1] if n["Name"] != "mixy"
    ]
    idx = _index(
        viz.build_viz_payload(
            doc, survey_results=survey, dirauth_status=DIRAUTH_STATUS
        )["nodes"]
    )
    assert ("mixy", "out") in idx
    out = idx[("mixy", "out")]
    assert out["status"] == "out" and out["details"]["addresses"] == [
        "tcp://203.0.113.9:1"
    ]


# ---- multi-file rendering ------------------------------------------------


def _generate(tmp_path, **kw):
    out = tmp_path / "visualize.html"
    viz.generate_viz(
        DOC,
        str(out),
        survey_results=_full_survey(),
        dirauth_status=DIRAUTH_STATUS,
        network_name="namenlos",
        epoch=DOC["Epoch"],
        epoch_time_str=_SNAPSHOT["captured_epoch_time"],
        **kw,
    )
    return out


def test_generate_viz_writes_multifile_layout(tmp_path):
    out = _generate(tmp_path)
    data_json = tmp_path / "visualize.data.json"
    assets = tmp_path / viz.ASSETS_SUBDIR
    assert out.exists() and data_json.exists() and assets.is_dir()
    # All static assets present.
    for fname in viz.VENDOR_SCRIPTS:
        assert (assets / fname).exists()
    assert (assets / viz.APP_JS_NAME).exists()


def test_shell_references_only_local_paths(tmp_path):
    html = _generate(tmp_path).read_text()
    assert not re.search(r'(?:src|href)\s*=\s*["\']https?://', html)
    assert f"{viz.ASSETS_SUBDIR}/three.min.js" in html
    assert "visualize.data.json" in html
    assert "window.KATZEN_POLL_SECONDS" in html


def test_data_file_is_plain_parseable_json(tmp_path):
    _generate(tmp_path)
    # The data file is pure JSON (not JS), so it parses directly.
    data = json.loads((tmp_path / "visualize.data.json").read_text())
    assert data["network_name"] == "namenlos"
    names = {n["name"] for n in data["nodes"]}
    assert {"windfall", "mixy", "annares", "storagereplica0"} <= names


def test_only_data_file_changes_across_runs(tmp_path):
    # The core requirement: a cron run rewrites only the data file; the static
    # JS assets keep their mtime so the browser never re-downloads them.
    _generate(tmp_path, poll_seconds=60)
    three = tmp_path / viz.ASSETS_SUBDIR / "three.min.js"
    app = tmp_path / viz.ASSETS_SUBDIR / viz.APP_JS_NAME
    three_mtime, app_mtime = three.stat().st_mtime_ns, app.stat().st_mtime_ns
    # Second run with fresh data (different generated_at).
    viz.generate_viz(
        DOC,
        str(tmp_path / "visualize.html"),
        survey_results=_full_survey(),
        dirauth_status=DIRAUTH_STATUS,
        network_name="namenlos",
        epoch=DOC["Epoch"],
        epoch_time_str=_SNAPSHOT["captured_epoch_time"],
    )
    assert three.stat().st_mtime_ns == three_mtime  # not rewritten
    assert app.stat().st_mtime_ns == app_mtime  # not rewritten


def test_write_if_changed(tmp_path):
    p = tmp_path / "f.txt"
    assert viz._write_if_changed(p, "a") is True
    assert viz._write_if_changed(p, "a") is False  # unchanged -> skipped
    assert viz._write_if_changed(p, "b") is True


class _StubResolver:
    """Resolver stub: pretends a geo + ASN database is present."""

    def resolve(self, ip, name=None):
        return (
            {
                "lat": 1.0,
                "lon": 2.0,
                "label": "Testville, Testland",
                "source": "stub",
            }
            if ip
            else None
        )

    def resolve_asn(self, ip):
        return {"asn": "AS64500", "org": "Test Net"} if ip else None

    def attribution(self):
        return None


def test_epoch_timing_fields_in_payload():
    p = viz.build_viz_payload(
        DOC,
        survey_results=_full_survey(),
        dirauth_status=DIRAUTH_STATUS,
        epoch=DOC["Epoch"],
        epoch_end="2026-09-02T00:20:00Z",
        epoch_period_s=1200.0,
    )
    assert p["epoch_end"] == "2026-09-02T00:20:00Z"
    assert p["epoch_period_s"] == 1200.0


def test_node_asn_present_when_resolver_has_asn():
    p = viz.build_viz_payload(
        DOC,
        survey_results=_full_survey(),
        dirauth_status=DIRAUTH_STATUS,
        geo_resolver=_StubResolver(),
    )
    with_asn = [n for n in p["nodes"] if n.get("asn")]
    assert with_asn, (
        "at least one node should carry an AS when the resolver has one"
    )
    assert with_asn[0]["asn"] == "AS64500"
    assert with_asn[0]["net"] == "Test Net"


def _hpayload(epoch, gen):
    return {
        "epoch": epoch,
        "generated_at": gen,
        "epoch_time_str": "t",
        "counts": {"total": 1},
        "nodes": [{"name": "a", "type": "mix", "status": "ok"}],
    }


def test_history_writer_dedupes_and_prunes(tmp_path):
    for e in (1, 2, 3):
        viz._write_history(
            tmp_path,
            "visualize",
            _hpayload(e, f"g{e}"),
            json.dumps(_hpayload(e, f"g{e}")),
            history_len=2,
        )
    hist = tmp_path / "visualize-history"
    index = json.loads((hist / "index.json").read_text())
    assert [x["epoch"] for x in index] == [
        2,
        3,
    ]  # pruned to the last 2 epochs
    assert not (hist / "1.json").exists()  # stale snapshot file removed
    assert (hist / "2.json").exists() and (hist / "3.json").exists()

    # Re-writing an existing epoch replaces its entry (dedupe), not appends.
    viz._write_history(
        tmp_path,
        "visualize",
        _hpayload(3, "g3b"),
        json.dumps(_hpayload(3, "g3b")),
        history_len=2,
    )
    index = json.loads((hist / "index.json").read_text())
    assert sum(1 for x in index if x["epoch"] == 3) == 1
    assert index[-1]["generated_at"] == "g3b"


def test_history_writer_disabled(tmp_path):
    viz._write_history(tmp_path, "vv", _hpayload(1, "x"), "{}", history_len=0)
    assert not (tmp_path / "vv-history").exists()


def test_generate_viz_write_history_false_skips_history_dir(tmp_path):
    # The intermediate staged write must not touch the scrubber history.
    _generate(tmp_path, write_history=False)
    assert (tmp_path / "visualize.data.json").exists()
    assert not (tmp_path / "visualize-history").exists()


def test_staged_writes_end_with_full_snapshot_in_history(tmp_path):
    # Mirror the staged flow: an intermediate write (write_history=False) for an
    # epoch followed by the final write (write_history=True). The scrubber
    # history must hold exactly the final snapshot for that epoch.
    _generate(tmp_path, write_history=False)
    _generate(tmp_path, write_history=True)
    hist = tmp_path / "visualize-history"
    assert hist.is_dir()
    index = json.loads((hist / "index.json").read_text())
    epoch = DOC["Epoch"]
    matching = [e for e in index if e["epoch"] == epoch]
    assert len(matching) == 1
    assert (hist / matching[0]["file"]).exists()
