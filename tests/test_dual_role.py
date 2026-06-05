"""Tests for role-aware status on machines that run several roles at once.

A directory authority may also run a mix (wauland, windfall in namenlos), so
node reachability must be read per role: one role's probe must not mask
another's.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from katzenpost_status.status import (  # noqa: E402
    _role_accepts,
    get_icmp_latency_from_survey,
    role_tcp_status,
)


def _dual_role_survey():
    """wauland: dirauth port reachable, mix port unreachable."""
    return {
        "wauland|dirauth|1.1.1.1:28181": {
            "name": "wauland",
            "node_type": "dirauth",
            "tcp_traceroute": {"reachable": True, "final_latency_ms": 12.0},
            "icmp_ping": {"reachable": True, "latency_ms": 10.0},
        },
        "wauland|mix-L2|1.1.1.1:30002": {
            "name": "wauland",
            "node_type": "mix-L2",
            "tcp_traceroute": {"reachable": False},
            "icmp_ping": {"reachable": False},
        },
    }


def test_mix_role_not_masked_by_dirauth():
    survey = _dual_role_survey()
    # The name-aggregated node_status is the OLD conflated value (up).
    node_status = {"wauland": (True, 12.0)}
    assert role_tcp_status("wauland", "mix", survey, node_status) == (False, None)
    assert role_tcp_status("wauland", "dirauth", survey, node_status) == (True, 12.0)


def test_icmp_latency_is_role_scoped():
    survey = _dual_role_survey()
    assert get_icmp_latency_from_survey("wauland", survey, "mix") is None
    assert get_icmp_latency_from_survey("wauland", survey, "dirauth") == 10.0
    # No category -> aggregate across roles (backwards compatible).
    assert get_icmp_latency_from_survey("wauland", survey, None) == 10.0


def test_mix_category_matches_layer_types():
    accept = _role_accepts("mix")
    assert accept("mix")
    assert accept("mix-L0")
    assert accept("mix-L2")
    assert not accept("dirauth")
    assert not accept("gateway")


def test_role_falls_back_to_node_status_when_role_not_surveyed():
    # A pure mix with no survey entry should fall back to node_status by name.
    node_status = {"cryptonymity": (True, 8.0)}
    assert role_tcp_status("cryptonymity", "mix", {}, node_status) == (True, 8.0)
    assert role_tcp_status("cryptonymity", "mix", None, node_status) == (True, 8.0)
    # Unknown node, no data anywhere.
    assert role_tcp_status("nobody", "mix", {}, {}) == (False, None)
