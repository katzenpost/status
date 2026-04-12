# SPDX-License-Identifier: AGPL-3.0-only

import asyncio

import pytest

from .conftest import get_config_path, is_daemon_available, setup_thin_client

pytestmark = pytest.mark.skipif(
    not is_daemon_available(),
    reason="Katzenpost daemon not available",
)


@pytest.mark.asyncio
async def test_replica_probe_round_trip():
    from katzenpost_status.replica_probe import probe_via_courier

    client = await setup_thin_client()
    try:
        service_descs = client.get_services("courier")
        assert len(service_descs) > 0, "No courier services found in PKI"

        desc = service_descs[0]
        config_path = get_config_path()

        result_code, latency_ms = await probe_via_courier(
            config_path, desc, timeout=120.0, debug=True
        )

        assert result_code == "SUCCESS", (
            f"Replica probe failed: {result_code}"
        )
        assert latency_ms is not None
        assert latency_ms > 0
    finally:
        client.stop()


@pytest.mark.asyncio
async def test_replica_probe_all():
    from katzenpost_status.replica_probe import probe_all_replicas

    client = await setup_thin_client()
    config_path = get_config_path()
    try:
        pki = client.pki_document()
        replica_names = []
        if pki:
            storage = pki.get("StorageNodes", {})
            replica_names = list(storage.keys())

        results = await probe_all_replicas(
            config_path, client, replica_names,
            timeout=120.0, debug=True,
        )

        assert len(results) > 0, "No replica probe results"
        for name, (result_code, latency_ms) in results.items():
            print(f"  {name}: {result_code} {latency_ms}")
            assert result_code == "SUCCESS", (
                f"Replica {name} failed: {result_code}"
            )
    finally:
        client.stop()
