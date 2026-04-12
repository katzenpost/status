# SPDX-License-Identifier: AGPL-3.0-only

import asyncio

import pytest

from .conftest import get_config_path, is_daemon_available, setup_thin_client

pytestmark = pytest.mark.skipif(
    not is_daemon_available(),
    reason="Katzenpost daemon not available",
)


@pytest.mark.asyncio
async def test_echo_probe_multiple_pings():
    from katzenpost_status.echo_probe import probe_provider

    client = await setup_thin_client()
    try:
        service_descs = client.get_services("echo")
        assert len(service_descs) > 0, "No echo services found in PKI"

        desc = service_descs[0]
        config_path = get_config_path()

        result_code, latency_ms = await probe_provider(
            config_path, desc, timeout=30.0, debug=True
        )

        assert result_code == "OK", (
            f"Echo probe failed: {result_code}"
        )
        assert latency_ms is not None
        assert latency_ms > 0
    finally:
        client.stop()


@pytest.mark.asyncio
async def test_echo_probe_all_providers():
    from katzenpost_status.echo_probe import probe_all_providers

    client = await setup_thin_client()
    config_path = get_config_path()
    try:
        results = await probe_all_providers(
            config_path, client, timeout=30.0, debug=True
        )

        assert len(results) > 0, "No echo providers found"
        for name, (result_code, latency_ms) in results.items():
            print(f"  {name}: {result_code} {latency_ms}")
            assert result_code == "OK", (
                f"Provider {name} failed: {result_code}"
            )
    finally:
        client.stop()
