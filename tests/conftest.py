# SPDX-License-Identifier: AGPL-3.0-only

import asyncio
import os
import socket
from pathlib import Path

import pytest

from katzenpost_thinclient import Config, ThinClient


def get_config_path() -> str:
    possible_paths = [
        Path(__file__).parent.parent / "testdata" / "thinclient.toml",
    ]
    for path in possible_paths:
        if path.exists():
            return str(path.resolve())
    return str(possible_paths[0])


def is_daemon_available() -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        result = sock.connect_ex(("127.0.0.1", 64331))
        sock.close()
        return result == 0
    except Exception:
        return False


async def setup_thin_client() -> ThinClient:
    config_path = get_config_path()
    cfg = Config(config_path)
    client = ThinClient(cfg)
    loop = asyncio.get_running_loop()
    await client.start(loop)

    attempts = 0
    while (
        not client.is_connected() or client.pki_document() is None
    ) and attempts < 30:
        await asyncio.sleep(1)
        attempts += 1

    if not client.is_connected():
        raise Exception(
            "Daemon failed to connect to mixnet within 30 seconds"
        )
    if client.pki_document() is None:
        raise Exception("PKI document not received within 30 seconds")

    return client


@pytest.fixture(scope="session")
def config_path() -> str:
    path = get_config_path()
    if not os.path.exists(path):
        pytest.skip(f"Config file not found: {path}")
    return path


@pytest.fixture(scope="session")
def daemon_available() -> bool:
    available = is_daemon_available()
    if not available:
        pytest.skip("Katzenpost daemon not available")
    return available
