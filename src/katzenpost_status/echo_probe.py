# SPDX-License-Identifier: AGPL-3.0-only

"""Echo service probe for katzenpost-status.

Tests that the echo service is running and responding correctly.
Sends a test payload and verifies it is echoed back unchanged.

Possible results:
- OK: echo service responded with correct payload
- TIMEOUT: no response within timeout
- MISMATCH: response received but payload differs
- FAILURE: error occurred
"""

import asyncio
import contextlib
import io
import logging
import time

from katzenpost_thinclient import ThinClient, Config

logger = logging.getLogger(__name__)

# Result codes
RESULT_OK = "OK"
RESULT_TIMEOUT = "TIMEOUT"
RESULT_MISMATCH = "MISMATCH"
RESULT_FAILURE = "FAILURE"


async def probe_provider(
    config_path: str,
    service_desc: object,
    timeout: float = 30.0,
    debug: bool = False,
) -> tuple[str, float | None]:
    """Probe an echo provider by sending a message and verifying the response.

    Returns:
        (result_code, latency_ms) where result_code is one of:
        - RESULT_OK: echo responded correctly
        - RESULT_TIMEOUT: timed out waiting for response
        - RESULT_MISMATCH: response payload differs from sent payload
        - RESULT_FAILURE: error occurred
    """
    thinclient_logger = logging.getLogger("thinclient")
    original_level = thinclient_logger.level
    if not debug:
        thinclient_logger.setLevel(logging.WARNING)

    provider_name = service_desc.mix_descriptor.get("Name", "unknown")

    if debug:
        logger.info("[%s] echo probe: starting", provider_name)

    cfg = Config(config_path)
    client = ThinClient(cfg)
    loop = asyncio.get_event_loop()

    try:
        with contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            await asyncio.wait_for(client.start(loop), timeout=10.0)
    except asyncio.TimeoutError:
        if debug:
            logger.error("[%s] echo probe: daemon connection timeout", provider_name)
        thinclient_logger.setLevel(original_level)
        return RESULT_TIMEOUT, None
    except Exception as e:
        if debug:
            logger.error("[%s] echo probe: daemon connection failed: %s", provider_name, e)
        thinclient_logger.setLevel(original_level)
        return RESULT_FAILURE, None

    if debug:
        logger.info("[%s] echo probe: daemon connected", provider_name)

    start_time = time.monotonic()
    try:
        payload = b"echo-probe-test"
        dest_node, dest_queue = service_desc.to_destination()

        if debug:
            logger.info("[%s] echo probe: sending message", provider_name)

        try:
            with contextlib.redirect_stdout(io.StringIO()), \
                 contextlib.redirect_stderr(io.StringIO()):
                reply_payload = await asyncio.wait_for(
                    client.blocking_send_message(
                        payload, dest_node, dest_queue,
                        timeout_seconds=timeout,
                    ),
                    timeout=timeout + 5.0,
                )

            end_time = time.monotonic()
            latency_ms = (end_time - start_time) * 1000

            if debug:
                logger.info(
                    "[%s] echo probe: reply received, %d bytes, latency=%.0fms",
                    provider_name, len(reply_payload), latency_ms
                )

            reply_prefix = reply_payload[:len(payload)]

            if len(reply_prefix) == len(payload) and reply_prefix == payload:
                if debug:
                    logger.info("[%s] echo probe: SUCCESS - payload verified", provider_name)
                return RESULT_OK, latency_ms
            else:
                if debug:
                    logger.warning(
                        "[%s] echo probe: MISMATCH - expected %s, got %s",
                        provider_name, payload, reply_prefix
                    )
                return RESULT_MISMATCH, latency_ms

        except asyncio.TimeoutError:
            if debug:
                logger.warning(
                    "[%s] echo probe: TIMEOUT waiting for reply (%.0fs)",
                    provider_name, timeout
                )
            return RESULT_TIMEOUT, None

    except Exception as e:
        if debug:
            logger.error("[%s] echo probe: ERROR: %s: %s", provider_name, type(e).__name__, e)
        return RESULT_FAILURE, None

    finally:
        thinclient_logger.setLevel(original_level)
        client.stop()


async def probe_all_providers(
    config_path: str,
    client: ThinClient,
    timeout: float = 30.0,
    debug: bool = False,
) -> dict[str, tuple[str, float | None]]:
    """Probe all echo providers in parallel.

    Returns:
        dict mapping provider_name -> (result_code, latency_ms)
    """
    try:
        service_descs = client.get_services("echo")
    except Exception as e:
        if debug:
            logger.error("echo probe: failed to get echo services: %s", e)
        return {}

    if not service_descs:
        if debug:
            logger.info("echo probe: no echo services found in PKI")
        return {}

    if debug:
        logger.info("echo probe: found %d echo provider(s)", len(service_descs))

    tasks = {
        desc.mix_descriptor.get("Name", "unknown"): probe_provider(
            config_path, desc, timeout, debug
        )
        for desc in service_descs
    }

    results: dict[str, tuple[str, float | None]] = {}
    gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)

    for name, result in zip(tasks.keys(), gathered):
        if isinstance(result, BaseException):
            if debug:
                logger.error("[%s] echo probe: task exception: %s", name, result)
            results[name] = (RESULT_FAILURE, None)
        else:
            results[name] = result

    if debug:
        ok_count = sum(1 for code, _ in results.values() if code == RESULT_OK)
        logger.info(
            "echo probe: complete, %d/%d providers OK",
            ok_count, len(results)
        )

    return results
