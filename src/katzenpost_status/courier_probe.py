# SPDX-License-Identifier: AGPL-3.0-only

"""Courier service probe for katzenpost-status.

Tests that the courier service is running and responding to queries.
Getting an ACK back (empty plaintext) means the courier is alive.

This does NOT test courier->replica connectivity. Use replica_probe for that.

Note: Testing the courier requires preparing a valid pigeonhole message, which
requires storage replicas to be present in the PKI consensus. If no replicas
are available, the probe will return NO_REPLICAS.
"""

import asyncio
import contextlib
import io
import logging
import os
import time

from katzenpost_thinclient import ThinClient, Config

logger = logging.getLogger(__name__)

# Result codes
RESULT_OK = "OK"
RESULT_NO_REPLICAS = "NO_REPLICAS"
RESULT_TIMEOUT = "TIMEOUT"
RESULT_FAILURE = "FAILURE"


async def probe_provider(
    config_path: str,
    service_desc: object,
    timeout: float = 30.0,
    debug: bool = False,
) -> tuple[str, float | None]:
    """Probe a courier provider by sending a query and verifying ACK response.

    Returns:
        (result_code, latency_ms) where result_code is one of:
        - RESULT_OK: courier responded with ACK
        - RESULT_NO_REPLICAS: no storage replicas in PKI, can't test
        - RESULT_TIMEOUT: timed out waiting for response
        - RESULT_FAILURE: error occurred
    """
    thinclient_logger = logging.getLogger("thinclient")
    original_level = thinclient_logger.level
    if not debug:
        thinclient_logger.setLevel(logging.WARNING)

    provider_name = service_desc.mix_descriptor.get("Name", "unknown")

    if debug:
        logger.info("[%s] courier probe: starting", provider_name)

    cfg = Config(config_path)
    client = ThinClient(cfg)
    loop = asyncio.get_event_loop()

    try:
        with contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            await asyncio.wait_for(client.start(loop), timeout=10.0)
    except asyncio.TimeoutError:
        if debug:
            logger.error("[%s] courier probe: daemon connection timeout", provider_name)
        thinclient_logger.setLevel(original_level)
        return RESULT_TIMEOUT, None
    except Exception as e:
        if debug:
            logger.error("[%s] courier probe: daemon connection failed: %s", provider_name, e)
        thinclient_logger.setLevel(original_level)
        return RESULT_FAILURE, None

    if debug:
        logger.info("[%s] courier probe: daemon connected", provider_name)

    start_time = time.monotonic()
    envelope_hash = None
    try:
        if debug:
            logger.info("[%s] courier probe: creating keypair", provider_name)

        seed = os.urandom(32)
        kp = await client.new_keypair(seed)

        test_payload = ("probe-" + str(time.time_ns())).encode("ascii")

        if debug:
            logger.info("[%s] courier probe: encrypting write", provider_name)

        try:
            wcr = await client.encrypt_write(
                plaintext=test_payload,
                write_cap=kp.write_cap,
                message_box_index=kp.first_message_index,
            )
        except Exception as e:
            error_msg = str(e)
            if "error code: 4" in error_msg:
                if debug:
                    logger.warning(
                        "[%s] courier probe: NO_REPLICAS - no storage replicas in PKI",
                        provider_name
                    )
                return RESULT_NO_REPLICAS, None
            else:
                if debug:
                    logger.error("[%s] courier probe: encrypt_write failed: %s", provider_name, e)
                raise

        envelope_hash = wcr.envelope_hash

        if debug:
            logger.info("[%s] courier probe: sending to courier via ARQ", provider_name)

        try:
            with contextlib.redirect_stdout(io.StringIO()), \
                 contextlib.redirect_stderr(io.StringIO()):
                result = await asyncio.wait_for(
                    client.start_resending_encrypted_message(
                        read_cap=None,
                        write_cap=kp.write_cap,
                        message_box_index=None,
                        reply_index=None,
                        envelope_descriptor=wcr.envelope_descriptor,
                        message_ciphertext=wcr.message_ciphertext,
                        envelope_hash=wcr.envelope_hash,
                    ),
                    timeout=timeout,
                )

            end_time = time.monotonic()
            latency_ms = (end_time - start_time) * 1000

            if debug:
                logger.info(
                    "[%s] courier probe: ACK received, %.0fms",
                    provider_name, latency_ms
                )

            await client.cancel_resending_encrypted_message(wcr.envelope_hash)
            envelope_hash = None

            if debug:
                logger.info("[%s] courier probe: SUCCESS", provider_name)

            return RESULT_OK, latency_ms

        except asyncio.TimeoutError:
            if debug:
                logger.warning(
                    "[%s] courier probe: TIMEOUT waiting for ACK (%.0fs)",
                    provider_name, timeout
                )
            return RESULT_TIMEOUT, None

    except Exception as e:
        if debug:
            logger.error("[%s] courier probe: ERROR: %s: %s", provider_name, type(e).__name__, e)
        return RESULT_FAILURE, None

    finally:
        if envelope_hash is not None:
            try:
                await client.cancel_resending_encrypted_message(envelope_hash)
            except Exception:
                pass
        thinclient_logger.setLevel(original_level)
        client.stop()


async def probe_all_providers(
    config_path: str,
    client: ThinClient,
    timeout: float = 30.0,
    debug: bool = False,
) -> dict[str, tuple[str, float | None]]:
    """Probe all courier providers in parallel.

    Returns:
        dict mapping provider_name -> (result_code, latency_ms)
    """
    try:
        service_descs = client.get_services("courier")
    except Exception as e:
        if debug:
            logger.error("courier probe: failed to get courier services: %s", e)
        return {}

    if not service_descs:
        if debug:
            logger.info("courier probe: no courier services found in PKI")
        return {}

    if debug:
        logger.info("courier probe: found %d courier provider(s)", len(service_descs))

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
                logger.error("[%s] courier probe: task exception: %s", name, result)
            results[name] = (RESULT_FAILURE, None)
        else:
            results[name] = result

    if debug:
        ok_count = sum(1 for code, _ in results.values() if code == RESULT_OK)
        logger.info(
            "courier probe: complete, %d/%d providers OK",
            ok_count, len(results)
        )

    return results
