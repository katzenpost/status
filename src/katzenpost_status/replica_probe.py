# SPDX-License-Identifier: AGPL-3.0-only

"""Replica probe for katzenpost-status.

Tests courier->replica connectivity by doing a full round-trip:
1. Write test message through courier
2. Wait for courier to store in replicas
3. Read message back through courier
4. Verify we got a response

Results are returned for each courier->replica pair. Since the courier
chooses which replica to use internally, we can't test specific replicas.
The same result applies to all replicas for a given courier.

Possible results:
- SUCCESS: full round-trip worked
- ACK_ONLY: courier ACK received but no data from replica (courier->replica path broken)
- NO_REPLICAS: no storage replicas in PKI consensus, can't test
- TIMEOUT: no response from courier
- FAILURE: error occurred
"""

import asyncio
import contextlib
import io
import logging
import os
import time

from katzenpost_thinclient import ThinClient, Config

logger = logging.getLogger(__name__)

# Result codes for tracking probe state
RESULT_SUCCESS = "SUCCESS"
RESULT_ACK_ONLY = "ACK_ONLY"
RESULT_NO_REPLICAS = "NO_REPLICAS"
RESULT_TIMEOUT = "TIMEOUT"
RESULT_FAILURE = "FAILURE"


async def probe_via_courier(
    config_path: str,
    service_desc: object,
    timeout: float = 60.0,
    debug: bool = False,
) -> tuple[str, float | None]:
    """Test courier->replica path by doing full write+read round-trip.

    Returns:
        (result_code, latency_ms) where result_code is one of:
        - RESULT_SUCCESS: full round-trip verified
        - RESULT_ACK_ONLY: courier ACK but no replica data
        - RESULT_NO_REPLICAS: no storage replicas in PKI
        - RESULT_TIMEOUT: timed out waiting for response
        - RESULT_FAILURE: error occurred
    """
    thinclient_logger = logging.getLogger("thinclient")
    original_level = thinclient_logger.level
    if not debug:
        thinclient_logger.setLevel(logging.WARNING)

    provider_name = service_desc.mix_descriptor.get("Name", "unknown")

    if debug:
        logger.info("[%s] replica probe: starting round-trip test", provider_name)

    cfg = Config(config_path)
    client = ThinClient(cfg)
    loop = asyncio.get_event_loop()

    try:
        with contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            await asyncio.wait_for(client.start(loop), timeout=10.0)
    except asyncio.TimeoutError:
        if debug:
            logger.error("[%s] replica probe: daemon connection timeout", provider_name)
        thinclient_logger.setLevel(original_level)
        return RESULT_TIMEOUT, None
    except Exception as e:
        if debug:
            logger.error("[%s] replica probe: daemon connection failed: %s", provider_name, e)
        thinclient_logger.setLevel(original_level)
        return RESULT_FAILURE, None

    if debug:
        logger.info("[%s] replica probe: daemon connected", provider_name)

    start_time = time.monotonic()
    got_write_ack = False
    write_envelope_hash = None
    read_envelope_hash = None

    try:
        # --- Write phase ---
        if debug:
            logger.info("[%s] replica probe: creating keypair", provider_name)

        seed = os.urandom(32)
        kp = await client.new_keypair(seed)

        test_id = f"replica-probe-{time.time_ns()}"
        test_payload = test_id.encode("ascii")

        if debug:
            logger.info("[%s] replica probe: encrypting write", provider_name)

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
                        "[%s] replica probe: NO_REPLICAS - no storage replicas in PKI",
                        provider_name
                    )
                return RESULT_NO_REPLICAS, None
            raise

        write_envelope_hash = wcr.envelope_hash

        if debug:
            logger.info("[%s] replica probe: sending write to courier", provider_name)

        try:
            with contextlib.redirect_stdout(io.StringIO()), \
                 contextlib.redirect_stderr(io.StringIO()):
                await asyncio.wait_for(
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

            if debug:
                logger.info("[%s] replica probe: write ACK received", provider_name)
            got_write_ack = True

        except asyncio.TimeoutError:
            if debug:
                logger.warning(
                    "[%s] replica probe: TIMEOUT waiting for write ACK (%.0fs)",
                    provider_name, timeout
                )
            return RESULT_TIMEOUT, None

        await client.cancel_resending_encrypted_message(wcr.envelope_hash)
        write_envelope_hash = None

        # --- Wait for replication ---
        replication_wait = 10.0
        if debug:
            logger.info("[%s] replica probe: waiting %.0fs for replication", provider_name, replication_wait)
        await asyncio.sleep(replication_wait)

        # --- Read phase ---
        if debug:
            logger.info("[%s] replica probe: encrypting read", provider_name)

        max_read_attempts = 3
        read_timeout = timeout
        got_read_response = False

        for attempt in range(max_read_attempts):
            if debug:
                logger.info("[%s] replica probe: read attempt %d/%d", provider_name, attempt + 1, max_read_attempts)

            rcr = await client.encrypt_read(
                read_cap=kp.read_cap,
                message_box_index=kp.first_message_index,
            )
            read_envelope_hash = rcr.envelope_hash

            try:
                with contextlib.redirect_stdout(io.StringIO()), \
                     contextlib.redirect_stderr(io.StringIO()):
                    read_result = await asyncio.wait_for(
                        client.start_resending_encrypted_message(
                            read_cap=kp.read_cap,
                            write_cap=None,
                            message_box_index=kp.first_message_index,
                            reply_index=0,
                            envelope_descriptor=rcr.envelope_descriptor,
                            message_ciphertext=rcr.message_ciphertext,
                            envelope_hash=rcr.envelope_hash,
                        ),
                        timeout=read_timeout,
                    )

                await client.cancel_resending_encrypted_message(rcr.envelope_hash)
                read_envelope_hash = None

                if read_result is not None and read_result.plaintext is not None:
                    if debug:
                        logger.info("[%s] replica probe: got read response", provider_name)
                    got_read_response = True
                    break
                else:
                    if debug:
                        logger.info("[%s] replica probe: empty response, retrying", provider_name)
                    await asyncio.sleep(5.0)

            except asyncio.TimeoutError:
                if read_envelope_hash is not None:
                    try:
                        await client.cancel_resending_encrypted_message(rcr.envelope_hash)
                    except Exception:
                        pass
                    read_envelope_hash = None
                if debug:
                    logger.warning(
                        "[%s] replica probe: read timeout attempt %d/%d",
                        provider_name, attempt + 1, max_read_attempts
                    )
                continue

        end_time = time.monotonic()
        latency_ms = (end_time - start_time) * 1000

        if got_read_response:
            if debug:
                logger.info("[%s] replica probe: SUCCESS - round-trip complete", provider_name)
            return RESULT_SUCCESS, latency_ms
        elif got_write_ack:
            if debug:
                logger.warning(
                    "[%s] replica probe: ACK_ONLY - courier ACK but no replica data",
                    provider_name
                )
            return RESULT_ACK_ONLY, latency_ms
        else:
            return RESULT_TIMEOUT, None

    except Exception as e:
        if debug:
            logger.error("[%s] replica probe: ERROR: %s: %s", provider_name, type(e).__name__, e)
        if got_write_ack:
            end_time = time.monotonic()
            latency_ms = (end_time - start_time) * 1000
            return RESULT_ACK_ONLY, latency_ms
        return RESULT_FAILURE, None

    finally:
        for eh in (write_envelope_hash, read_envelope_hash):
            if eh is not None:
                try:
                    await client.cancel_resending_encrypted_message(eh)
                except Exception:
                    pass
        thinclient_logger.setLevel(original_level)
        client.stop()


async def probe_all_replicas(
    config_path: str,
    client: ThinClient,
    replica_names: list[str],
    timeout: float = 60.0,
    debug: bool = False,
) -> dict[str, tuple[str, float | None]]:
    """Probe all courier->replica paths.

    For each courier provider, tests connectivity to replicas.
    Since we can't target specific replicas, the same result applies
    to all replicas for a given courier.

    Args:
        config_path: Path to thinclient config
        client: Connected ThinClient instance
        replica_names: List of storage replica names from PKI
        timeout: Timeout for each probe
        debug: Enable debug logging

    Returns:
        dict mapping "{courier}->{replica}" -> (result_code, latency_ms)
    """
    try:
        service_descs = client.get_services("courier")
    except Exception as e:
        if debug:
            logger.error("replica probe: failed to get courier services: %s", e)
        return {}

    if not service_descs:
        if debug:
            logger.info("replica probe: no courier services found in PKI")
        return {}

    if not replica_names:
        if debug:
            logger.info("replica probe: no storage replicas in PKI")
        results: dict[str, tuple[str, float | None]] = {}
        for desc in service_descs:
            courier_name = desc.mix_descriptor.get("Name", "unknown")
            key = f"{courier_name}->replicas"
            results[key] = (RESULT_NO_REPLICAS, None)
        return results

    if debug:
        logger.info(
            "replica probe: testing %d courier(s) x %d replica(s)",
            len(service_descs), len(replica_names)
        )

    # Run probe for each courier
    courier_tasks = {
        desc.mix_descriptor.get("Name", "unknown"): probe_via_courier(
            config_path, desc, timeout, debug
        )
        for desc in service_descs
    }

    courier_results: dict[str, tuple[str, float | None]] = {}
    gathered = await asyncio.gather(*courier_tasks.values(), return_exceptions=True)

    for courier_name, result in zip(courier_tasks.keys(), gathered):
        if isinstance(result, BaseException):
            if debug:
                logger.error("[%s] replica probe: task exception: %s", courier_name, result)
            courier_results[courier_name] = (RESULT_FAILURE, None)
        else:
            courier_results[courier_name] = result
            if debug:
                result_code, latency = result
                latency_str = f"{latency:.0f}ms" if latency else "N/A"
                logger.info("[%s] replica probe: result=%s latency=%s", courier_name, result_code, latency_str)

    # Expand results to all courier->replica combinations
    results = {}
    for courier_name, probe_result in courier_results.items():
        for replica_name in replica_names:
            key = f"{courier_name}->{replica_name}"
            results[key] = probe_result

    if debug:
        success_count = sum(1 for code, _ in courier_results.values() if code == RESULT_SUCCESS)
        logger.info(
            "replica probe: complete, %d/%d couriers reached replicas",
            success_count, len(courier_results)
        )

    return results
