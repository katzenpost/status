# SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

import asyncio
import contextlib
import io
import json
import logging
import os
import subprocess
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

import cbor2
import click
import tomli
from katzenpost_thinclient import ThinClient, Config
from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.terminal_theme import MONOKAI
from rich.text import Text

from . import __version__

EPOCH = datetime(2017, 6, 1)
PERIOD = timedelta(minutes=20)

SurveyTarget = tuple[str, str, str, int]
ServiceProbeResults = dict[str, dict[str, tuple[bool, float | None]]]


def format_host_port(host: str, port: int) -> str:
    """Format host:port for display, handling IPv6 addresses correctly."""
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


class ConnectionStatus:

    def __init__(self) -> None:
        self.daemon_connected: bool = False
        self.network_online: bool = False
        self.error_message: str | None = None

    @property
    def fully_connected(self) -> bool:
        return self.daemon_connected and self.network_online


async def probe_tcp(
    host: str,
    port: int,
    timeout: float = 5.0,
) -> tuple[bool, float | None]:
    start_time = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        end_time = time.monotonic()
        latency_ms = (end_time - start_time) * 1000
        return True, latency_ms
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
        return False, None


async def probe_dirauths(
    dirauth_addresses: dict[str, list[tuple[str, int]]],
    timeout: float = 5.0,
) -> dict[str, tuple[bool, float | None]]:
    # Flatten to list of (name, host, port) for probing
    probe_list: list[tuple[str, str, int]] = []
    for name, addrs in dirauth_addresses.items():
        for host, port in addrs:
            probe_list.append((name, host, port))

    tasks = [probe_tcp(host, port, timeout) for name, host, port in probe_list]
    results_list = await asyncio.gather(*tasks)

    # Aggregate by name: if any address succeeds, node is up (use best latency)
    results: dict[str, tuple[bool, float | None]] = {}
    for (name, host, port), (ok, latency) in zip(probe_list, results_list):
        if name not in results:
            results[name] = (ok, latency)
        elif ok and not results[name][0]:
            # New success replaces previous failure
            results[name] = (ok, latency)
        elif ok and results[name][0]:
            # Both successful, compare latencies (prefer lower)
            existing_latency = results[name][1]
            if latency is not None and (existing_latency is None or latency < existing_latency):
                results[name] = (ok, latency)
    return results


async def probe_all_nodes(
    node_addresses: dict[str, list[tuple[str, int]]],
    timeout: float = 5.0,
) -> dict[str, tuple[bool, float | None]]:
    # Flatten to list of (name, host, port) for probing
    probe_list: list[tuple[str, str, int]] = []
    for name, addrs in node_addresses.items():
        for host, port in addrs:
            probe_list.append((name, host, port))

    tasks = [probe_tcp(host, port, timeout) for name, host, port in probe_list]
    results_list = await asyncio.gather(*tasks)

    # Aggregate by name: if any address succeeds, node is up (use best latency)
    results: dict[str, tuple[bool, float | None]] = {}
    for (name, host, port), (ok, latency) in zip(probe_list, results_list):
        if name not in results:
            results[name] = (ok, latency)
        elif ok and not results[name][0]:
            # New success replaces previous failure
            results[name] = (ok, latency)
        elif ok and results[name][0]:
            # Both successful, compare latencies (prefer lower)
            existing_latency = results[name][1]
            if latency is not None and (existing_latency is None or latency < existing_latency):
                results[name] = (ok, latency)
    return results


def get_cache_path(custom_path: str | None = None) -> Path:
    if custom_path:
        return Path(custom_path)
    cache_dir = Path.home() / ".cache" / "katzenpost-status"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / "address_cache.json"


def load_typed_address_cache(
    cache_path: Path | None = None,
    verbose: bool = False,
) -> list[SurveyTarget]:
    if cache_path is None:
        cache_path = get_cache_path()
    if cache_path.exists():
        try:
            with open(cache_path, "r") as f:
                data = json.load(f)
                targets: list[SurveyTarget] = []

                # New format: dict with "name|type" keys and [[host, port], ...] values
                if isinstance(data, dict):
                    for key, addrs in data.items():
                        if "|" in key and isinstance(addrs, list):
                            name, node_type = key.split("|", 1)
                            for addr in addrs:
                                if isinstance(addr, (list, tuple)) and len(addr) == 2:
                                    targets.append((name, node_type, str(addr[0]), int(addr[1])))
                    return targets

                # Old format: list of [name, type, host, port]
                if isinstance(data, list) and len(data) > 0:
                    first = data[0]
                    if isinstance(first, (list, tuple)) and len(first) == 4:
                        return [
                            (str(item[0]), str(item[1]), str(item[2]), int(item[3]))
                            for item in data
                            if isinstance(item, (list, tuple)) and len(item) == 4
                        ]
                if verbose:
                    click.echo(f"Unknown cache format, clearing: {data}")
                cache_path.unlink()
        except (json.JSONDecodeError, IOError, ValueError, TypeError) as e:
            if verbose:
                click.echo(f"Cache error ({e}), clearing cache")
            try:
                cache_path.unlink()
            except OSError:
                pass
    return []


def save_typed_address_cache(
    targets: list[SurveyTarget],
    cache_path: Path | None = None,
) -> None:
    if cache_path is None:
        cache_path = get_cache_path()
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    existing = load_typed_address_cache(cache_path)

    # Merge addresses by (name, type), storing set of (host, port) tuples
    by_key: dict[str, set[tuple[str, int]]] = {}

    def add_entry(name: str, node_type: str, host: str, port: int) -> None:
        if not host or port == 0:
            return
        key = f"{name}|{node_type}"
        if key not in by_key:
            by_key[key] = set()
        by_key[key].add((host, port))

    for t in existing:
        add_entry(t[0], t[1], t[2], t[3])

    for t in targets:
        add_entry(t[0], t[1], t[2], t[3])

    # Convert to serializable format
    cache_data = {key: sorted(list(addrs)) for key, addrs in by_key.items()}

    with open(cache_path, "w") as f:
        json.dump(cache_data, f, indent=2)


def get_consensus_cache_path(cache_path: Path | None = None) -> Path:
    if cache_path:
        return cache_path.parent / "last_consensus.json"
    cache_dir = Path.home() / ".cache" / "katzenpost-status"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / "last_consensus.json"


def load_last_consensus(
    cache_path: Path | None = None,
) -> dict[str, Any] | None:
    consensus_path = get_consensus_cache_path(cache_path)
    if consensus_path.exists():
        try:
            with open(consensus_path, "r") as f:
                data: dict[str, Any] = json.load(f)
                return data
        except (json.JSONDecodeError, IOError):
            pass
    return None


def save_last_consensus(
    epoch: int,
    epoch_time_str: str,
    cache_path: Path | None = None,
) -> None:
    consensus_path = get_consensus_cache_path(cache_path)
    consensus_path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "epoch": epoch,
        "epoch_time_str": epoch_time_str,
        "saved_at": datetime.utcnow().isoformat() + "Z",
    }
    with open(consensus_path, "w") as f:
        json.dump(data, f, indent=2)


def run_icmp_ping(host: str, count: int = 3, timeout: int = 2) -> dict[str, Any]:
    result: dict[str, Any] = {
        "host": host,
        "reachable": False,
        "latency_ms": None,
        "packet_loss": 100.0,
        "error": None,
    }
    try:
        proc = subprocess.run(
            ["ping", "-c", str(count), "-W", str(timeout), host],
            capture_output=True,
            text=True,
            timeout=count * timeout + 5,
        )
        if proc.returncode == 0:
            result["reachable"] = True
            for line in proc.stdout.splitlines():
                if "min/avg/max" in line:
                    parts = line.split("=")
                    if len(parts) >= 2:
                        times = parts[1].strip().split("/")
                        if len(times) >= 2:
                            result["latency_ms"] = float(times[1])
                if "packet loss" in line:
                    for part in line.split(","):
                        if "packet loss" in part:
                            pct = part.strip().split("%")[0].split()[-1]
                            result["packet_loss"] = float(pct)
    except subprocess.TimeoutExpired:
        result["error"] = "timeout"
    except FileNotFoundError:
        result["error"] = "ping not found"
    except Exception as e:
        result["error"] = str(e)
    return result


def run_tcp_traceroute(
    host: str,
    port: int,
    max_hops: int = 30,
    timeout: int = 2,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "reachable": False,
        "hops": [],
        "final_latency_ms": None,
        "error": None,
    }

    # Detect IPv6 address
    is_ipv6 = ":" in host

    if is_ipv6:
        # For IPv6, try tcptraceroute6 first, fall back to simple TCP connect
        return _run_ipv6_tcp_probe(host, port, max_hops, timeout)

    # IPv4: use standard tcptraceroute
    try:
        cmd = [
            "tcptraceroute",
            "-w", str(timeout),
            "-n",
            "-m", str(max_hops),
            host,
            str(port),
        ]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max_hops * timeout + 10,
        )
        _parse_tcptraceroute_output(proc.stdout, result)

        # If no hops found and stderr has content, record the error
        if not result["hops"] and proc.stderr.strip():
            result["error"] = proc.stderr.strip()[:100]
    except subprocess.TimeoutExpired:
        result["error"] = "timeout"
    except FileNotFoundError:
        result["error"] = "tcptraceroute not found"
    except Exception as e:
        result["error"] = str(e)
    return result


def _run_ipv6_tcp_probe(
    host: str,
    port: int,
    max_hops: int = 30,
    timeout: int = 2,
) -> dict[str, Any]:
    """Probe IPv6 TCP port - try tcptraceroute6, verify with simple connect."""
    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "reachable": False,
        "hops": [],
        "final_latency_ms": None,
        "error": None,
    }

    traceroute_worked = False

    # Try tcptraceroute6 first (from ndisc6 package)
    try:
        cmd = [
            "tcptraceroute6",
            "-n",
            "-w", str(timeout),
            "-m", str(max_hops),
            host,
            str(port),
        ]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max_hops * timeout + 10,
        )
        _parse_tcptraceroute6_output(proc.stdout, result)
        traceroute_worked = True
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        result["error"] = "timeout"
    except Exception:
        pass

    # If tcptraceroute6 didn't confirm reachability, try simple TCP connect
    # This handles cases where intermediate hops don't respond but port is open
    if not result["reachable"]:
        # Use longer timeout for socket connect (5s) since remote IPv6 may have higher latency
        connect_result = _simple_tcp_connect(host, port, timeout=5)
        if connect_result["reachable"]:
            result["reachable"] = True
            result["final_latency_ms"] = connect_result["final_latency_ms"]
            result["error"] = None
            # If we have traceroute hops but socket succeeded, add destination as final hop
            if result["hops"]:
                # Check if last hop is already the destination
                last_hop = result["hops"][-1] if result["hops"] else None
                if not last_hop or last_hop.get("ip") != host:
                    # Add destination as final reachable hop
                    next_hop_num = len(result["hops"]) + 1
                    result["hops"].append({
                        "hop": next_hop_num,
                        "ip": host,
                        "latency_ms": connect_result["final_latency_ms"]
                    })
            else:
                # No traceroute hops, use the connect result's single hop
                result["hops"] = connect_result["hops"]
        else:
            # Preserve the error from the simple connect attempt
            err = connect_result.get("error", "unknown")
            result["error"] = f"socket: {err}"

    # If no traceroute data at all, fall back entirely to simple connect
    if not traceroute_worked and not result["hops"]:
        return _simple_tcp_connect(host, port, timeout=5)

    return result


def _simple_tcp_connect(
    host: str,
    port: int,
    timeout: int = 5,
) -> dict[str, Any]:
    """Simple TCP connect test without traceroute."""
    import socket

    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "reachable": False,
        "hops": [],
        "final_latency_ms": None,
        "error": None,
    }

    try:
        start = time.monotonic()
        # Determine address family
        is_ipv6 = ":" in host
        family = socket.AF_INET6 if is_ipv6 else socket.AF_INET

        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        end = time.monotonic()
        sock.close()

        result["reachable"] = True
        result["final_latency_ms"] = (end - start) * 1000
        # Add a single "hop" showing the destination
        result["hops"] = [{"hop": 1, "ip": host, "latency_ms": result["final_latency_ms"]}]
    except socket.timeout:
        result["error"] = "timeout"
    except ConnectionRefusedError:
        result["error"] = "connection refused"
    except OSError as e:
        result["error"] = str(e)[:50]

    return result


def _parse_tcptraceroute_output(stdout: str, result: dict[str, Any]) -> None:
    """Parse output from tcptraceroute (IPv4)."""
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("Selected") or line.startswith("Tracing"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            hop_num = parts[0]
            if hop_num.isdigit():
                hop_info: dict[str, Any] = {"hop": int(hop_num)}
                if parts[1] == "*":
                    hop_info["ip"] = None
                    hop_info["latency_ms"] = None
                else:
                    hop_info["ip"] = parts[1]
                    latencies = []
                    for p in parts[2:]:
                        if p == "ms":
                            continue
                        if p == "*":
                            continue
                        if p.startswith("["):
                            if "open" in p:
                                result["reachable"] = True
                            continue
                        try:
                            latencies.append(float(p))
                        except ValueError:
                            pass
                    if latencies:
                        hop_info["latency_ms"] = sum(latencies) / len(latencies)
                    else:
                        hop_info["latency_ms"] = None
                result["hops"].append(hop_info)
                if result["reachable"] and hop_info.get("latency_ms"):
                    result["final_latency_ms"] = hop_info["latency_ms"]


def _parse_tcptraceroute6_output(stdout: str, result: dict[str, Any]) -> None:
    """Parse output from tcptraceroute6 (from ndisc6 package)."""
    # Format: " 1  2a02:898:246:64::1 (2a02:898:246:64::1)  0.440 ms  * *"
    # Or: " 24  * * 2a01:4f9:3100:4b60:1010::1 (...)  28.469 ms [open]"
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("traceroute"):
            continue

        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit():
            hop_num = int(parts[0])
            hop_info: dict[str, Any] = {"hop": hop_num, "ip": None, "latency_ms": None}

            # Find IP address (not * and not in parentheses)
            for i, p in enumerate(parts[1:], 1):
                if p == "*":
                    continue
                if p.startswith("(") or p == "ms":
                    continue
                if "[open]" in p:
                    result["reachable"] = True
                    continue
                # Check if it looks like an IPv6 address
                if ":" in p or "." in p:
                    hop_info["ip"] = p
                    break

            # Find latency (number followed by ms)
            latencies = []
            for i, p in enumerate(parts):
                if p == "ms" and i > 0:
                    try:
                        latencies.append(float(parts[i - 1]))
                    except ValueError:
                        pass

            if latencies:
                hop_info["latency_ms"] = sum(latencies) / len(latencies)

            # Check for [open] marker
            if "[open]" in line:
                result["reachable"] = True

            result["hops"].append(hop_info)
            if result["reachable"] and hop_info.get("latency_ms"):
                result["final_latency_ms"] = hop_info["latency_ms"]


def _survey_single_target(
    target: SurveyTarget,
    run_traceroute: bool = True,
) -> tuple[str, dict[str, Any]]:
    name, node_type, host, port = target
    # Include host:port in key to allow multiple addresses per node
    key = f"{name}|{node_type}|{host}:{port}"
    node_result: dict[str, Any] = {
        "name": name,
        "node_type": node_type,
        "host": host if host else "unknown",
        "port": port,
    }
    if host:
        node_result["icmp_ping"] = run_icmp_ping(host)
        if run_traceroute:
            node_result["tcp_traceroute"] = run_tcp_traceroute(host, port)
    else:
        node_result["icmp_ping"] = {
            "host": "unknown",
            "reachable": False,
            "latency_ms": None,
            "packet_loss": 100.0,
            "error": "address unknown",
        }
        node_result["tcp_traceroute"] = {
            "host": "unknown",
            "port": port,
            "reachable": False,
            "hops": [],
            "final_latency_ms": None,
            "error": "address unknown",
        }
    return key, node_result


def run_survey_parallel(
    targets: list[SurveyTarget],
    run_traceroute: bool = True,
    verbose: bool = False,
    max_workers: int = 10,
) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}

    if not targets:
        return results

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_target = {
            executor.submit(_survey_single_target, target, run_traceroute): target
            for target in targets
        }

        for future in as_completed(future_to_target):
            target = future_to_target[future]
            name, node_type, host, port = target
            try:
                key, node_result = future.result()
                results[key] = node_result
                if verbose:
                    icmp = node_result.get("icmp_ping", {})
                    tcp = node_result.get("tcp_traceroute", {})
                    icmp_ok = "OK" if icmp.get("reachable") else "FAIL"
                    tcp_ok = "OPEN" if tcp.get("reachable") else "CLOSED"
                    tcp_err = ""
                    if not tcp.get("reachable") and tcp.get("error"):
                        tcp_err = f" ({tcp['error']})"
                    click.echo(
                        f"  [{node_type:10}] {name:15} {format_host_port(host, port)} "
                        f"ICMP={icmp_ok} TCP={tcp_ok}{tcp_err}"
                    )
            except Exception as e:
                key = f"{name}|{node_type}"
                results[key] = {
                    "name": name,
                    "node_type": node_type,
                    "host": host,
                    "port": port,
                    "error": str(e),
                }
                if verbose:
                    click.echo(
                        f"  [{node_type:10}] {name:15} {format_host_port(host, port)} ERROR: {e}"
                    )

    return results


def make_survey_table(
    survey_results: dict[str, dict[str, Any]],
    operational_nodes: set[str] | None = None,
) -> Table:
    table = Table(
        title="Survey Results",
        show_header=True,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
    )
    table.add_column("Node", style="dim")
    table.add_column("Type", style="dim")
    table.add_column("Host", justify="left")
    table.add_column("Port", justify="right")
    table.add_column("ICMP Ping", justify="right")
    table.add_column("TCP Trace", justify="right")
    table.add_column("Hops", justify="right")

    sorted_items = sorted(
        survey_results.items(),
        key=lambda x: (x[1].get("name", ""), x[1].get("node_type", "")),
    )

    for key, data in sorted_items:
        name = data.get("name", key.split("|")[0] if "|" in key else key)
        node_type = data.get("node_type", "")
        host = data.get("host", "")
        port = data.get("port", 0)

        is_unknown = host == "unknown" or host == ""
        
        tcp = data.get("tcp_traceroute", {})
        tcp_reachable = tcp.get("reachable", False) if tcp else False

        icmp = data.get("icmp_ping", {})
        icmp_reachable = icmp.get("reachable", False) if icmp else False

        # Check if node is operational (in consensus) - dirauths are always considered operational
        is_dirauth = node_type == "dirauth"
        is_operational = is_dirauth or (
            operational_nodes is not None and name in operational_nodes
        ) or operational_nodes is None

        # Determine if this row should be highlighted as OUT (reachable but not in consensus)
        is_out = tcp_reachable and not is_operational

        if is_unknown:
            host_display = "UNKNOWN"
            port_display = "-"
        else:
            host_display = host
            port_display = str(port)

        if is_unknown:
            icmp_status = Text("UNKNOWN", style="red")
        elif icmp.get("reachable"):
            latency = icmp.get("latency_ms")
            if latency is not None:
                icmp_status = Text(f"OK ({latency:.1f}ms)", style="yellow" if is_out else "cyan")
            else:
                icmp_status = Text("OK", style="yellow" if is_out else "cyan")
        elif icmp.get("error"):
            if icmp.get("error") == "address unknown":
                icmp_status = Text("UNKNOWN", style="red")
            elif tcp_reachable:
                icmp_status = Text("FILTERED", style="yellow")
            else:
                icmp_status = Text(f"ERR: {icmp['error']}", style="red")
        else:
            if tcp_reachable:
                icmp_status = Text("FILTERED", style="yellow")
            else:
                icmp_status = Text("DOWN", style="red")

        if is_unknown:
            tcp_status = Text("UNKNOWN", style="red")
            hop_count: str | Text = "-"
        elif tcp:
            if tcp.get("reachable"):
                latency = tcp.get("final_latency_ms")
                if is_out:
                    if latency is not None:
                        tcp_status = Text(f"OUT ({latency:.1f}ms)", style="yellow")
                    else:
                        tcp_status = Text("OUT", style="yellow")
                else:
                    if latency is not None:
                        tcp_status = Text(f"OPEN ({latency:.1f}ms)", style="cyan")
                    else:
                        tcp_status = Text("OPEN", style="cyan")
            elif tcp.get("error"):
                if tcp.get("error") == "address unknown":
                    tcp_status = Text("UNKNOWN", style="red")
                else:
                    tcp_status = Text(f"ERR: {tcp['error']}", style="red")
            else:
                tcp_status = Text("CLOSED", style="red")
            hop_count = Text(str(len(tcp.get("hops", []))), style="yellow") if is_out else str(len(tcp.get("hops", [])))
        else:
            tcp_status = Text("N/A", style="dim")
            hop_count = "-"

        if is_out:
            table.add_row(
                Text(name, style="yellow"),
                Text(node_type, style="yellow"),
                Text(host_display, style="yellow"),
                Text(port_display, style="yellow"),
                icmp_status, tcp_status, hop_count
            )
        else:
            table.add_row(
                name, node_type, host_display, port_display,
                icmp_status, tcp_status, hop_count
            )

    return table


def make_traceroute_detail_table(
    key: str,
    data: dict[str, Any],
    operational_nodes: set[str] | None = None,
) -> Table:
    name = data.get("name", key.split("|")[0] if "|" in key else key)
    node_type = data.get("node_type", "")
    host = data.get("host", "")
    port = data.get("port", 0)
    trace_data = data.get("tcp_traceroute", {})
    icmp_data = data.get("icmp_ping", {})

    is_unknown = host == "unknown" or host == ""
    if is_unknown:
        addr_str = "UNKNOWN"
    else:
        addr_str = format_host_port(host, port)

    # Determine node status for title styling
    tcp_reachable = trace_data.get("reachable", False) if trace_data else False
    icmp_reachable = icmp_data.get("reachable", False) if icmp_data else False
    is_operational = name in operational_nodes if operational_nodes else False
    
    # Dirauths are not in operational_nodes (which comes from PKI doc)
    # but should be cyan when TCP is up since they ARE the consensus makers
    is_dirauth = node_type == "dirauth"
    
    # Determine title style:
    # - OK (in consensus, or dirauth with TCP up): cyan
    # - OUT (TCP up, not in consensus): yellow
    # - DOWN & OUT (TCP down, not in consensus): red
    if is_operational or (is_dirauth and tcp_reachable):
        title_style = "cyan"
    elif tcp_reachable:
        title_style = "yellow"
    else:
        title_style = "red"

    title = Text()
    title.append(f"{name} ({node_type})\n", style=title_style)
    title.append(addr_str, style=title_style)
    
    table = Table(
        title=title,
        show_header=True,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
    )
    table.add_column("Hop", justify="right")
    table.add_column("IP Address", justify="left")
    table.add_column("Latency", justify="right")

    hops = trace_data.get("hops", [])
    if hops:
        # Collapse consecutive * entries into a single line
        i = 0
        while i < len(hops):
            hop = hops[i]
            ip = hop.get("ip") or "*"
            latency = hop.get("latency_ms")

            if ip == "*" and latency is None:
                # Count consecutive * entries
                star_start = hop.get("hop", i + 1)
                star_count = 1
                j = i + 1
                while j < len(hops):
                    next_hop = hops[j]
                    next_ip = next_hop.get("ip") or "*"
                    next_latency = next_hop.get("latency_ms")
                    if next_ip == "*" and next_latency is None:
                        star_count += 1
                        j += 1
                    else:
                        break

                # Display single * line for the range
                if star_count == 1:
                    hop_num = str(star_start)
                else:
                    hop_num = f"{star_start}-{star_start + star_count - 1}"
                table.add_row(hop_num, "*", "*")
                i = j
            else:
                hop_num = str(hop.get("hop", ""))
                latency_display: str | Text
                if latency is not None:
                    latency_display = Text(f"{latency:.1f}ms", style="cyan")
                else:
                    latency_display = "*"
                table.add_row(hop_num, ip, latency_display)
                i += 1
    else:
        error = trace_data.get("error", "")
        if error == "address unknown" or is_unknown:
            table.add_row("-", Text("UNKNOWN", style="red"), "-")
        elif error:
            table.add_row("-", Text(f"Error: {error}", style="red"), "-")
        else:
            table.add_row("-", "No path data", "-")

    return table


def epoch_id_to_time_str(epoch_id: int) -> str:
    t = EPOCH + epoch_id * PERIOD
    return t.strftime("%Y-%m-%d %H:%M:%S")


def parse_host_port(addr: str) -> tuple[str, int] | None:
    if addr.startswith("tcp://"):
        addr = addr[6:]
    if addr.startswith("["):
        bracket_end = addr.find("]")
        if bracket_end != -1:
            host = addr[1:bracket_end]
            rest = addr[bracket_end + 1:]
            if rest.startswith(":"):
                try:
                    return (host, int(rest[1:]))
                except ValueError:
                    pass
    elif ":" in addr:
        host, port_str = addr.rsplit(":", 1)
        try:
            return (host, int(port_str))
        except ValueError:
            pass
    return None


def parse_dirauth_config(dirauthconf: str) -> dict[str, Any]:
    with open(dirauthconf, "rb") as f:
        config = tomli.load(f)

    authorities = {
        auth["Identifier"] for auth in config.get("Authorities", [])
    }

    def extract_all_addresses(
        nodes: list[dict[str, Any]],
    ) -> dict[str, list[tuple[str, int]]]:
        addresses: dict[str, list[tuple[str, int]]] = {}
        for node in nodes:
            name = node.get("Identifier", "")
            addr_list = node.get("Addresses", [])
            if name:
                node_addrs: list[tuple[str, int]] = []
                for addr in addr_list:
                    result = parse_host_port(addr)
                    if result:
                        node_addrs.append(result)
                if node_addrs:
                    addresses[name] = node_addrs
        return addresses

    dirauth_addresses = extract_all_addresses(config.get("Authorities", []))
    mix_addresses = extract_all_addresses(config.get("Mixes", []))
    gateway_addresses = extract_all_addresses(config.get("GatewayNodes", []))
    servicenode_addresses = extract_all_addresses(config.get("ServiceNodes", []))
    storagenode_addresses = extract_all_addresses(config.get("StorageReplicas", []))

    mixes = {mix["Identifier"] for mix in config.get("Mixes", [])}
    gateways = {
        node["Identifier"] for node in config.get("GatewayNodes", [])
    }
    servicenodes = {
        node["Identifier"] for node in config.get("ServiceNodes", [])
    }
    storagenodes = {
        node["Identifier"] for node in config.get("StorageReplicas", [])
    }
    sphinx_geometry = config["SphinxGeometry"]
    server = config["Server"]

    topology_layers: list[list[str]] = []
    topology_addresses: dict[str, list[tuple[str, int]]] = {}
    topology_config = config.get("Topology", {})
    layers_config = topology_config.get("Layers", [])
    for layer in layers_config:
        layer_nodes = []
        for node in layer.get("Nodes", []):
            name = node.get("Identifier", "")
            if name:
                layer_nodes.append(name)
                addr_list = node.get("Addresses", [])
                node_addrs: list[tuple[str, int]] = []
                for addr in addr_list:
                    result = parse_host_port(addr)
                    if result:
                        node_addrs.append(result)
                if node_addrs:
                    topology_addresses[name] = node_addrs
        topology_layers.append(layer_nodes)

    # Extract network parameters from config
    parameters = config.get("Parameters", {})

    return {
        "server": server,
        "sphinx_geometry": sphinx_geometry,
        "parameters": parameters,
        "authorities": authorities,
        "dirauth_addresses": dirauth_addresses,
        "mix_addresses": mix_addresses,
        "gateway_addresses": gateway_addresses,
        "servicenode_addresses": servicenode_addresses,
        "storagenode_addresses": storagenode_addresses,
        "topology_addresses": topology_addresses,
        "mixes": mixes,
        "gateways": gateways,
        "servicenodes": servicenodes,
        "storagenodes": storagenodes,
        "topology_layers": topology_layers,
    }


def build_survey_targets_from_config(
    dirauth_data: dict[str, Any],
) -> list[SurveyTarget]:
    targets: list[SurveyTarget] = []

    for name, addrs in dirauth_data.get("dirauth_addresses", {}).items():
        for host, port in addrs:
            targets.append((name, "dirauth", host, port))

    for name, addrs in dirauth_data.get("gateway_addresses", {}).items():
        for host, port in addrs:
            targets.append((name, "gateway", host, port))

    for name, addrs in dirauth_data.get("servicenode_addresses", {}).items():
        for host, port in addrs:
            targets.append((name, "service", host, port))

    for name, addrs in dirauth_data.get("mix_addresses", {}).items():
        for host, port in addrs:
            targets.append((name, "mix", host, port))

    for name, addrs in dirauth_data.get("storagenode_addresses", {}).items():
        for host, port in addrs:
            targets.append((name, "storage", host, port))

    topology_addresses = dirauth_data.get("topology_addresses", {})
    topology_layers = dirauth_data.get("topology_layers", [])
    for layer_idx, layer_nodes in enumerate(topology_layers):
        for name in layer_nodes:
            if name in topology_addresses:
                for host, port in topology_addresses[name]:
                    targets.append((name, f"mix-L{layer_idx}", host, port))

    return targets


def parse_thinclient_config(config_path: str) -> dict[str, Any]:
    """Read the thin client TOML for display purposes only.

    The Sphinx and Pigeonhole geometries are no longer carried in this
    file: the daemon now supplies them to the thin client over the
    handshake. We read only the [Dial] transport so that verbose output
    can name where it is connecting.
    """
    with open(config_path, "rb") as f:
        config = tomli.load(f)
    dial = config.get("Dial", {})
    unix = dial.get("Unix", {})
    tcp = dial.get("Tcp", {})
    if unix:
        network = "unix"
        address = unix.get("Address", "")
    else:
        network = tcp.get("Network", "tcp")
        address = tcp.get("Address", "localhost:64331")
    return {
        "network": network,
        "address": address,
    }


def pigeonhole_geometry_to_dict(geometry: Any) -> dict[str, Any]:
    """Render a thin client PigeonholeGeometry object as the PascalCase
    dict the geometry tables expect.

    The daemon supplies this geometry over the handshake, so we read it
    from the connected client rather than the config file. Returns an
    empty dict when no geometry is available (for instance, when the
    daemon could not be reached).
    """
    if geometry is None:
        return {}
    return {
        "MaxPlaintextPayloadLength": geometry.max_plaintext_payload_length,
        "CourierQueryReadLength": geometry.courier_query_read_length,
        "CourierQueryWriteLength": geometry.courier_query_write_length,
        "CourierQueryReplyReadLength": geometry.courier_query_reply_read_length,
        "CourierQueryReplyWriteLength": geometry.courier_query_reply_write_length,
        "NIKEName": geometry.nike_name,
        "SignatureSchemeName": geometry.signature_scheme_name,
    }


def decode_node(raw_node: bytes | dict[str, Any]) -> dict[str, Any]:
    """Decode a CBOR-encoded node or return it directly if already decoded."""
    if isinstance(raw_node, dict):
        return raw_node
    result: dict[str, Any] = cbor2.loads(raw_node)
    return result


def get_operational_nodes(doc: dict[str, Any]) -> set[str]:
    nodes: set[str] = set()
    for node in doc.get("GatewayNodes", []):
        nodes.add(decode_node(node)["Name"])
    for node in doc.get("ServiceNodes", []):
        nodes.add(decode_node(node)["Name"])
    for layer in doc.get("Topology", []):
        for node in layer:
            nodes.add(decode_node(node)["Name"])
    for node in doc.get("StorageReplicas", []):
        nodes.add(decode_node(node)["Name"])
    return nodes


def get_node_addresses_from_pki(doc: dict[str, Any]) -> dict[str, list[tuple[str, int]]]:
    addresses: dict[str, list[tuple[str, int]]] = {}

    def extract_all_addresses(node_data: dict[str, Any]) -> list[tuple[str, int]]:
        results: list[tuple[str, int]] = []
        addrs = node_data.get("Addresses", {})
        for transport in ["tcp4", "tcp", "tcp6"]:
            addr_list = addrs.get(transport, [])
            for addr in addr_list:
                result = parse_host_port(addr)
                if result:
                    results.append(result)
        return results

    for raw_node in doc.get("GatewayNodes", []):
        node = decode_node(raw_node)
        name = node.get("Name", "")
        if name:
            node_addrs = extract_all_addresses(node)
            if node_addrs:
                addresses[name] = node_addrs

    for raw_node in doc.get("ServiceNodes", []):
        node = decode_node(raw_node)
        name = node.get("Name", "")
        if name:
            node_addrs = extract_all_addresses(node)
            if node_addrs:
                addresses[name] = node_addrs

    for layer in doc.get("Topology", []):
        for raw_node in layer:
            node = decode_node(raw_node)
            name = node.get("Name", "")
            if name:
                node_addrs = extract_all_addresses(node)
                if node_addrs:
                    addresses[name] = node_addrs

    for raw_node in doc.get("StorageReplicas", []):
        node = decode_node(raw_node)
        name = node.get("Name", "")
        if name:
            node_addrs = extract_all_addresses(node)
            if node_addrs:
                addresses[name] = node_addrs

    return addresses


def build_survey_targets_from_pki(doc: dict[str, Any]) -> list[SurveyTarget]:
    targets: list[SurveyTarget] = []

    def extract_all_addresses(node_data: dict[str, Any]) -> list[tuple[str, int]]:
        results: list[tuple[str, int]] = []
        addrs = node_data.get("Addresses", {})
        for transport in ["tcp4", "tcp", "tcp6"]:
            addr_list = addrs.get(transport, [])
            for addr in addr_list:
                result = parse_host_port(addr)
                if result:
                    results.append(result)
        return results

    for raw_node in doc.get("GatewayNodes", []):
        node = decode_node(raw_node)
        name = node.get("Name", "")
        if name:
            for host, port in extract_all_addresses(node):
                targets.append((name, "gateway", host, port))

    for raw_node in doc.get("ServiceNodes", []):
        node = decode_node(raw_node)
        name = node.get("Name", "")
        if name:
            for host, port in extract_all_addresses(node):
                targets.append((name, "service", host, port))

    for layer_idx, layer in enumerate(doc.get("Topology", [])):
        for raw_node in layer:
            node = decode_node(raw_node)
            name = node.get("Name", "")
            if name:
                for host, port in extract_all_addresses(node):
                    targets.append((name, f"mix-L{layer_idx}", host, port))

    for raw_node in doc.get("StorageReplicas", []):
        node = decode_node(raw_node)
        name = node.get("Name", "")
        if name:
            for host, port in extract_all_addresses(node):
                targets.append((name, "storage", host, port))

    return targets


def get_services_by_capability(
    doc: dict[str, Any],
) -> dict[str, list[str]]:
    capabilities: dict[str, list[str]] = defaultdict(list)
    for raw_node in doc.get("ServiceNodes", []):
        node = decode_node(raw_node)
        node_name = node.get("Name", "unknown")
        kaetzchen = node.get("Kaetzchen", {})
        if isinstance(kaetzchen, dict):
            for capability in kaetzchen.keys():
                capabilities[capability].append(node_name)
    return dict(capabilities)


def make_network_params_table(
    doc: dict[str, Any],
    sphinx_geometry: dict[str, Any],
    pigeonhole_geometry: dict[str, Any],
    config_params: dict[str, Any] | None = None,
) -> Table:
    table = Table(
        title="Mix Parameters",
        show_header=True,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
    )
    table.add_column("Name", style="dim")
    table.add_column("Value", justify="right")

    user_payload = sphinx_geometry.get("UserForwardPayloadLength", "N/A")
    table.add_row("UserForwardPayloadLength", str(user_payload))
    max_plaintext = pigeonhole_geometry.get("MaxPlaintextPayloadLength", "N/A")
    table.add_row("MaxPlaintextPayloadLength", str(max_plaintext))

    table.add_row("Mix Layers", f"{len(doc.get('Topology', []))}")

    # Parameters: prefer consensus (doc), fall back to config, then N/A
    # Check nested "Parameters" key in doc first, then top-level doc, then config
    doc_params = doc.get("Parameters", {})
    cfg = config_params or {}

    def get_param(name: str) -> str:
        # Try doc's nested Parameters first
        if name in doc_params:
            return str(doc_params[name])
        # Try top-level doc
        if name in doc:
            return str(doc[name])
        # Fall back to config
        if name in cfg:
            return str(cfg[name])
        return "N/A"

    table.add_row("SendRatePerMinute", get_param("SendRatePerMinute"))
    table.add_row("Mu", get_param("Mu"))
    table.add_row("LambdaM", get_param("LambdaM"))
    table.add_row("LambdaG", get_param("LambdaG"))
    table.add_row("LambdaP", get_param("LambdaP"))
    table.add_row("LambdaL", get_param("LambdaL"))
    table.add_row("LambdaD", get_param("LambdaD"))
    return table


def make_status_table(
    dirauths: set[str],
    mixes: set[str],
    gateways: set[str],
    servicenodes: set[str],
    storagenodes: set[str],
) -> Table:
    table = Table(
        title="Node Statistics",
        show_header=True,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
    )
    table.add_column("Node Type", style="dim")
    table.add_column("Configured", justify="right")

    table.add_row("Directory Authority Nodes", str(len(dirauths)))
    table.add_row("Mix Nodes", str(len(mixes)))
    table.add_row("Gateway Nodes", str(len(gateways)))
    table.add_row("Kaetzchen Service Nodes", str(len(servicenodes)))
    table.add_row("Storage Nodes", str(len(storagenodes)))
    return table


def get_service_node_timing(
    provider_name: str,
    survey_results: dict[str, dict[str, Any]] | None,
) -> float | None:
    if not survey_results:
        return None
    for key, data in survey_results.items():
        if key.startswith(f"{provider_name}|"):
            tcp = data.get("tcp_traceroute", {})
            tcp_latency = tcp.get("final_latency_ms")
            if tcp.get("reachable") and isinstance(tcp_latency, (int, float)):
                return float(tcp_latency)
            icmp = data.get("icmp_ping", {})
            icmp_latency = icmp.get("latency_ms")
            if icmp.get("reachable") and isinstance(icmp_latency, (int, float)):
                return float(icmp_latency)
    return None


def make_ping_table(
    service_probes: ServiceProbeResults,
    capabilities: dict[str, list[str]],
    survey_results: dict[str, dict[str, Any]] | None = None,
) -> Table:
    table = Table(
        title="Kaetzchen Service Active Probes",
        show_header=True,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
    )
    table.add_column("Service")
    table.add_column("Result", justify="right")

    # Collect all rows for sorting: (sort_key, label, status_text)
    rows: list[tuple[str, Text | str, Text]] = []

    # Echo probes
    echo_providers = capabilities.get("echo", [])
    echo_results = service_probes.get("echo", {})
    for provider in sorted(echo_providers):
        service_name = f"echo@{provider}"
        probe_result = echo_results.get(provider)
        if probe_result is None:
            rows.append((service_name, Text(service_name, style="dim"), Text("Unsupported", style="dim")))
        else:
            success, latency = probe_result
            if success:
                latency_str = f" ({latency:.0f}ms)" if latency is not None else ""
                rows.append((service_name, Text(service_name, style="cyan"), Text(f"OK{latency_str}", style="cyan")))
            else:
                fallback = get_service_node_timing(provider, survey_results)
                timing = f" ({fallback:.0f}ms)" if fallback else ""
                rows.append((service_name, Text(service_name, style="red"), Text(f"FAILURE{timing}", style="red")))

    # Courier probes (independent, not derived from replica probes)
    courier_providers = capabilities.get("courier", [])
    courier_results = service_probes.get("courier", {})
    for provider in sorted(courier_providers):
        service_name = f"courier@{provider}"
        probe_result = courier_results.get(provider)
        if probe_result is None:
            rows.append((service_name, Text(service_name, style="dim"), Text("Unsupported", style="dim")))
        else:
            success, latency = probe_result
            if success:
                latency_str = f" ({latency:.0f}ms)" if latency is not None else ""
                rows.append((service_name, Text(service_name, style="cyan"), Text(f"OK{latency_str}", style="cyan")))
            else:
                fallback = get_service_node_timing(provider, survey_results)
                timing = f" ({fallback:.0f}ms)" if fallback else ""
                rows.append((service_name, Text(service_name, style="red"), Text(f"FAILURE{timing}", style="red")))

    # Replica probes - format: courier@provider->replica
    storage_replicas = capabilities.get("_storage_replicas", [])
    replica_results = service_probes.get("replica", {})

    for courier in sorted(courier_providers):
        for replica in sorted(storage_replicas):
            probe_key = f"{courier}->{replica}"
            probe_result = replica_results.get(probe_key)
            sort_key = f"courier@{courier}->{replica}"

            service_label = Text()

            if probe_result is None:
                service_label.append("courier@", style="dim")
                service_label.append(courier, style="dim")
                service_label.append("->", style="dim")
                service_label.append(replica, style="dim")
                rows.append((sort_key, service_label, Text("Unsupported", style="dim")))
            else:
                success, latency = probe_result
                if success:
                    # Full success - all cyan
                    service_label.append("courier@", style="cyan")
                    service_label.append(courier, style="cyan")
                    service_label.append("->", style="cyan")
                    service_label.append(replica, style="cyan")
                    latency_str = f" ({latency:.0f}ms)" if latency is not None else ""
                    rows.append((sort_key, service_label, Text(f"OK{latency_str}", style="cyan")))
                elif latency is not None:
                    # Got courier ACK but no replica data - courier cyan, arrow/replica yellow
                    service_label.append("courier@", style="cyan")
                    service_label.append(courier, style="cyan")
                    service_label.append("->", style="yellow")
                    service_label.append(replica, style="yellow")
                    latency_str = f" ({latency:.0f}ms)"
                    rows.append((sort_key, service_label, Text(f"COURIER ACK{latency_str}", style="yellow")))
                else:
                    # Complete failure - all red
                    service_label.append("courier@", style="red")
                    service_label.append(courier, style="red")
                    service_label.append("->", style="red")
                    service_label.append(replica, style="red")
                    fallback = get_service_node_timing(courier, survey_results)
                    timing = f" ({fallback:.0f}ms)" if fallback else ""
                    rows.append((sort_key, service_label, Text(f"FAILURE{timing}", style="red")))

    # Sort rows alphabetically and add to table
    for sort_key, label, status_text in sorted(rows, key=lambda x: x[0]):
        table.add_row(label, status_text)

    return table

def make_connection_status_table(conn_status: ConnectionStatus, has_consensus: bool) -> Table:
    # Check if any critical check failed
    any_failed = not conn_status.daemon_connected or not has_consensus
    
    table = Table(
        title="kpclientd Status",
        show_header=True,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
        border_style="red" if any_failed else None,
    )
    table.add_column("Check", style="dim")
    table.add_column("Result", justify="right")

    # Row 1: Socket connection to kpclientd daemon
    if conn_status.daemon_connected:
        socket_status = Text("OK", style="cyan")
    else:
        socket_status = Text("FAIL", style="red")
    table.add_row("Socket", socket_status)

    # Row 2: Consensus fetch result
    if has_consensus:
        consensus_status = Text("OK", style="cyan")
    else:
        if conn_status.daemon_connected:
            # Socket works but no consensus - network is in dissensus
            consensus_status = Text("DISSENSUS", style="red")
        else:
            # Can't fetch consensus without socket
            consensus_status = Text("N/A", style="dim")
    table.add_row("Consensus", consensus_status)

    # Row 3: Network status (only meaningful if socket connected)
    if conn_status.daemon_connected:
        if has_consensus and conn_status.network_online:
            network_status = Text("ONLINE", style="cyan")
        elif has_consensus:
            network_status = Text("OFFLINE", style="yellow")
        else:
            # No consensus means daemon can't reach network
            network_status = Text("OFFLINE", style="red")
        table.add_row("Network", network_status)

    return table


def make_services_table(capabilities: dict[str, list[str]]) -> Table:
    table = Table(
        title="Kaetzchen Services",
        show_header=True,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
    )
    table.add_column("Mix Service", style="dim")
    table.add_column("Providers", justify="right")
    table.add_column("Count", justify="right")

    for capability, providers in sorted(capabilities.items()):
        if capability.startswith("_"):
            continue
        providers_str = ", ".join(sorted(providers))
        table.add_row(capability, providers_str, str(len(providers)))

    return table


def make_outage_reports(
    doc: dict[str, Any],
    mixes: set[str],
    gateways: set[str],
    servicenodes: set[str],
    storagenodes: set[str],
    dirauth_status: dict[str, tuple[bool, float | None]],
    node_status: dict[str, tuple[bool, float | None]],
    survey_results: dict[str, dict[str, Any]] | None = None,
) -> list[Table]:
    operational_nodes = get_operational_nodes(doc)

    def get_node_survey_status(
        node_name: str, category: str | None = None
    ) -> tuple[bool, float | None, bool, float | None, bool]:
        """Get ICMP and TCP status from survey results, limited to a single
        role category when given so a dual-role machine's roles are not
        conflated. Returns (icmp_ok, icmp_latency, tcp_ok, tcp_latency,
        was_surveyed)."""
        entries = _survey_entries_for_role(node_name, category, survey_results)
        if not entries:
            return False, None, False, None, False

        icmp_ok = False
        icmp_latency: float | None = None
        tcp_ok = False
        tcp_latency: float | None = None

        for data in entries:
            icmp = data.get("icmp_ping", {})
            if icmp.get("reachable"):
                icmp_ok = True
                lat = icmp.get("latency_ms")
                if isinstance(lat, (int, float)):
                    if icmp_latency is None or lat < icmp_latency:
                        icmp_latency = float(lat)

            tcp = data.get("tcp_traceroute", {})
            if tcp.get("reachable"):
                tcp_ok = True
                lat = tcp.get("final_latency_ms")
                if isinstance(lat, (int, float)):
                    if tcp_latency is None or lat < tcp_latency:
                        tcp_latency = float(lat)

        return icmp_ok, icmp_latency, tcp_ok, tcp_latency, True

    def get_outage_report(
        node_type: str,
        config_nodes: set[str],
        category: str,
    ) -> Table | None:
        outages = config_nodes - operational_nodes
        if outages:
            table = Table(
                title=node_type,
                show_header=False,
                box=box.HEAVY_EDGE,
                border_style="red",
            )
            table.add_column(node_type, justify="center", no_wrap=True)
            table.add_column("Status", justify="right")
            for node in sorted(outages):
                # Get status from survey results (more accurate), for this role only
                icmp_ok, icmp_latency, tcp_ok, tcp_latency, was_surveyed = get_node_survey_status(node, category)
                
                # Fallback to node_status if no survey results for this node
                if not was_surveyed and node in node_status:
                    tcp_ok, tcp_latency = node_status[node]
                
                # Determine display based on survey status:
                # - TCP OPEN: OUT (yellow) - service responds but not in consensus
                # - TCP CLOSED (surveyed) + ICMP OK: DOWN & OUT with timing
                # - TCP CLOSED (surveyed) + ICMP FAIL: DOWN & OUT
                # - Not surveyed: OUT (yellow) - unknown if service is down
                
                if tcp_ok:
                    latency = tcp_latency if tcp_latency is not None else icmp_latency
                    if latency is not None:
                        status = Text(f"OUT ({latency:.0f}ms)", style="yellow")
                    else:
                        status = Text("OUT", style="yellow")
                elif was_surveyed:
                    if icmp_ok and icmp_latency is not None:
                        status = Text(f"DOWN & OUT ({icmp_latency:.0f}ms)", style="red")
                    else:
                        status = Text("DOWN & OUT", style="red")
                else:
                    status = Text("OUT", style="yellow")
                table.add_row(node, status)
            return table
        return None

    dirauth_outages = {
        name for name, (is_up, _) in dirauth_status.items() if not is_up
    }
    dirauth_report: Table | None = None
    if dirauth_outages:
        dirauth_report = Table(
            title="Directory Authorities",
            show_header=False,
            box=box.HEAVY_EDGE,
            border_style="red",
        )
        dirauth_report.add_column("Directory Authorities", justify="center", no_wrap=True)
        dirauth_report.add_column("Status", justify="right")
        for node in sorted(dirauth_outages):
            # Get survey status for dirauth
            icmp_ok, icmp_latency, tcp_ok, tcp_latency, was_surveyed = get_node_survey_status(node, "dirauth")
            
            if tcp_ok:
                latency = tcp_latency if tcp_latency is not None else icmp_latency
                if latency is not None:
                    status = Text(f"OUT ({latency:.0f}ms)", style="yellow")
                else:
                    status = Text("OUT", style="yellow")
            elif was_surveyed:
                if icmp_ok and icmp_latency is not None:
                    status = Text(f"DOWN & OUT ({icmp_latency:.0f}ms)", style="red")
                else:
                    status = Text("DOWN & OUT", style="red")
            else:
                status = Text("OUT", style="yellow")
            dirauth_report.add_row(node, status)

    reports = [
        dirauth_report,
        get_outage_report("Mix Nodes", mixes, "mix"),
        get_outage_report("Gateways", gateways, "gateway"),
        get_outage_report("Service Nodes", servicenodes, "service"),
        get_outage_report("Storage Replicas", storagenodes, "storage"),
    ]
    return [r for r in reports if r is not None]


# Survey node_type values are role-specific ("dirauth", "gateway", "service",
# "mix", "storage", and the per-layer "mix-L0"/"mix-L1"/...). A single machine
# may run several roles at once (for example a directory authority that also
# runs a mix), so reachability must be read per role. Matching by name alone
# lets one role's probe mask another's, making a dead mix on a healthy dirauth
# host appear alive.
def _role_accepts(category: str) -> Callable[[str], bool]:
    if category == "mix":
        return lambda t: t == "mix" or t.startswith("mix-")
    return lambda t: t == category


def _survey_entries_for_role(
    node_name: str,
    category: str | None,
    survey_results: dict[str, dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    if not survey_results:
        return []
    accept = _role_accepts(category) if category is not None else (lambda _t: True)
    return [
        data
        for data in survey_results.values()
        if data.get("name") == node_name and accept(str(data.get("node_type", "")))
    ]


def role_tcp_status(
    node_name: str,
    category: str,
    survey_results: dict[str, dict[str, Any]] | None,
    node_status: dict[str, tuple[bool, float | None]],
) -> tuple[bool, float | None]:
    """Best TCP reachability and latency for node_name in a single role.

    Only survey entries belonging to `category` are considered, so a machine
    running several roles does not have one role's reachability reported for
    another. Falls back to the name-keyed node_status only when this role was
    not surveyed."""
    entries = _survey_entries_for_role(node_name, category, survey_results)
    if not entries:
        return node_status.get(node_name, (False, None))
    tcp_up = False
    tcp_latency: float | None = None
    for data in entries:
        tcp = data.get("tcp_traceroute", {})
        if tcp.get("reachable"):
            tcp_up = True
            lat = tcp.get("final_latency_ms")
            if isinstance(lat, (int, float)) and (tcp_latency is None or lat < tcp_latency):
                tcp_latency = float(lat)
    return tcp_up, tcp_latency


def get_icmp_latency_from_survey(
    node_name: str,
    survey_results: dict[str, dict[str, Any]] | None,
    category: str | None = None,
) -> float | None:
    """Get the best (lowest) ICMP latency for a node, optionally limited to a
    single role category so dual-role machines are not conflated."""
    best_latency: float | None = None
    for data in _survey_entries_for_role(node_name, category, survey_results):
        icmp = data.get("icmp_ping", {})
        if icmp.get("reachable"):
            lat = icmp.get("latency_ms")
            if isinstance(lat, (int, float)):
                if best_latency is None or lat < best_latency:
                    best_latency = float(lat)
    return best_latency


def make_dirauth_table(
    authorities: set[str],
    dirauth_status: dict[str, tuple[bool, float | None]],
    has_consensus: bool = True,
) -> Table:
    # Check if all dirauths are failing
    all_down = all(
        not dirauth_status.get(node, (False, None))[0]
        for node in authorities
    ) if authorities else False
    
    table = Table(
        title="Directory Authorities",
        show_header=False,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
        border_style="red" if (all_down or not has_consensus) else "cyan",
    )
    table.add_column("Node Name", style="dim")
    table.add_column("Status", justify="right")

    for node in sorted(authorities):
        if node in dirauth_status:
            is_up, latency = dirauth_status[node]
            latency_str = f" ({latency:.0f}ms)" if latency is not None else ""
            if is_up:
                if has_consensus:
                    status = Text(f"CONSENSUS{latency_str}", style="cyan")
                else:
                    status = Text(f"DISSENSUS{latency_str}", style="red")
            else:
                status = Text(f"DOWN{latency_str}" if latency_str else "DOWN", style="red")
        else:
            status = Text("N/A", style="red")
        table.add_row(node, status)
    return table


def make_gateway_table(
    gateways: set[str],
    operational_nodes: set[str],
    node_status: dict[str, tuple[bool, float | None]],
    survey_results: dict[str, dict[str, Any]] | None = None,
) -> Table:
    # Check if all gateways are failing (not operational)
    all_failing = all(
        node not in operational_nodes
        for node in gateways
    ) if gateways else False
    
    table = Table(
        title="Gateways",
        show_header=False,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
        border_style="red" if all_failing else "cyan",
    )
    table.add_column("Node Name", style="dim")
    table.add_column("Status", justify="right")
    for node in sorted(gateways):
        tcp_up, tcp_latency = role_tcp_status(node, "gateway", survey_results, node_status)
        icmp_latency = get_icmp_latency_from_survey(node, survey_results, "gateway")
        
        is_operational = node in operational_nodes

        if is_operational:
            latency_str = f" ({tcp_latency:.0f}ms)" if tcp_latency is not None else ""
            status = Text(f"OK{latency_str}", style="cyan")
        elif tcp_up:
            latency_str = f" ({tcp_latency:.0f}ms)" if tcp_latency is not None else ""
            status = Text(f"OUT{latency_str}", style="yellow")
        else:
            if icmp_latency is not None:
                status = Text(f"DOWN & OUT ({icmp_latency:.0f}ms)", style="red")
            else:
                status = Text("DOWN & OUT", style="red")
        table.add_row(node, status)
    return table


def make_service_table(
    servicenodes: set[str],
    operational_nodes: set[str],
    node_status: dict[str, tuple[bool, float | None]],
    survey_results: dict[str, dict[str, Any]] | None = None,
) -> Table:
    # Check if all service nodes are failing (not operational)
    all_failing = all(
        node not in operational_nodes
        for node in servicenodes
    ) if servicenodes else False
    
    table = Table(
        title="Kaetzchen Service\nNodes",
        show_header=False,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
        border_style="red" if all_failing else "cyan",
    )
    table.add_column("Node Name", style="dim")
    table.add_column("Status", justify="right")
    for node in sorted(servicenodes):
        tcp_up, tcp_latency = role_tcp_status(node, "service", survey_results, node_status)
        icmp_latency = get_icmp_latency_from_survey(node, survey_results, "service")
        
        is_operational = node in operational_nodes

        if is_operational:
            latency_str = f" ({tcp_latency:.0f}ms)" if tcp_latency is not None else ""
            status = Text(f"OK{latency_str}", style="cyan")
        elif tcp_up:
            latency_str = f" ({tcp_latency:.0f}ms)" if tcp_latency is not None else ""
            status = Text(f"OUT{latency_str}", style="yellow")
        else:
            if icmp_latency is not None:
                status = Text(f"DOWN & OUT ({icmp_latency:.0f}ms)", style="red")
            else:
                status = Text("DOWN & OUT", style="red")
        table.add_row(node, status)
    return table


def make_storage_table(
    storagenodes: set[str],
    operational_nodes: set[str],
    node_status: dict[str, tuple[bool, float | None]],
    survey_results: dict[str, dict[str, Any]] | None = None,
) -> Table:
    # Check if all storage nodes are failing (not operational)
    all_failing = all(
        node not in operational_nodes
        for node in storagenodes
    ) if storagenodes else False
    
    table = Table(
        title="Storage Replicas",
        show_header=False,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
        border_style="red" if all_failing else "cyan",
    )
    table.add_column("Node Name", style="dim")
    table.add_column("Status", justify="right")
    
    for node in sorted(storagenodes):
        tcp_up, tcp_latency = role_tcp_status(node, "storage", survey_results, node_status)
        icmp_latency = get_icmp_latency_from_survey(node, survey_results, "storage")
        
        is_operational = node in operational_nodes

        if is_operational:
            latency_str = f" ({tcp_latency:.0f}ms)" if tcp_latency is not None else ""
            status = Text(f"OK{latency_str}", style="cyan")
        elif tcp_up:
            latency_str = f" ({tcp_latency:.0f}ms)" if tcp_latency is not None else ""
            status = Text(f"OUT{latency_str}", style="yellow")
        else:
            if icmp_latency is not None:
                status = Text(f"DOWN & OUT ({icmp_latency:.0f}ms)", style="red")
            else:
                status = Text("DOWN & OUT", style="red")
        table.add_row(node, status)
    return table


def make_topology_table(
    doc: dict[str, Any],
    n: int,
    expected_nodes: list[str],
    operational_nodes: set[str],
    node_status: dict[str, tuple[bool, float | None]],
    survey_results: dict[str, dict[str, Any]] | None = None,
) -> Table:
    # Check if all nodes in this layer are failing (not operational)
    all_failing = all(
        node_name not in operational_nodes
        for node_name in expected_nodes
    ) if expected_nodes else False
    
    table = Table(
        title=f"Mix Layer {n}",
        show_header=False,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
        border_style="red" if all_failing else "cyan",
    )
    table.add_column("Node Name", style="dim")
    table.add_column("Status", justify="right")

    for node_name in sorted(expected_nodes):
        tcp_up, tcp_latency = role_tcp_status(node_name, "mix", survey_results, node_status)
        icmp_latency = get_icmp_latency_from_survey(node_name, survey_results, "mix")
        
        is_operational = node_name in operational_nodes

        if is_operational:
            latency_str = f" ({tcp_latency:.0f}ms)" if tcp_latency is not None else ""
            status = Text(f"OK{latency_str}", style="cyan")
        elif tcp_up:
            latency_str = f" ({tcp_latency:.0f}ms)" if tcp_latency is not None else ""
            status = Text(f"OUT{latency_str}", style="yellow")
        else:
            if icmp_latency is not None:
                status = Text(f"DOWN & OUT ({icmp_latency:.0f}ms)", style="red")
            else:
                status = Text("DOWN & OUT", style="red")
        table.add_row(node_name, status)

    return table


def make_consensus_info_table(
    doc: dict[str, Any],
    server: dict[str, Any],
    last_consensus: dict[str, Any] | None = None,
) -> Table:
    epoch = doc.get("Epoch", 0)
    has_consensus = epoch > 0
    
    table = Table(
        title="Consensus Information",
        show_header=True,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
        border_style="red" if not has_consensus else "cyan",
    )
    table.add_column("Name", style="dim")
    table.add_column("Value", justify="right")
    table.add_column("UTC Earth Time", justify="right")

    genesis_epoch = doc.get("GenesisEpoch", 0)
    version = doc.get("Version", "N/A")
    pki_sig_scheme = (
        doc.get("PKISignatureScheme")
        or server.get("PKISignatureScheme")
        or "N/A"
    )

    if epoch > 0:
        table.add_row("Epoch", str(epoch), epoch_id_to_time_str(epoch))
        table.add_row(
            "GenesisEpoch", str(genesis_epoch), epoch_id_to_time_str(genesis_epoch)
        )
    else:
        table.add_row(
            "Epoch",
            Text("NO CONSENSUS", style="red"),
            Text("Network may be down", style="red"),
        )
        if last_consensus:
            last_epoch = last_consensus.get("epoch", 0)
            last_time_str = last_consensus.get("epoch_time_str", "")
            saved_at_str = last_consensus.get("saved_at", "")
            table.add_row(
                "Last Known Epoch",
                str(last_epoch),
                last_time_str,
            )
            if saved_at_str:
                try:
                    saved_at = datetime.fromisoformat(
                        saved_at_str.replace("Z", "+00:00")
                    )
                    now = datetime.utcnow().replace(tzinfo=saved_at.tzinfo)
                    delta = now - saved_at
                    hours, remainder = divmod(int(delta.total_seconds()), 3600)
                    minutes, seconds = divmod(remainder, 60)
                    if hours > 0:
                        elapsed = f"{hours}h {minutes}m {seconds}s ago"
                    elif minutes > 0:
                        elapsed = f"{minutes}m {seconds}s ago"
                    else:
                        elapsed = f"{seconds}s ago"
                    table.add_row(
                        "Time Since Consensus",
                        "",
                        Text(elapsed, style="yellow"),
                    )
                except (ValueError, TypeError):
                    pass

    version_str = str(version)
    if version_str != "N/A" and not version_str.startswith("v"):
        version_str = f"v{version_str}"
    table.add_row("PKI Doc Version", version_str, "")
    table.add_row("PKISignatureScheme", str(pki_sig_scheme), "")

    return table


def make_cipher_schemes_table(
    doc: dict[str, Any],
    sphinx_geometry: dict[str, Any],
    server: dict[str, Any],
) -> Table:
    table = Table(
        title="PKI Cryptography",
        show_header=True,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
    )
    table.add_column("Name", style="dim")
    table.add_column("Value", justify="right")

    pki_sig_scheme = (
        doc.get("PKISignatureScheme")
        or server.get("PKISignatureScheme")
        or "N/A"
    )
    wire_kem = (
        server.get("WireKEM")
        or server.get("WireKEMScheme")
        or doc.get("WireKEMScheme")
        or doc.get("WireKEM")
    )
    if not wire_kem:
        wire_kem = "N/A"
    sphinx_nike = sphinx_geometry.get("NIKEName", "N/A")
    sphinx_kem = sphinx_geometry.get("KEMName", "")

    table.add_row("PKI Signature Scheme", str(pki_sig_scheme))
    table.add_row("Wire KEM Scheme", str(wire_kem))
    table.add_row("Sphinx NIKE Scheme", str(sphinx_nike))
    if sphinx_kem:
        table.add_row("Sphinx KEM Scheme", str(sphinx_kem))

    return table


def make_sphinx_geometry_table(sphinx_geometry: dict[str, Any]) -> Table:
    table = Table(
        title="Sphinx Geometry",
        show_header=True,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
    )
    table.add_column("Name", style="dim")
    table.add_column("Value", justify="right")

    fields = [
        "PacketLength",
        "HeaderLength",
        "RoutingInfoLength",
        "PerHopRoutingInfoLength",
        "SURBLength",
        "SphinxPlaintextHeaderLength",
        "PayloadTagLength",
        "ForwardPayloadLength",
        "UserForwardPayloadLength",
        "NextNodeHopLength",
        "SPRPKeyMaterialLength",
        "NIKEName",
        "KEMName",
    ]

    for field in fields:
        value = sphinx_geometry.get(field, "")
        table.add_row(field, str(value))

    return table


def make_pigeonhole_geometry_table(
    pigeonhole_geometry: dict[str, Any],
) -> Table:
    table = Table(
        title="Pigeonhole Geometry",
        show_header=True,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
    )
    table.add_column("Name", style="dim")
    table.add_column("Value", justify="right")

    # Only show fields that actually have values
    fields = [
        "Slots",
        "SlotPayloadLength",
        "MaxPigeonholePayloadLength",
        "MaxPlaintextPayloadLength",
        "CourierQueryWriteLength",
        "CourierQueryReadLength",
        "CourierQueryReplyReadLength",
        "CourierQueryReplyWriteLength",
        "NIKEName",
        "SignatureSchemeName",
    ]

    for field in fields:
        value = pigeonhole_geometry.get(field)
        if value is not None and value != "":
            table.add_row(field, str(value))

    return table


def make_srv_table(doc: dict[str, Any]) -> Table:
    srv = doc.get("SharedRandomValue")
    has_srv = srv is not None
    
    table = Table(
        title="Shared Random Value",
        show_header=True,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
        border_style="cyan" if has_srv else "red",
    )
    table.add_column("Name", style="dim")
    table.add_column("Value", justify="right")

    if srv:
        table.add_row("SharedRandomValue", srv.hex())
    else:
        table.add_row("SharedRandomValue", Text("N/A", style="red"))

    prior = doc.get("PriorSharedRandom", [])
    if prior and len(prior) >= 1:
        table.add_row("PriorSharedRandom0", prior[0].hex())
    if prior and len(prior) >= 2:
        table.add_row("PriorSharedRandom1", prior[1].hex())

    return table


async def do_ping_provider(
    config_path: str,
    service_desc: Any,
    timeout: float = 30.0,
) -> tuple[bool, float | None]:
    """Ping a specific echo provider."""
    thinclient_logger = logging.getLogger("thinclient")
    original_level = thinclient_logger.level
    thinclient_logger.setLevel(logging.WARNING)

    cfg = Config(config_path)
    client = ThinClient(cfg)
    loop = asyncio.get_event_loop()
    try:
        with contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            await asyncio.wait_for(client.start(loop), timeout=10.0)
    except Exception:
        thinclient_logger.setLevel(original_level)
        return False, None
    start_time = time.monotonic()
    try:
        payload = b"hello"
        dest_node, dest_queue = service_desc.to_destination()
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
        payload2 = reply_payload[:len(payload)]
        success = len(payload2) == len(payload) and payload2 == payload
        return success, latency_ms if success else None
    except (asyncio.TimeoutError, Exception):
        return False, None
    finally:
        thinclient_logger.setLevel(original_level)
        client.stop()


async def do_ping_all_providers_parallel(
    config_path: str,
    client: ThinClient,
    timeout: float = 30.0,
) -> dict[str, tuple[bool, float | None]]:
    try:
        service_descs = client.get_services("echo")
    except Exception:
        return {}
    tasks = {
        desc.mix_descriptor.get("Name", "unknown"): do_ping_provider(config_path, desc, timeout)
        for desc in service_descs
    }
    results: dict[str, tuple[bool, float | None]] = {}
    gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
    for name, result in zip(tasks.keys(), gathered):
        if isinstance(result, BaseException):
            results[name] = (False, None)
        else:
            results[name] = result
    return results

async def do_courier_probe(
    config_path: str,
    service_desc: Any,
    timeout: float = 60.0,
) -> tuple[bool, float | None]:
    """Test courier service by sending a write and getting ACK.

    This only tests that the courier responds, not replica connectivity.

    Returns:
        (success, latency_ms) where:
        - (True, latency): Courier responded with ACK
        - (False, None): No response or error
    """
    thinclient_logger = logging.getLogger("thinclient")
    original_level = thinclient_logger.level
    thinclient_logger.setLevel(logging.WARNING)

    cfg = Config(config_path)
    client = ThinClient(cfg)
    loop = asyncio.get_event_loop()

    try:
        with contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            await asyncio.wait_for(client.start(loop), timeout=10.0)
    except Exception:
        thinclient_logger.setLevel(original_level)
        return False, None

    start_time = time.monotonic()
    envelope_hash = None

    try:
        seed = os.urandom(32)
        kp = await client.new_keypair(seed)

        test_payload = f"courier-probe-{time.time_ns()}".encode("ascii")

        try:
            wcr = await client.encrypt_write(
                plaintext=test_payload,
                write_cap=kp.write_cap,
                message_box_index=kp.first_message_index,
            )
        except Exception as e:
            if "error code: 4" in str(e):
                return False, None
            raise

        envelope_hash = wcr.envelope_hash

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

            end_time = time.monotonic()
            latency_ms = (end_time - start_time) * 1000
            await client.cancel_resending_encrypted_message(wcr.envelope_hash)
            envelope_hash = None
            return True, latency_ms

        except asyncio.TimeoutError:
            return False, None

    except Exception:
        return False, None
    finally:
        if envelope_hash is not None:
            try:
                await client.cancel_resending_encrypted_message(envelope_hash)
            except Exception:
                pass
        thinclient_logger.setLevel(original_level)
        client.stop()


async def do_courier_probes_parallel(
    config_path: str,
    client: ThinClient,
    timeout: float = 60.0,
) -> dict[str, tuple[bool, float | None]]:
    """Probe all courier providers in parallel.
    
    Returns dict mapping provider_name -> (success, latency_ms)
    """
    try:
        service_descs = client.get_services("courier")
    except Exception:
        return {}
    
    if not service_descs:
        return {}
    
    tasks = {
        desc.mix_descriptor.get("Name", "unknown"): do_courier_probe(config_path, desc, timeout)
        for desc in service_descs
    }
    
    results: dict[str, tuple[bool, float | None]] = {}
    gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
    for name, result in zip(tasks.keys(), gathered):
        if isinstance(result, BaseException):
            results[name] = (False, None)
        else:
            results[name] = result
    
    return results

async def do_replica_probe(
    config_path: str,
    service_desc: Any,
    timeout: float = 60.0,
) -> tuple[bool, float | None]:
    """Test courier->replica connectivity via write/read round-trip.

    Returns:
        (success, latency_ms) where:
        - (True, latency): Full round-trip succeeded
        - (False, latency): Courier ACK received but no replica data
        - (False, None): Complete failure
    """
    thinclient_logger = logging.getLogger("thinclient")
    original_level = thinclient_logger.level
    thinclient_logger.setLevel(logging.WARNING)

    cfg = Config(config_path)
    client = ThinClient(cfg)
    loop = asyncio.get_event_loop()

    try:
        with contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            await asyncio.wait_for(client.start(loop), timeout=10.0)
    except Exception:
        thinclient_logger.setLevel(original_level)
        return False, None

    start_time = time.monotonic()
    got_write_ack = False
    write_envelope_hash = None
    read_envelope_hash = None

    try:
        seed = os.urandom(32)
        kp = await client.new_keypair(seed)

        test_id = f"replica-probe-{time.time_ns()}"
        test_payload = test_id.encode("ascii")

        try:
            wcr = await client.encrypt_write(
                plaintext=test_payload,
                write_cap=kp.write_cap,
                message_box_index=kp.first_message_index,
            )
        except Exception as e:
            if "error code: 4" in str(e):
                return False, None
            raise

        write_envelope_hash = wcr.envelope_hash

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
            got_write_ack = True
        except asyncio.TimeoutError:
            return False, None

        await client.cancel_resending_encrypted_message(wcr.envelope_hash)
        write_envelope_hash = None

        # Wait for replication
        await asyncio.sleep(10.0)

        # Read phase
        max_retries = 3
        retry_delay = 10.0

        for attempt in range(max_retries):
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
                        timeout=timeout,
                    )

                await client.cancel_resending_encrypted_message(rcr.envelope_hash)
                read_envelope_hash = None

                if read_result is not None and read_result.plaintext is not None:
                    end_time = time.monotonic()
                    latency_ms = (end_time - start_time) * 1000
                    return True, latency_ms

            except asyncio.TimeoutError:
                if read_envelope_hash is not None:
                    try:
                        await client.cancel_resending_encrypted_message(rcr.envelope_hash)
                    except Exception:
                        pass
                    read_envelope_hash = None

            if attempt < max_retries - 1:
                await asyncio.sleep(retry_delay)

        # Got courier ACK but no replica data
        if got_write_ack:
            end_time = time.monotonic()
            latency_ms = (end_time - start_time) * 1000
            return False, latency_ms

        return False, None

    except Exception:
        if got_write_ack:
            end_time = time.monotonic()
            latency_ms = (end_time - start_time) * 1000
            return False, latency_ms
        return False, None
    finally:
        for eh in (write_envelope_hash, read_envelope_hash):
            if eh is not None:
                try:
                    await client.cancel_resending_encrypted_message(eh)
                except Exception:
                    pass
        thinclient_logger.setLevel(original_level)
        client.stop()


async def do_replica_probes_parallel(
    config_path: str,
    client: ThinClient,
    replica_names: list[str],
    timeout: float = 160.0,
) -> dict[str, tuple[bool, float | None]]:
    """Probe courier->replica paths with separate probes for each replica.
    
    Returns dict mapping "{courier}->{replica}" -> (success, latency_ms)
    """
    try:
        service_descs = client.get_services("courier")
    except Exception:
        return {}
    
    if not service_descs:
        return {}
    
    if not replica_names:
        return {}
    
    # Run separate probe for EACH courier->replica combination
    tasks: dict[str, Any] = {}
    for desc in service_descs:
        courier_name = desc.mix_descriptor.get("Name", "unknown")
        for replica_name in replica_names:
            key = f"{courier_name}->{replica_name}"
            # Each probe is independent
            tasks[key] = do_replica_probe(config_path, desc, timeout)
    
    results: dict[str, tuple[bool, float | None]] = {}
    gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
    for key, result in zip(tasks.keys(), gathered):
        if isinstance(result, BaseException):
            results[key] = (False, None)
        else:
            results[key] = result
    
    return results

def pretty_print_pki_doc(doc: dict[str, Any]) -> str:
    lines: list[str] = []

    def format_value(value: Any, indent: int = 0) -> str:
        prefix = "  " * indent
        if isinstance(value, bytes):
            return value.hex()
        elif isinstance(value, dict):
            if not value:
                return "{}"
            sub_lines = ["{"]
            for k, v in value.items():
                sub_lines.append(f"{prefix}  {k}: {format_value(v, indent + 1)}")
            sub_lines.append(f"{prefix}}}")
            return "\n".join(sub_lines)
        elif isinstance(value, list):
            if not value:
                return "[]"
            if all(isinstance(x, bytes) for x in value):
                sub_lines = ["["]
                for item in value:
                    sub_lines.append(f"{prefix}    {item.hex()}")
                sub_lines.append(f"{prefix}]")
                return "\n".join(sub_lines)
            return str(value)
        else:
            s = str(value)
            # Normalize multiple consecutive newlines to single newlines
            while '\n\n' in s:
                s = s.replace('\n\n', '\n')
            return s

    skip_keys = {"GatewayNodes", "ServiceNodes", "StorageReplicas", "Topology", "Signatures"}

    for key, value in doc.items():
        if key in skip_keys:
            continue
        lines.append(f"{key}: {format_value(value)}")

    for category in ["GatewayNodes", "ServiceNodes", "StorageReplicas"]:
        nodes = doc.get(category, [])
        if nodes:
            lines.append(f"{category}:")
            for raw_node in nodes:
                node = decode_node(raw_node)
                name = node.get("Name", "unknown")
                lines.append(f"  - {name}:")
                for k, v in node.items():
                    if k != "Name":
                        lines.append(f"      {k}: {format_value(v, 3)}")

    topology = doc.get("Topology", [])
    if topology:
        lines.append("Topology:")
        for layer_idx, layer in enumerate(topology):
            lines.append(f"  Layer {layer_idx}:")
            for raw_node in layer:
                node = decode_node(raw_node)
                name = node.get("Name", "unknown")
                lines.append(f"    - {name}:")
                for k, v in node.items():
                    if k != "Name":
                        lines.append(f"        {k}: {format_value(v, 4)}")

    return "\n".join(lines)

def make_pki_doc_panel(doc: dict[str, Any], has_consensus: bool = True) -> Panel:
    epoch = doc.get("Epoch", 0)
    if epoch > 0:
        pki_text = pretty_print_pki_doc(doc)
        content: RenderableType = Text(pki_text, style="dim")
    else:
        content = Align.center(Text("No consensus document", style="red"))
    
    # Border is red if no consensus
    border_style = "cyan" if has_consensus else "red"
    return Panel(
        content,
        title="PKI Document",
        title_align="left",
        border_style=border_style,
    )


def make_footer(network_name: str) -> Text:
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    return Text(
        f"{network_name} status - Generated: {now} - v{__version__}",
        style="dim",
        justify="center",
    )


def generate_report(
    doc: dict[str, Any],
    dirauthconf: str,
    output_file: str | None = None,
    service_probes: ServiceProbeResults | None = None,
    conn_status: ConnectionStatus | None = None,
    dirauth_status: dict[str, tuple[bool, float | None]] | None = None,
    node_status: dict[str, tuple[bool, float | None]] | None = None,
    network_name: str = "namenlos",
    show_pki_doc: bool = False,
    survey_results: dict[str, dict[str, Any]] | None = None,
    quiet: bool = False,
    last_consensus: dict[str, Any] | None = None,
    pigeonhole_geometry: dict[str, Any] | None = None,
) -> None:
    if conn_status is None:
        conn_status = ConnectionStatus()
    if pigeonhole_geometry is None:
        pigeonhole_geometry = {}
    if dirauth_status is None:
        dirauth_status = {}
    if node_status is None:
        node_status = {}
    if service_probes is None:
        service_probes = {}

    width = 160 if output_file else None

    if quiet:
        console = Console(
            file=io.StringIO(),
            record=True,
            width=width,
            force_terminal=True,
        )
    else:
        console = Console(
            record=bool(output_file),
            width=width,
            force_terminal=True,
        )

    dirauth_data = parse_dirauth_config(dirauthconf)
    server = dirauth_data["server"]
    sphinx_geometry = dirauth_data["sphinx_geometry"]
    config_params = dirauth_data.get("parameters", {})
    authorities = dirauth_data["authorities"]
    mixes = dirauth_data["mixes"]
    gateways = dirauth_data["gateways"]
    servicenodes = dirauth_data["servicenodes"]
    storagenodes = dirauth_data["storagenodes"]
    topology_layers = dirauth_data["topology_layers"]
    
    # Also include storage nodes from survey results (address cache)
    # These may not be in the PKI document yet
    if survey_results:
        for key, data in survey_results.items():
            if data.get("node_type") == "storage":
                node_name = data.get("name", "")
                if node_name:
                    storagenodes.add(node_name)

    capabilities = get_services_by_capability(doc)
    storage_replica_names = [
        decode_node(n).get("Name", f"replica{i}")
        for i, n in enumerate(doc.get("StorageReplicas", []))
    ]
    capabilities["_storage_replicas"] = storage_replica_names

    epoch = doc.get("Epoch", 0)
    has_consensus = epoch > 0

    # Merge survey_results into node_status for accurate TCP status
    # Survey results are more comprehensive and should override PKI-based probing
    # Aggregate by node name - if ANY address succeeds, node is considered up
    if survey_results:
        for key, data in survey_results.items():
            node_name = data.get("name", "")
            if not node_name:
                continue
            tcp = data.get("tcp_traceroute", {})
            tcp_ok = tcp.get("reachable", False) if tcp else False
            tcp_latency = tcp.get("final_latency_ms") if tcp else None
            if isinstance(tcp_latency, (int, float)):
                tcp_latency = float(tcp_latency)
            else:
                tcp_latency = None
            
            # Aggregate: if any address succeeds, node is up (keep best latency)
            if node_name in node_status:
                existing_ok, existing_latency = node_status[node_name]
                if tcp_ok and not existing_ok:
                    # New success replaces previous failure
                    node_status[node_name] = (tcp_ok, tcp_latency)
                elif tcp_ok and existing_ok:
                    # Both successful, prefer lower latency
                    if tcp_latency is not None and (existing_latency is None or tcp_latency < existing_latency):
                        node_status[node_name] = (tcp_ok, tcp_latency)
                # If existing is up and new is down, keep existing (success)
            else:
                node_status[node_name] = (tcp_ok, tcp_latency)

    consensus_table = make_consensus_info_table(doc, server, last_consensus)

    status_table = make_status_table(
        authorities, mixes, gateways, servicenodes, storagenodes
    )

    connection_table = make_connection_status_table(conn_status, has_consensus)

    outage_tables = make_outage_reports(
        doc, mixes, gateways, servicenodes, storagenodes, dirauth_status, node_status, survey_results
    )
    outages_panel: Panel | None = None
    if outage_tables:
        outages_content: RenderableType
        if len(outage_tables) == 1:
            outages_content = Align.center(outage_tables[0])
        else:
            centered_outages = [Align.center(t) for t in outage_tables]
            outages_content = Columns(
                centered_outages, equal=True, expand=True
            )
        outages_panel = Panel(
            outages_content,
            title="Outages",
            title_align="left",
            border_style="red",
        )

    # Build status content - all tables stacked vertically (one per row)
    status_content: list[RenderableType] = [
        Align.center(consensus_table),
        Align.center(status_table),
    ]

    if has_consensus:
        services_table = make_services_table(capabilities)
        status_content.append(Align.center(services_table))

    status_content.append(Align.center(connection_table))

    if has_consensus:
        ping_table = make_ping_table(service_probes, capabilities, survey_results)
        status_content.append(Align.center(ping_table))
    if outages_panel:
        status_content.append(outages_panel)

    # Status section border: cyan if consensus, red if no consensus
    status_border = "cyan" if has_consensus else "red"

    status_section = Panel(
        Group(*status_content),
        title="Status and Health",
        title_align="left",
        border_style=status_border,
    )

    operational_nodes = get_operational_nodes(doc)
    dirauth_table = make_dirauth_table(authorities, dirauth_status, has_consensus)
    gateway_table = make_gateway_table(gateways, operational_nodes, node_status, survey_results)
    servicenode_table = make_service_table(servicenodes, operational_nodes, node_status, survey_results)
    storage_table = make_storage_table(storagenodes, operational_nodes, node_status, survey_results)

    layer_tables: list[Table] = []
    for i, layer_nodes in enumerate(topology_layers):
        table = make_topology_table(doc, i, layer_nodes, operational_nodes, node_status, survey_results)
        layer_tables.append(table)

    # Layout: all tables stacked vertically (dirauths, gateways, layers, service, storage)
    topology_content: list[RenderableType] = []
    for layer_table in layer_tables:
        topology_content.append(Align.center(layer_table))

    # Service nodes and storage replicas stacked vertically
    service_storage_content: list[RenderableType] = [Align.center(servicenode_table)]
    if storagenodes:
        service_storage_content.append(Align.center(storage_table))

    # Determine if any nodes are down for Network Nodes Summary border
    # Check all configured nodes against operational nodes and TCP status
    any_node_down = False
    any_node_out = False
    
    # Check mixes, gateways, servicenodes, storagenodes
    all_config_nodes = mixes | gateways | servicenodes | storagenodes
    for node_name in all_config_nodes:
        is_operational = node_name in operational_nodes
        tcp_up = node_status.get(node_name, (False, None))[0]
        if not is_operational:
            if not tcp_up:
                any_node_down = True
            else:
                any_node_out = True
    
    # Also check dirauths
    for name, (is_up, _) in dirauth_status.items():
        if not is_up:
            any_node_down = True
    
    if any_node_down:
        nodes_border = "red"
    elif any_node_out:
        nodes_border = "yellow"
    else:
        nodes_border = "cyan"

    nodes_section = Panel(
        Group(
            Align.center(dirauth_table),
            Align.center(gateway_table),
            *topology_content,
            *service_storage_content,
        ),
        title="Network Nodes Summary",
        title_align="left",
        border_style=nodes_border,
    )

    ciphers_table = make_cipher_schemes_table(doc, sphinx_geometry, server)
    network_params_table = make_network_params_table(
        doc, sphinx_geometry, pigeonhole_geometry, config_params
    )
    sphinx_table = make_sphinx_geometry_table(sphinx_geometry)
    srv_table = make_srv_table(doc)

    # All crypto tables stacked vertically
    crypto_content: list[RenderableType] = [Align.center(sphinx_table)]
    if pigeonhole_geometry:
        pigeonhole_table = make_pigeonhole_geometry_table(pigeonhole_geometry)
        crypto_content.append(Align.center(pigeonhole_table))
    crypto_content.append(Align.center(network_params_table))
    crypto_content.append(Align.center(ciphers_table))
    crypto_content.append(Align.center(srv_table))

    crypto_section = Panel(
        Group(*crypto_content),
        title="Cryptography and Parameters",
        title_align="left",
        border_style="cyan",
    )

    footer = make_footer(network_name)

    sections: list[RenderableType] = [
        status_section,
        nodes_section,
        crypto_section,
    ]

    if survey_results:
        survey_table = make_survey_table(survey_results, operational_nodes)

        sorted_items = sorted(
            survey_results.items(),
            key=lambda x: (x[1].get("name", ""), x[1].get("node_type", "")),
        )

        # Build trace tables with consistent formatting
        trace_tables: list[Table] = []
        for key, data in sorted_items:
            trace_table = make_traceroute_detail_table(key, data, operational_nodes)
            trace_tables.append(trace_table)

        survey_content: list[RenderableType] = [Align.center(survey_table)]

        if trace_tables:
            # Stack tables vertically in rows of 3
            TABLES_PER_ROW = 3
            trace_rows: list[RenderableType] = []
            
            for i in range(0, len(trace_tables), TABLES_PER_ROW):
                row_tables = trace_tables[i:i + TABLES_PER_ROW]
                if len(row_tables) == 1:
                    trace_rows.append(Align.center(row_tables[0]))
                else:
                    trace_rows.append(Columns(row_tables, equal=True, expand=True))

            # Determine trace panel border based on node status
            trace_border = "red" if any_node_down else ("yellow" if any_node_out else "grey70")
            trace_panel = Panel(
                Group(*trace_rows),
                title="Network path details",
                title_align="left",
                border_style=trace_border,
            )
            survey_content.append(trace_panel)

        # Survey panel border based on whether any TCP connections failed
        any_tcp_failed = any(
            not data.get("tcp_traceroute", {}).get("reachable", False)
            for data in survey_results.values()
        )
        survey_border = "red" if any_tcp_failed else "cyan"
        
        survey_panel = Panel(
            Group(*survey_content),
            title="Network Survey",
            title_align="left",
            border_style=survey_border,
        )
        sections.append(survey_panel)

    if show_pki_doc:
        pki_panel = make_pki_doc_panel(doc, has_consensus)
        sections.append(pki_panel)

    sections.append(Align.center(footer))

    # Outer panel border: cyan if consensus, red if no consensus
    outer_border = "bold cyan" if has_consensus else "bold red"
    outer_panel = Panel(
        Group(*sections),
        title=network_name,
        title_align="center",
        border_style=outer_border,
    )

    console.print(outer_panel)

    if output_file:
        html = console.export_html(inline_styles=True, theme=MONOKAI)
        with open(output_file, "w", encoding="utf-8") as file:
            file.write(html)


async def _collect_network_data(
    ctx: click.Context,
    cache_path: Path,
) -> tuple[
    dict[str, Any],
    ConnectionStatus,
    dict[str, tuple[bool, float | None]],
    dict[str, tuple[bool, float | None]],
    ThinClient | None,
    dict[str, Any],
]:
    config_path: str = ctx.obj["config_path"]
    dirauthconf: str = ctx.obj["dirauthconf"]
    connect_timeout: float = ctx.obj["timeout"]
    verbose: bool = ctx.obj.get("verbose", False)

    conn_status = ConnectionStatus()

    dirauth_data = parse_dirauth_config(dirauthconf)
    dirauth_addresses = dirauth_data["dirauth_addresses"]

    dirauth_status = await probe_dirauths(dirauth_addresses, timeout=connect_timeout)

    thinclient_data = parse_thinclient_config(config_path)
    network = thinclient_data.get("network", "tcp")
    address = thinclient_data.get("address", "localhost:64331")

    # Suppress thinclient debug output - capture to buffer for error reporting
    thinclient_logger = logging.getLogger("thinclient")
    original_level = thinclient_logger.level
    thinclient_logger.setLevel(logging.WARNING)

    # Capture stdout/stderr from thinclient library
    captured_output = io.StringIO()

    cfg = Config(config_path)
    client = ThinClient(cfg)
    loop = asyncio.get_event_loop()
    client_started = False

    if verbose:
        click.echo(f"Connecting to kpclientd at {network}://{address}...")

    try:
        with contextlib.redirect_stdout(captured_output), \
             contextlib.redirect_stderr(captured_output):
            await asyncio.wait_for(client.start(loop), timeout=connect_timeout)
        conn_status.daemon_connected = True
        client_started = True
        if verbose:
            click.echo("  Socket: OK")
    except asyncio.TimeoutError:
        conn_status.daemon_connected = False
        conn_status.error_message = f"Connection to daemon timed out ({network}://{address})"
        if verbose:
            click.echo(f"  Socket: TIMEOUT after {connect_timeout}s")
            output = captured_output.getvalue()
            if output.strip():
                click.echo(f"  Thinclient output:\n{output}")
    except Exception as e:
        error_str = str(e).strip()
        if not error_str:
            conn_status.daemon_connected = True
            conn_status.network_online = False
            if verbose:
                click.echo("  Socket: OK (daemon offline)")
        else:
            conn_status.daemon_connected = False
            conn_status.error_message = f"{e} ({network}://{address})"
            if verbose:
                click.echo(f"  Socket: FAILED - {e}")
                output = captured_output.getvalue()
                if output.strip():
                    click.echo(f"  Thinclient output:\n{output}")

    doc: dict[str, Any] = {}
    node_status: dict[str, tuple[bool, float | None]] = {}

    if conn_status.daemon_connected:
        doc = client.pki_document() or {}
        epoch = doc.get("Epoch", 0)
        if verbose:
            if epoch > 0:
                click.echo(f"  Consensus: OK (epoch {epoch})")
            else:
                click.echo("  Consensus: NONE")
        if doc.get("Topology") and len(doc.get("Topology", [])) > 0:
            conn_status.network_online = True
            if verbose:
                click.echo("  Network: ONLINE")
        else:
            conn_status.network_online = False
            if verbose:
                click.echo("  Network: OFFLINE")

        pki_node_addresses = get_node_addresses_from_pki(doc)
        if pki_node_addresses:
            node_status = await probe_all_nodes(
                pki_node_addresses, timeout=connect_timeout
            )

    # Restore thinclient logger level
    thinclient_logger.setLevel(original_level)

    # The daemon delivers the Pigeonhole geometry over the handshake, so
    # it is available on the client once start() has returned.
    pigeonhole_geometry: dict[str, Any] = {}
    if client_started:
        pigeonhole_geometry = pigeonhole_geometry_to_dict(
            getattr(client, "pigeonhole_geometry", None)
        )

    return (
        doc,
        conn_status,
        dirauth_status,
        node_status,
        client if client_started else None,
        pigeonhole_geometry,
    )


async def _async_main_inner(ctx: click.Context) -> None:
    dirauthconf: str = ctx.obj["dirauthconf"]
    config_path: str = ctx.obj["config_path"]
    htmlout: str = ctx.obj["htmlout"]
    network_name: str = ctx.obj["network_name"]
    show_pki_doc: bool = ctx.obj["pki_document"]
    run_survey: bool = ctx.obj["survey"]
    ping_enabled: bool = ctx.obj["ping"]
    max_threads: int = ctx.obj["max_threads"]
    cache_file: str = ctx.obj["cache_file"]
    verbose: bool = ctx.obj["verbose"]
    quiet: bool = ctx.obj["quiet"]

    cache_path = get_cache_path(cache_file if cache_file else None)

    if verbose:
        doc, conn_status, dirauth_status, node_status, client, pigeonhole_geometry = (
            await _collect_network_data(ctx, cache_path)
        )
    else:
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            doc, conn_status, dirauth_status, node_status, client, pigeonhole_geometry = (
                await _collect_network_data(ctx, cache_path)
            )

    last_consensus = load_last_consensus(cache_path)
    epoch = doc.get("Epoch", 0)
    if epoch > 0:
        epoch_time_str = epoch_id_to_time_str(epoch)
        save_last_consensus(epoch, epoch_time_str, cache_path)

    survey_results: dict[str, dict[str, Any]] | None = None
    service_probes: ServiceProbeResults = {}
    all_targets: list[SurveyTarget] = []

    if run_survey:
        dirauth_data = parse_dirauth_config(dirauthconf)
        config_targets = build_survey_targets_from_config(dirauth_data)
        pki_targets = build_survey_targets_from_pki(doc)
        cached_targets = load_typed_address_cache(cache_path, verbose=verbose)

        seen: set[tuple[str, str, str, int]] = set()
        for target in config_targets + pki_targets + cached_targets:
            key = (target[0], target[1], target[2], target[3])
            if key not in seen:
                seen.add(key)
                all_targets.append(target)

        # Track which (name, type) combinations have real addresses
        has_address: set[tuple[str, str]] = set()
        for name, node_type, host, port in all_targets:
            if host and port > 0:
                has_address.add((name, node_type))

        # Add UNKNOWN entries for configured nodes without addresses
        for name in dirauth_data.get("authorities", set()):
            if (name, "dirauth") not in has_address:
                all_targets.append((name, "dirauth", "", 0))

        for name in dirauth_data.get("gateways", set()):
            if (name, "gateway") not in has_address:
                all_targets.append((name, "gateway", "", 0))

        for name in dirauth_data.get("servicenodes", set()):
            if (name, "service") not in has_address:
                all_targets.append((name, "service", "", 0))

        for name in dirauth_data.get("storagenodes", set()):
            if (name, "storage") not in has_address:
                all_targets.append((name, "storage", "", 0))

        topology_layers = dirauth_data.get("topology_layers", [])
        for layer_idx, layer_nodes in enumerate(topology_layers):
            layer_type = f"mix-L{layer_idx}"
            for name in layer_nodes:
                if (name, layer_type) not in has_address:
                    all_targets.append((name, layer_type, "", 0))

        if config_targets:
            save_typed_address_cache(config_targets, cache_path)
        if pki_targets:
            save_typed_address_cache(pki_targets, cache_path)

    async def run_survey_async() -> dict[str, dict[str, Any]] | None:
        if not all_targets:
            return None
        if verbose and not quiet:
            click.echo(f"Running survey on {len(all_targets)} node endpoints...")
        return await asyncio.to_thread(
            run_survey_parallel, all_targets, True, verbose and not quiet, max_threads
        )

    # Get storage replica names from PKI for replica probes
    storage_replica_names = [
        decode_node(n).get("Name", f"replica{i}")
        for i, n in enumerate(doc.get("StorageReplicas", []))
    ]

    async def run_echo_probes_async() -> dict[str, tuple[bool, float | None]]:
        if not (ping_enabled and client):
            return {}
        return await do_ping_all_providers_parallel(config_path, client, timeout=30.0)

    async def run_courier_probes_async() -> dict[str, tuple[bool, float | None]]:
        if not (ping_enabled and client):
            return {}
        return await do_courier_probes_parallel(config_path, client, timeout=60.0)

    async def run_replica_probes_async() -> dict[str, tuple[bool, float | None]]:
        if not (ping_enabled and client):
            return {}
        if not storage_replica_names:
            return {}
        return await do_replica_probes_parallel(
            config_path, client, storage_replica_names, timeout=160.0
        )

    survey_results, echo_results, courier_results, replica_results = await asyncio.gather(
        run_survey_async(), run_echo_probes_async(), run_courier_probes_async(), run_replica_probes_async()
    )
    if echo_results:
        service_probes["echo"] = echo_results
        if any(ok for ok, _ in echo_results.values()):
            conn_status.network_online = True
    if courier_results:
        service_probes["courier"] = courier_results
        if any(ok for ok, _ in courier_results.values()):
            conn_status.network_online = True
    if replica_results:
        service_probes["replica"] = replica_results
        # Check if any replica probe succeeded or got ACK
        if any(ok or (lat is not None) for ok, lat in replica_results.values()):
            conn_status.network_online = True

    if client:
        client.stop()

    generate_report(
        doc,
        dirauthconf,
        output_file=htmlout or None,
        service_probes=service_probes,
        conn_status=conn_status,
        dirauth_status=dirauth_status,
        node_status=node_status,
        network_name=network_name,
        show_pki_doc=show_pki_doc,
        survey_results=survey_results,
        quiet=quiet,
        last_consensus=last_consensus,
        pigeonhole_geometry=pigeonhole_geometry,
    )

async def async_main(ctx: click.Context) -> None:
    await _async_main_inner(ctx)


@click.command()
@click.option(
    "--config",
    "config_path",
    required=True,
    help="Path to the thin client TOML config file.",
)
@click.option(
    "--htmlout",
    default="",
    help="Path to output HTML file.",
)
@click.option(
    "--dirauthconf",
    required=True,
    help="Path to the directory authority configuration TOML file.",
)
@click.option(
    "--network-name",
    "network_name",
    default="namenlos",
    help="Name of the network deployment (outer panel title).",
)
@click.option(
    "--ping/--no-ping",
    default=False,
    help="Send a ping via echo service and show result.",
)
@click.option(
    "--timeout",
    default=10.0,
    type=float,
    help="Connection timeout in seconds (default: 10).",
)
@click.option(
    "--pki-document",
    is_flag=True,
    help="Include the full PKI document in output.",
)
@click.option(
    "--survey",
    is_flag=True,
    help="Run network survey (ICMP ping and TCP traceroute to all nodes).",
)
@click.option(
    "--threads",
    "max_threads",
    type=int,
    default=20,
    help="Maximum number of threads for parallel survey (default: 20).",
)
@click.option(
    "--cache-file",
    "cache_file",
    default="",
    help="Path to address cache file (default: ~/.cache/katzenpost-status/address_cache.json).",
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Verbose output (debug logging).",
)
@click.option(
    "--quiet",
    is_flag=True,
    help="Suppress all console output.",
)
@click.version_option(version=__version__, prog_name="katzenpost-status")
@click.pass_context
def main(
    ctx: click.Context,
    config_path: str,
    dirauthconf: str,
    network_name: str,
    htmlout: str,
    ping: bool,
    timeout: float,
    pki_document: bool,
    survey: bool,
    max_threads: int,
    cache_file: str,
    verbose: bool,
    quiet: bool,
) -> None:
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config_path
    ctx.obj["dirauthconf"] = dirauthconf
    ctx.obj["network_name"] = network_name
    ctx.obj["htmlout"] = htmlout
    ctx.obj["ping"] = ping
    ctx.obj["timeout"] = timeout
    ctx.obj["pki_document"] = pki_document
    ctx.obj["survey"] = survey
    ctx.obj["max_threads"] = max_threads
    ctx.obj["cache_file"] = cache_file
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet

    if verbose and not quiet:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(levelname)s:%(name)s:%(message)s",
        )
        # Suppress noisy library loggers even in verbose mode
        logging.getLogger("thinclient").setLevel(logging.WARNING)
        logging.getLogger("asyncio").setLevel(logging.WARNING)

    asyncio.run(async_main(ctx))


if __name__ == "__main__":
    main()
