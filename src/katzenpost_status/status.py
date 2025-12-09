# SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

import asyncio
import contextlib
import io
import json
import logging
import subprocess
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

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
    dirauth_addresses: dict[str, tuple[str, int]],
    timeout: float = 5.0,
) -> dict[str, tuple[bool, float | None]]:
    names = list(dirauth_addresses.keys())
    tasks = [
        probe_tcp(host, port, timeout)
        for host, port in dirauth_addresses.values()
    ]
    results_list = await asyncio.gather(*tasks)
    return dict(zip(names, results_list))


async def probe_all_nodes(
    node_addresses: dict[str, tuple[str, int]],
    timeout: float = 5.0,
) -> dict[str, tuple[bool, float | None]]:
    names = list(node_addresses.keys())
    tasks = [
        probe_tcp(host, port, timeout)
        for host, port in node_addresses.values()
    ]
    results_list = await asyncio.gather(*tasks)
    return dict(zip(names, results_list))


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
                if isinstance(data, list) and len(data) > 0:
                    first = data[0]
                    if isinstance(first, (list, tuple)) and len(first) == 4:
                        return [
                            (str(item[0]), str(item[1]), str(item[2]), int(item[3]))
                            for item in data
                            if isinstance(item, (list, tuple)) and len(item) == 4
                        ]
                if verbose:
                    click.echo(f"Old cache format detected, clearing: {data}")
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
    existing_set: set[tuple[str, str, str, int]] = set()
    for t in existing:
        existing_set.add((t[0], t[1], t[2], t[3]))
    for target in targets:
        existing_set.add((target[0], target[1], target[2], target[3]))
    with open(cache_path, "w") as f:
        json.dump([list(t) for t in existing_set], f, indent=2)


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
    try:
        proc = subprocess.run(
            [
                "tcptraceroute",
                "-w", str(timeout),
                "-n",
                "-m", str(max_hops),
                host,
                str(port),
            ],
            capture_output=True,
            text=True,
            timeout=max_hops * timeout + 10,
        )
        for line in proc.stdout.splitlines():
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
    except subprocess.TimeoutExpired:
        result["error"] = "timeout"
    except FileNotFoundError:
        result["error"] = "tcptraceroute not found"
    except Exception as e:
        result["error"] = str(e)
    return result


def _survey_single_target(
    target: SurveyTarget,
    run_traceroute: bool = True,
) -> tuple[str, dict[str, Any]]:
    name, node_type, host, port = target
    key = f"{name}|{node_type}"
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
                    click.echo(
                        f"  [{node_type:10}] {name:15} {host}:{port} "
                        f"ICMP={icmp_ok} TCP={tcp_ok}"
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
                        f"  [{node_type:10}] {name:15} {host}:{port} ERROR: {e}"
                    )

    return results


def make_survey_table(survey_results: dict[str, dict[str, Any]]) -> Table:
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
        if is_unknown:
            host_display = Text("UNKNOWN", style="red")
            port_display = Text("-", style="dim")
        else:
            host_display = Text(host, style="dim")
            port_display = Text(str(port))

        tcp = data.get("tcp_traceroute", {})
        tcp_reachable = tcp.get("reachable", False) if tcp else False

        icmp = data.get("icmp_ping", {})
        if is_unknown:
            icmp_status = Text("UNKNOWN", style="red")
        elif icmp.get("reachable"):
            latency = icmp.get("latency_ms")
            if latency is not None:
                icmp_status = Text(f"OK ({latency:.1f}ms)", style="cyan")
            else:
                icmp_status = Text("OK", style="cyan")
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
            hop_count = Text("-", style="dim")
        elif tcp:
            if tcp.get("reachable"):
                latency = tcp.get("final_latency_ms")
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
            hop_count = Text(str(len(tcp.get("hops", []))))
        else:
            tcp_status = Text("N/A", style="dim")
            hop_count = Text("-", style="dim")

        table.add_row(
            name, node_type, host_display, port_display,
            icmp_status, tcp_status, hop_count
        )

    return table


def make_traceroute_detail_table(
    key: str,
    data: dict[str, Any],
) -> Table:
    name = data.get("name", key.split("|")[0] if "|" in key else key)
    node_type = data.get("node_type", "")
    host = data.get("host", "")
    port = data.get("port", 0)
    trace_data = data.get("tcp_traceroute", {})

    is_unknown = host == "unknown" or host == ""
    if is_unknown:
        addr_str = "UNKNOWN"
    else:
        addr_str = f"{host}:{port}"

    title = f"{name} ({node_type})\n{addr_str}"
    table = Table(
        title=title,
        show_header=True,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
    )
    table.add_column("Hop", justify="right", min_width=3)
    table.add_column("IP Address", justify="left", min_width=15)
    table.add_column("Latency", justify="right", min_width=8)

    hops = trace_data.get("hops", [])
    if hops:
        for hop in hops:
            hop_num = Text(str(hop.get("hop", "")), style="dim")
            ip = Text(hop.get("ip") or "*", style="dim")
            latency = hop.get("latency_ms")
            if latency is not None:
                latency_str = Text(f"{latency:.1f}ms", style="cyan")
            else:
                latency_str = Text("*", style="dim")
            table.add_row(hop_num, ip, latency_str)
    else:
        error = trace_data.get("error", "")
        if error == "address unknown" or is_unknown:
            table.add_row(Text("-", style="dim"), Text("UNKNOWN", style="red"), Text("-", style="dim"))
        elif error:
            table.add_row(Text("-", style="dim"), Text(f"Error: {error}", style="red"), Text("-", style="dim"))
        else:
            table.add_row(Text("-", style="dim"), Text("No path data", style="dim"), Text("-", style="dim"))

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

    def extract_addresses(
        nodes: list[dict[str, Any]],
    ) -> dict[str, tuple[str, int]]:
        addresses: dict[str, tuple[str, int]] = {}
        for node in nodes:
            name = node.get("Identifier", "")
            addr_list = node.get("Addresses", [])
            if addr_list and name:
                result = parse_host_port(addr_list[0])
                if result:
                    addresses[name] = result
        return addresses

    dirauth_addresses = extract_addresses(config.get("Authorities", []))
    mix_addresses = extract_addresses(config.get("Mixes", []))
    gateway_addresses = extract_addresses(config.get("GatewayNodes", []))
    servicenode_addresses = extract_addresses(config.get("ServiceNodes", []))
    storagenode_addresses = extract_addresses(config.get("StorageNodes", []))

    mixes = {mix["Identifier"] for mix in config.get("Mixes", [])}
    gateways = {
        node["Identifier"] for node in config.get("GatewayNodes", [])
    }
    servicenodes = {
        node["Identifier"] for node in config.get("ServiceNodes", [])
    }
    storagenodes = {
        node["Identifier"] for node in config.get("StorageNodes", [])
    }
    sphinx_geometry = config["SphinxGeometry"]
    server = config["Server"]

    topology_layers: list[list[str]] = []
    topology_addresses: dict[str, tuple[str, int]] = {}
    topology_config = config.get("Topology", {})
    layers_config = topology_config.get("Layers", [])
    for layer in layers_config:
        layer_nodes = []
        for node in layer.get("Nodes", []):
            name = node.get("Identifier", "")
            if name:
                layer_nodes.append(name)
                addr_list = node.get("Addresses", [])
                if addr_list:
                    result = parse_host_port(addr_list[0])
                    if result:
                        topology_addresses[name] = result
        topology_layers.append(layer_nodes)

    return {
        "server": server,
        "sphinx_geometry": sphinx_geometry,
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

    for name, (host, port) in dirauth_data.get("dirauth_addresses", {}).items():
        targets.append((name, "dirauth", host, port))

    for name, (host, port) in dirauth_data.get("gateway_addresses", {}).items():
        targets.append((name, "gateway", host, port))

    for name, (host, port) in dirauth_data.get("servicenode_addresses", {}).items():
        targets.append((name, "servicenode", host, port))

    for name, (host, port) in dirauth_data.get("mix_addresses", {}).items():
        targets.append((name, "mix", host, port))

    for name, (host, port) in dirauth_data.get("storagenode_addresses", {}).items():
        targets.append((name, "storage", host, port))

    topology_addresses = dirauth_data.get("topology_addresses", {})
    topology_layers = dirauth_data.get("topology_layers", [])
    for layer_idx, layer_nodes in enumerate(topology_layers):
        for name in layer_nodes:
            if name in topology_addresses:
                host, port = topology_addresses[name]
                targets.append((name, f"mix-L{layer_idx}", host, port))
            else:
                targets.append((name, f"mix-L{layer_idx}", "", 0))

    return targets


def parse_thinclient_config(config_path: str) -> dict[str, Any]:
    with open(config_path, "rb") as f:
        config = tomli.load(f)
    pigeonhole_geometry = config.get("PigeonholeGeometry", {})
    return {"pigeonhole_geometry": pigeonhole_geometry}


def get_operational_nodes(doc: dict[str, Any]) -> set[str]:
    nodes: set[str] = set()
    for node in doc.get("GatewayNodes", []):
        nodes.add(cbor2.loads(node)["Name"])
    for node in doc.get("ServiceNodes", []):
        nodes.add(cbor2.loads(node)["Name"])
    for layer in doc.get("Topology", []):
        for node in layer:
            nodes.add(cbor2.loads(node)["Name"])
    return nodes


def get_node_addresses_from_pki(doc: dict[str, Any]) -> dict[str, tuple[str, int]]:
    addresses: dict[str, tuple[str, int]] = {}

    def extract_address(node_data: dict[str, Any]) -> tuple[str, int] | None:
        addrs = node_data.get("Addresses", {})
        for transport in ["tcp4", "tcp", "tcp6"]:
            addr_list = addrs.get(transport, [])
            if addr_list:
                result = parse_host_port(addr_list[0])
                if result:
                    return result
        return None

    for raw_node in doc.get("GatewayNodes", []):
        node = cbor2.loads(raw_node)
        name = node.get("Name", "")
        addr = extract_address(node)
        if name and addr:
            addresses[name] = addr

    for raw_node in doc.get("ServiceNodes", []):
        node = cbor2.loads(raw_node)
        name = node.get("Name", "")
        addr = extract_address(node)
        if name and addr:
            addresses[name] = addr

    for layer in doc.get("Topology", []):
        for raw_node in layer:
            node = cbor2.loads(raw_node)
            name = node.get("Name", "")
            addr = extract_address(node)
            if name and addr:
                addresses[name] = addr

    return addresses


def build_survey_targets_from_pki(doc: dict[str, Any]) -> list[SurveyTarget]:
    targets: list[SurveyTarget] = []

    def extract_address(node_data: dict[str, Any]) -> tuple[str, int] | None:
        addrs = node_data.get("Addresses", {})
        for transport in ["tcp4", "tcp", "tcp6"]:
            addr_list = addrs.get(transport, [])
            if addr_list:
                result = parse_host_port(addr_list[0])
                if result:
                    return result
        return None

    for raw_node in doc.get("GatewayNodes", []):
        node = cbor2.loads(raw_node)
        name = node.get("Name", "")
        addr = extract_address(node)
        if name and addr:
            targets.append((name, "gateway", addr[0], addr[1]))

    for raw_node in doc.get("ServiceNodes", []):
        node = cbor2.loads(raw_node)
        name = node.get("Name", "")
        addr = extract_address(node)
        if name and addr:
            targets.append((name, "servicenode", addr[0], addr[1]))

    for layer_idx, layer in enumerate(doc.get("Topology", [])):
        for raw_node in layer:
            node = cbor2.loads(raw_node)
            name = node.get("Name", "")
            addr = extract_address(node)
            if name and addr:
                targets.append((name, f"mix-L{layer_idx}", addr[0], addr[1]))

    return targets


def get_services_by_capability(
    doc: dict[str, Any],
) -> dict[str, list[str]]:
    capabilities: dict[str, list[str]] = defaultdict(list)
    for raw_node in doc.get("ServiceNodes", []):
        node = cbor2.loads(raw_node)
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
) -> Table:
    table = Table(
        title="Network Parameters",
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

    table.add_row("Topology Layers", f"{len(doc.get('Topology', []))}")
    table.add_row(
        "SendRatePerMinute", f"{doc.get('SendRatePerMinute', 'N/A')}"
    )
    table.add_row("Mu", f"{doc.get('Mu', 'N/A')}")
    table.add_row("LambdaM", f"{doc.get('LambdaM', 'N/A')}")
    table.add_row("LambdaG", f"{doc.get('LambdaG', 'N/A')}")
    table.add_row("LambdaP", f"{doc.get('LambdaP', 'N/A')}")
    table.add_row("LambdaL", f"{doc.get('LambdaL', 'N/A')}")
    table.add_row("LambdaD", f"{doc.get('LambdaD', 'N/A')}")
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
    table.add_row("Service Nodes", str(len(servicenodes)))
    table.add_row("Storage Nodes", str(len(storagenodes)))
    return table


def make_ping_table(
    ping_ok: bool | None,
    ping_latency_ms: float | None,
) -> Table:
    table = Table(
        title="Ping",
        show_header=True,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
    )
    table.add_column("Check", style="dim")
    table.add_column("Result", justify="right")
    if ping_ok is None:
        result = Text("N/A", style="dim")
    elif ping_ok:
        if ping_latency_ms is not None:
            result = Text(f"OK ({ping_latency_ms:.0f}ms)", style="cyan")
        else:
            result = Text("OK", style="cyan")
    else:
        result = Text("FAIL", style="red")
    table.add_row("Echo Service", result)
    return table


def make_connection_status_table(conn_status: ConnectionStatus) -> Table:
    table = Table(
        title="Client Status",
        show_header=True,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
    )
    table.add_column("Check", style="dim")
    table.add_column("Result", justify="right")

    if conn_status.daemon_connected:
        daemon_status = Text("OK", style="cyan")
    else:
        daemon_status = Text("FAIL", style="red")
    table.add_row("Daemon Connection", daemon_status)

    if conn_status.daemon_connected:
        if conn_status.network_online:
            network_status = Text("ONLINE", style="cyan")
        else:
            network_status = Text("OFFLINE", style="yellow")
        table.add_row("Network Status", network_status)

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
        providers_str = ", ".join(sorted(providers))
        table.add_row(capability, providers_str, str(len(providers)))

    return table


def make_outage_reports(
    doc: dict[str, Any],
    mixes: set[str],
    gateways: set[str],
    servicenodes: set[str],
    dirauth_status: dict[str, tuple[bool, float | None]],
    node_status: dict[str, tuple[bool, float | None]],
) -> list[Table]:
    operational_nodes = get_operational_nodes(doc)

    def get_outage_report(
        node_type: str,
        config_nodes: set[str],
    ) -> Table | None:
        outages = config_nodes - operational_nodes
        if outages:
            table = Table(
                title=node_type,
                show_header=False,
                box=box.HEAVY_EDGE,
            )
            table.add_column(node_type, justify="center", no_wrap=True)
            table.add_column("Status", justify="right")
            for node in sorted(outages):
                tcp_up = False
                latency: float | None = None
                if node in node_status:
                    tcp_up, latency = node_status[node]
                if tcp_up and latency is not None:
                    status = Text(f"DOWN ({latency:.0f}ms)", style="red")
                else:
                    status = Text("DOWN", style="red")
                table.add_row(node, status)
            return table
        return None

    dirauth_outages = {
        name for name, (is_up, _) in dirauth_status.items() if not is_up
    }
    dirauth_report: Table | None = None
    if dirauth_outages:
        dirauth_report = Table(
            title="Dir Auths",
            show_header=False,
            box=box.HEAVY_EDGE,
        )
        dirauth_report.add_column("Dir Auths", justify="center", no_wrap=True)
        dirauth_report.add_column("Status", justify="right")
        for node in sorted(dirauth_outages):
            dirauth_report.add_row(node, Text("DOWN", style="red"))

    reports = [
        dirauth_report,
        get_outage_report("Mix Nodes", mixes),
        get_outage_report("Gateways", gateways),
        get_outage_report("Service Nodes", servicenodes),
    ]
    return [r for r in reports if r is not None]


def make_dirauth_table(
    authorities: set[str],
    dirauth_status: dict[str, tuple[bool, float | None]],
) -> Table:
    table = Table(
        title="Dir Auths",
        show_header=False,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
    )
    table.add_column("Node Name", style="dim")
    table.add_column("Status", justify="right")

    for node in sorted(authorities):
        if node in dirauth_status:
            is_up, latency = dirauth_status[node]
            if is_up:
                if latency is not None:
                    status = Text(f"OK ({latency:.0f}ms)", style="cyan")
                else:
                    status = Text("OK", style="cyan")
            else:
                status = Text("DOWN", style="red")
        else:
            status = Text("N/A", style="dim")
        table.add_row(node, status)
    return table


def make_gateway_table(
    gateways: set[str],
    operational_nodes: set[str],
    node_status: dict[str, tuple[bool, float | None]],
) -> Table:
    table = Table(
        title="Gateways",
        show_header=False,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
    )
    table.add_column("Node Name", style="dim")
    table.add_column("Status", justify="right")
    for node in sorted(gateways):
        tcp_up = False
        latency: float | None = None
        if node in node_status:
            tcp_up, latency = node_status[node]

        is_operational = node in operational_nodes
        latency_str = f" ({latency:.0f}ms)" if latency is not None else ""

        if is_operational:
            status = Text(f"OK{latency_str}", style="cyan")
        elif tcp_up:
            status = Text(f"DOWN{latency_str}", style="red")
        else:
            status = Text("DOWN", style="red")
        table.add_row(node, status)
    return table


def make_service_table(
    servicenodes: set[str],
    operational_nodes: set[str],
    node_status: dict[str, tuple[bool, float | None]],
) -> Table:
    table = Table(
        title="Service Nodes",
        show_header=False,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
    )
    table.add_column("Node Name", style="dim")
    table.add_column("Status", justify="right")
    for node in sorted(servicenodes):
        tcp_up = False
        latency: float | None = None
        if node in node_status:
            tcp_up, latency = node_status[node]

        is_operational = node in operational_nodes
        latency_str = f" ({latency:.0f}ms)" if latency is not None else ""

        if is_operational:
            status = Text(f"OK{latency_str}", style="cyan")
        elif tcp_up:
            status = Text(f"DOWN{latency_str}", style="red")
        else:
            status = Text("DOWN", style="red")
        table.add_row(node, status)
    return table


def make_topology_table(
    doc: dict[str, Any],
    n: int,
    expected_nodes: list[str],
    operational_nodes: set[str],
    node_status: dict[str, tuple[bool, float | None]],
) -> Table:
    table = Table(
        title=f"Topology Layer {n}",
        show_header=False,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
    )
    table.add_column("Node Name", style="dim")
    table.add_column("Status", justify="right")

    for node_name in sorted(expected_nodes):
        tcp_up = False
        latency: float | None = None
        if node_name in node_status:
            tcp_up, latency = node_status[node_name]

        is_operational = node_name in operational_nodes
        latency_str = f" ({latency:.0f}ms)" if latency is not None else ""

        if is_operational:
            status = Text(f"OK{latency_str}", style="cyan")
        elif tcp_up:
            status = Text(f"DOWN{latency_str}", style="red")
        else:
            status = Text("DOWN", style="red")
        table.add_row(node_name, status)

    return table


def make_consensus_info_table(
    doc: dict[str, Any],
    last_consensus: dict[str, Any] | None = None,
) -> Table:
    table = Table(
        title="Consensus Information",
        show_header=True,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
    )
    table.add_column("Name", style="dim")
    table.add_column("Value", justify="right")
    table.add_column("UTC Earth Time", justify="right")

    epoch = doc.get("Epoch", 0)
    genesis_epoch = doc.get("GenesisEpoch", 0)
    version = doc.get("Version", "N/A")
    pki_sig_scheme = doc.get("PKISignatureScheme", "N/A")

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
        title="Cipher Schemes",
        show_header=True,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
    )
    table.add_column("Name", style="dim")
    table.add_column("Value", justify="right")

    pki_sig_scheme = doc.get("PKISignatureScheme", "N/A")
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
        value = pigeonhole_geometry.get(field, "")
        table.add_row(field, str(value))

    return table


def make_srv_table(doc: dict[str, Any]) -> Table:
    table = Table(
        title="Shared Random Value",
        show_header=True,
        header_style="bold bright_white",
        box=box.HEAVY_EDGE,
    )
    table.add_column("Name", style="dim")
    table.add_column("Value", justify="right")

    srv = doc.get("SharedRandomValue")
    if srv:
        table.add_row("SharedRandomValue", srv.hex())
    else:
        table.add_row("SharedRandomValue", "N/A")

    prior = doc.get("PriorSharedRandom", [])
    if prior and len(prior) >= 1:
        table.add_row("PriorSharedRandom0", prior[0].hex())
    if prior and len(prior) >= 2:
        table.add_row("PriorSharedRandom1", prior[1].hex())

    return table


class PingState:
    def __init__(self) -> None:
        self.reply_message: dict[str, Any] | None = None

    def save_reply(self, reply: dict[str, Any]) -> None:
        self.reply_message = reply


async def do_ping(
    client: ThinClient,
    state: PingState,
    timeout: float = 30.0,
) -> tuple[bool, float | None]:
    start_time = time.monotonic()
    try:
        service_desc = client.get_service("echo")
        surb_id = client.new_surb_id()
        payload = b"hello"
        dest_node, dest_queue = service_desc.to_destination()
        await client.send_reliable_message(
            surb_id, payload, dest_node, dest_queue
        )
        await asyncio.wait_for(
            client.await_message_reply(),
            timeout=timeout,
        )
        end_time = time.monotonic()
        latency_ms = (end_time - start_time) * 1000

        reply = state.reply_message
        if reply is None:
            return False, None
        payload2 = reply.get("payload", b"")
        payload2 = payload2[0 : len(payload)]
        success = (
            len(payload2) == len(payload)
            and payload2.decode() == payload.decode()
        )
        return success, latency_ms if success else None
    except asyncio.TimeoutError:
        return False, None
    except Exception:
        return False, None


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
            return str(value)

    skip_keys = {"GatewayNodes", "ServiceNodes", "Topology", "Signatures"}

    for key, value in doc.items():
        if key in skip_keys:
            continue
        lines.append(f"{key}: {format_value(value)}")

    for category in ["GatewayNodes", "ServiceNodes"]:
        nodes = doc.get(category, [])
        if nodes:
            lines.append(f"{category}:")
            for raw_node in nodes:
                node = cbor2.loads(raw_node)
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
                node = cbor2.loads(raw_node)
                name = node.get("Name", "unknown")
                lines.append(f"    - {name}:")
                for k, v in node.items():
                    if k != "Name":
                        lines.append(f"        {k}: {format_value(v, 4)}")

    return "\n".join(lines)


def make_pki_doc_panel(doc: dict[str, Any]) -> Panel:
    pki_text = pretty_print_pki_doc(doc)
    return Panel(
        Text(pki_text, style="dim"),
        title="PKI Document",
        title_align="left",
        border_style="grey70",
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
    config_path: str,
    output_file: str | None = None,
    ping_ok: bool | None = None,
    ping_latency_ms: float | None = None,
    conn_status: ConnectionStatus | None = None,
    dirauth_status: dict[str, tuple[bool, float | None]] | None = None,
    node_status: dict[str, tuple[bool, float | None]] | None = None,
    network_name: str = "namenlos",
    show_pki_doc: bool = False,
    survey_results: dict[str, dict[str, Any]] | None = None,
    quiet: bool = False,
    last_consensus: dict[str, Any] | None = None,
) -> None:
    if conn_status is None:
        conn_status = ConnectionStatus()
    if dirauth_status is None:
        dirauth_status = {}
    if node_status is None:
        node_status = {}

    width = 140 if output_file else None

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
    authorities = dirauth_data["authorities"]
    mixes = dirauth_data["mixes"]
    gateways = dirauth_data["gateways"]
    servicenodes = dirauth_data["servicenodes"]
    storagenodes = dirauth_data["storagenodes"]
    topology_layers = dirauth_data["topology_layers"]

    thinclient_data = parse_thinclient_config(config_path)
    pigeonhole_geometry = thinclient_data["pigeonhole_geometry"]

    capabilities = get_services_by_capability(doc)

    consensus_table = make_consensus_info_table(doc, last_consensus)

    status_table = make_status_table(
        authorities, mixes, gateways, servicenodes, storagenodes
    )
    services_table = make_services_table(capabilities)

    connection_table = make_connection_status_table(conn_status)
    row3_tables: list[RenderableType] = [Align.center(connection_table)]
    if ping_ok is not None:
        ping_table = make_ping_table(ping_ok, ping_latency_ms)
        row3_tables.append(Align.center(ping_table))

    outage_tables = make_outage_reports(
        doc, mixes, gateways, servicenodes, dirauth_status, node_status
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

    status_content: list[RenderableType] = [
        Align.center(consensus_table),
        Columns(
            [Align.center(status_table), Align.center(services_table)],
            equal=True,
            expand=True,
        ),
        Columns(row3_tables, equal=True, expand=True),
    ]
    if outages_panel:
        status_content.append(outages_panel)

    status_section = Panel(
        Group(*status_content),
        title="Status and Health",
        title_align="left",
        border_style="cyan",
    )

    operational_nodes = get_operational_nodes(doc)
    dirauth_table = make_dirauth_table(authorities, dirauth_status)
    gateway_table = make_gateway_table(gateways, operational_nodes, node_status)
    servicenode_table = make_service_table(servicenodes, operational_nodes, node_status)

    layer_tables: list[RenderableType] = []
    for i, layer_nodes in enumerate(topology_layers):
        table = make_topology_table(doc, i, layer_nodes, operational_nodes, node_status)
        layer_tables.append(Align.center(table))

    traffic_flow: list[RenderableType] = [Align.center(gateway_table)]
    traffic_flow.extend(layer_tables)
    traffic_flow.append(Align.center(servicenode_table))

    nodes_section = Panel(
        Group(
            Align.center(dirauth_table),
            Columns(traffic_flow, equal=True, expand=True),
        ),
        title="Network Nodes Summary",
        title_align="left",
        border_style="cyan",
    )

    ciphers_table = make_cipher_schemes_table(doc, sphinx_geometry, server)
    network_params_table = make_network_params_table(
        doc, sphinx_geometry, pigeonhole_geometry
    )
    sphinx_table = make_sphinx_geometry_table(sphinx_geometry)
    srv_table = make_srv_table(doc)

    crypto_row1 = Columns(
        [Align.center(ciphers_table), Align.center(network_params_table)],
        equal=True,
        expand=True,
    )

    geometry_tables: list[RenderableType] = [Align.center(sphinx_table)]
    if pigeonhole_geometry:
        pigeonhole_table = make_pigeonhole_geometry_table(pigeonhole_geometry)
        geometry_tables.append(Align.center(pigeonhole_table))
    crypto_row2 = Columns(geometry_tables, equal=True, expand=True)

    crypto_row3 = Align.center(srv_table)

    crypto_section = Panel(
        Group(crypto_row1, crypto_row2, crypto_row3),
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
        survey_table = make_survey_table(survey_results)

        sorted_items = sorted(
            survey_results.items(),
            key=lambda x: (x[1].get("name", ""), x[1].get("node_type", "")),
        )

        trace_tables: list[RenderableType] = []
        for key, data in sorted_items:
            trace_table = make_traceroute_detail_table(key, data)
            trace_tables.append(Align.center(trace_table))

        survey_content: list[RenderableType] = [Align.center(survey_table)]

        if trace_tables:
            trace_rows: list[RenderableType] = []
            for i in range(0, len(trace_tables), 3):
                row_tables = trace_tables[i:i + 3]
                if len(row_tables) == 1:
                    trace_rows.append(row_tables[0])
                else:
                    trace_rows.append(
                        Columns(row_tables, equal=True, expand=True)
                    )

            trace_panel = Panel(
                Group(*trace_rows),
                title="Network path details",
                title_align="left",
                border_style="grey70",
            )
            survey_content.append(trace_panel)

        survey_panel = Panel(
            Group(*survey_content),
            title="Network Survey",
            title_align="left",
            border_style="cyan",
        )
        sections.append(survey_panel)

    if show_pki_doc:
        pki_panel = make_pki_doc_panel(doc)
        sections.append(pki_panel)

    sections.append(Align.center(footer))

    outer_panel = Panel(
        Group(*sections),
        title=network_name,
        title_align="center",
        border_style="bold white",
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
    bool | None,
    float | None,
    ConnectionStatus,
    dict[str, tuple[bool, float | None]],
    dict[str, tuple[bool, float | None]],
]:
    config_path: str = ctx.obj["config_path"]
    dirauthconf: str = ctx.obj["dirauthconf"]
    ping_enabled: bool = ctx.obj["ping"]
    connect_timeout: float = ctx.obj["timeout"]

    conn_status = ConnectionStatus()

    dirauth_data = parse_dirauth_config(dirauthconf)
    dirauth_addresses = dirauth_data["dirauth_addresses"]

    dirauth_status = await probe_dirauths(dirauth_addresses, timeout=connect_timeout)

    ping_state: PingState | None = None
    if ping_enabled:
        ping_state = PingState()
        cfg = Config(config_path, on_message_reply=ping_state.save_reply)
    else:
        cfg = Config(config_path)

    client = ThinClient(cfg)
    loop = asyncio.get_event_loop()

    try:
        await asyncio.wait_for(client.start(loop), timeout=connect_timeout)
        conn_status.daemon_connected = True
    except asyncio.TimeoutError:
        conn_status.daemon_connected = False
        conn_status.error_message = "Connection to daemon timed out"
    except Exception as e:
        conn_status.daemon_connected = False
        conn_status.error_message = str(e)

    doc: dict[str, Any] = {}
    node_status: dict[str, tuple[bool, float | None]] = {}

    if conn_status.daemon_connected:
        doc = client.pki_document() or {}
        if doc.get("Topology") and len(doc.get("Topology", [])) > 0:
            conn_status.network_online = True
        else:
            conn_status.network_online = False

        pki_node_addresses = get_node_addresses_from_pki(doc)
        if pki_node_addresses:
            node_status = await probe_all_nodes(
                pki_node_addresses, timeout=connect_timeout
            )

    ping_ok: bool | None = None
    ping_latency_ms: float | None = None
    if ping_enabled and ping_state is not None and conn_status.daemon_connected:
        ping_ok, ping_latency_ms = await do_ping(client, ping_state)
        if ping_ok:
            conn_status.network_online = True

    if conn_status.daemon_connected:
        client.stop()

    return doc, ping_ok, ping_latency_ms, conn_status, dirauth_status, node_status


async def _async_main_inner(ctx: click.Context) -> None:
    dirauthconf: str = ctx.obj["dirauthconf"]
    config_path: str = ctx.obj["config_path"]
    htmlout: str = ctx.obj["htmlout"]
    network_name: str = ctx.obj["network_name"]
    show_pki_doc: bool = ctx.obj["pki_document"]
    run_survey: bool = ctx.obj["survey"]
    max_threads: int = ctx.obj["max_threads"]
    cache_file: str = ctx.obj["cache_file"]
    verbose: bool = ctx.obj["verbose"]
    quiet: bool = ctx.obj["quiet"]

    cache_path = get_cache_path(cache_file if cache_file else None)

    if verbose:
        doc, ping_ok, ping_latency_ms, conn_status, dirauth_status, node_status = (
            await _collect_network_data(ctx, cache_path)
        )
    else:
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            doc, ping_ok, ping_latency_ms, conn_status, dirauth_status, node_status = (
                await _collect_network_data(ctx, cache_path)
            )

    last_consensus = load_last_consensus(cache_path)
    epoch = doc.get("Epoch", 0)
    if epoch > 0:
        epoch_time_str = epoch_id_to_time_str(epoch)
        save_last_consensus(epoch, epoch_time_str, cache_path)

    survey_results: dict[str, dict[str, Any]] | None = None
    if run_survey:
        dirauth_data = parse_dirauth_config(dirauthconf)
        config_targets = build_survey_targets_from_config(dirauth_data)
        pki_targets = build_survey_targets_from_pki(doc)
        cached_targets = load_typed_address_cache(cache_path, verbose=verbose)

        seen: set[tuple[str, str, str, int]] = set()
        all_targets: list[SurveyTarget] = []
        for target in config_targets + pki_targets + cached_targets:
            key = (target[0], target[1], target[2], target[3])
            if key not in seen:
                seen.add(key)
                all_targets.append(target)

        if config_targets:
            save_typed_address_cache(config_targets, cache_path)
        if pki_targets:
            save_typed_address_cache(pki_targets, cache_path)

        if verbose and not quiet:
            click.echo(f"Running survey on {len(all_targets)} node endpoints...")

        survey_results = run_survey_parallel(
            all_targets,
            run_traceroute=True,
            verbose=verbose and not quiet,
            max_workers=max_threads,
        )

    generate_report(
        doc,
        dirauthconf,
        config_path,
        output_file=htmlout or None,
        ping_ok=ping_ok,
        ping_latency_ms=ping_latency_ms,
        conn_status=conn_status,
        dirauth_status=dirauth_status,
        node_status=node_status,
        network_name=network_name,
        show_pki_doc=show_pki_doc,
        survey_results=survey_results,
        quiet=quiet,
        last_consensus=last_consensus,
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

    asyncio.run(async_main(ctx))


if __name__ == "__main__":
    main()
