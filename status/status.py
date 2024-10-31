#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

import asyncio
import cbor2
from rich.console import Console
from rich.table import Table
from rich.columns import Columns
from rich.panel import Panel
from thinclient import ThinClient, Config
from rich import box
import click
import tomli
from datetime import datetime, timedelta

# Define the base epoch start time and period duration
EPOCH = datetime(2017, 6, 1)
PERIOD = timedelta(minutes=20)  # Katzenpost epoch period (20 minutes)

def epoch_id_to_time_str(epoch_id):
    t = EPOCH + epoch_id * PERIOD
    return t.strftime("%Y-%m-%d %H:%M:%S")


def parse_config(dirauthconf):
    with open(dirauthconf, "rb") as f:
        config = tomli.load(f)
    authorities = {auth["Identifier"] for auth in config.get("Authorities", [])}
    mixes = {mix["Identifier"] for mix in config.get("Mixes", [])}
    gateways = {node["Identifier"] for node in config.get("GatewayNodes", [])}
    servicenodes = {node["Identifier"] for node in config.get("ServiceNodes", [])}
    sphinxGeometry = config["SphinxGeometry"]
    return sphinxGeometry, authorities, mixes, gateways, servicenodes

def get_operational_nodes(doc):
    nodes = set()
    for node in doc["GatewayNodes"]:
        nodes.add(cbor2.loads(node)["Name"])
    for node in doc["ServiceNodes"]:
        nodes.add(cbor2.loads(node)["Name"])
    for layer in doc["Topology"]:
        for node in layer:
            nodes.add(cbor2.loads(node)["Name"])
    return nodes


def make_tuning_params_table(doc):
    tuning_params_table = Table(title="Tuning Parameters", show_header=True, header_style="bold magenta", box=box.HEAVY_EDGE)
    tuning_params_table.add_column("Name", style="dim")
    tuning_params_table.add_column("Value", justify="right")
    tuning_params_table.add_row("Topology Layers", f"{len(doc['Topology'])}")    
    tuning_params_table.add_row("SendRatePerMinute", f"{doc['SendRatePerMinute']}")
    tuning_params_table.add_row("Mu", f"{doc['Mu']}")
    tuning_params_table.add_row("LambdaM", f"{doc['LambdaM']}")
    tuning_params_table.add_row("LambdaG", f"{doc['LambdaG']}")
    tuning_params_table.add_row("LambdaP", f"{doc['LambdaP']}")
    tuning_params_table.add_row("LambdaL", f"{doc['LambdaL']}")
    tuning_params_table.add_row("LambdaD", f"{doc['LambdaD']}")
    return tuning_params_table

def make_status_table(doc):
    status_table = Table(title="Node Statistics", show_header=True, header_style="bold magenta", box=box.HEAVY_EDGE)
    status_table.add_column("Node Type", style="dim")
    status_table.add_column("Value", justify="right")

    num_mix_nodes = sum(len(layer) for layer in doc["Topology"])
    num_gateways = len(doc["GatewayNodes"])
    num_service_nodes = len(doc["ServiceNodes"])
    num_replica_nodes = 0
    if "StorageReplicas" in doc:
        num_replica_nodes = len(doc["StorageReplicas"])

    status_table.add_row("Mix Nodes", str(num_mix_nodes))
    status_table.add_row("Gateway Nodes", str(num_gateways))
    status_table.add_row("Service Nodes", str(num_service_nodes))
    status_table.add_row("Storage Replica Nodes", str(num_replica_nodes))
    return status_table

def make_outage_reports(doc, mixes, gateways, servicenodes):
    operational_nodes = get_operational_nodes(doc)
    def get_outage_report(node_type, config_nodes):
        outages = config_nodes - operational_nodes
        if outages:
            outage_table = Table(title=f"{node_type} Outages", show_header=True, header_style="bold red", box=box.HEAVY_EDGE)
            outage_table.add_column("Identifier", justify="left")
            for node in outages:
                outage_table.add_row(node)
            return outage_table
        else:
            return None
    return [
        get_outage_report("Mix Nodes", mixes),
        get_outage_report("Gateway Nodes", gateways),
        get_outage_report("Service Nodes", servicenodes),
    ]

def make_dirauth_table(doc, authorities):
    dirauth_table = Table(title="Directory Authority Nodes", show_header=False, header_style="bold magenta", box=box.HEAVY_EDGE)
    dirauth_table.add_column("Node Name", style="dim")
    for node in authorities:
        dirauth_table.add_row(node)
    return dirauth_table

def make_gateway_table(doc, gateways):
    table = Table(title="Gateway Nodes", show_header=False, header_style="bold magenta", box=box.HEAVY_EDGE)
    table.add_column("Node Name", style="dim")
    for node in gateways:
        table.add_row(node)
    return table

def make_service_table(doc, services):
    table = Table(title="Service Nodes", show_header=False, header_style="bold magenta", box=box.HEAVY_EDGE)
    table.add_column("Node Name", style="dim")
    for node in services:
        table.add_row(node)
    return table

def make_topology_table(doc, n, layer):
    table = Table(title=f"Topology Layer {n} Nodes", show_header=False, header_style="bold magenta", box=box.HEAVY_EDGE)
    table.add_column("Node Name", style="dim")
    layer = doc['Topology'][n]
    for raw in layer:
        node = cbor2.loads(raw)
        table.add_row(node['Name'])
    return table

def make_consensus_info_table(doc):
    consensus_table = Table(title="Consensus Information", show_header=True, header_style="bold magenta", box=box.HEAVY_EDGE)
    consensus_table.add_column("Name", style="dim")
    consensus_table.add_column("Value", justify="right")
    consensus_table.add_column("Human Readable", justify="right")
    consensus_table.add_row("Epoch", f"{doc['Epoch']}", epoch_id_to_time_str(doc['Epoch']))
    consensus_table.add_row("GenesisEpoch", f"{doc['GenesisEpoch']}", epoch_id_to_time_str(doc['GenesisEpoch']))
    consensus_table.add_row("PKI Doc Version", f"{doc['Version']}", "")
    consensus_table.add_row("PKISignatureScheme", f"{doc['PKISignatureScheme']}", "")
    return consensus_table

def make_srv_table(doc):
    srv_table = Table(title="Shared Random Value", show_header=True, header_style="bold magenta", box=box.HEAVY_EDGE)
    srv_table.add_column("Name", style="dim")
    srv_table.add_column("Value", justify="right")
    srv_table.add_row("SharedRandomValue", f"{doc['SharedRandomValue'].hex()}")
    for i, prior in enumerate(doc['PriorSharedRandom']):
        srv_table.add_row(f"PriorSharedRandom{i}", f"{doc['PriorSharedRandom'][i].hex()}")
    return srv_table

def make_sphinx_geometry_table(sphinxGeometry):
    table = Table(title="Sphinx Geometry", show_header=False, header_style="bold magenta", box=box.HEAVY_EDGE)
    table.add_column("Name", style="dim")
    table.add_column("Value", justify="right")
    for key, value in sphinxGeometry.items():
        table.add_row(f"{key}", f"{value}")
    return table
    

def generate_report(sphinxGeometry, doc, authorities, mixes, gateways, servicenodes, output_file=None):
    console = Console(record=bool(output_file))

    consensus_table = make_consensus_info_table(doc)
    status_table = make_status_table(doc)
    tuning_params_table = make_tuning_params_table(doc)
    combined_summary = Columns([consensus_table, status_table, tuning_params_table])
    console.print(Panel(combined_summary, title="Network Status Summary", title_align="left", border_style="green"))


    dirauth_table = make_dirauth_table(doc, authorities)
    gateway_table = make_gateway_table(doc, gateways)
    servicenode_table = make_service_table(doc, servicenodes)
    combined_nodes_list = [dirauth_table, gateway_table]
    for i, layer in enumerate(doc["Topology"]):
        table = make_topology_table(doc, i, layer)
        combined_nodes_list.append(table)
    combined_nodes_list.append(servicenode_table)
    combined_nodes_summary = Columns(combined_nodes_list)
    console.print(Panel(combined_nodes_summary, title="Network Nodes Summary", title_align="left", border_style="green"))

    outage_reports = make_outage_reports(doc, mixes, gateways, servicenodes)
    pre_outage_summary = []
    for report in outage_reports:
        if report:
            pre_outage_summary.append(report)
    outage_summary = Columns(pre_outage_summary)
    console.print(Panel(outage_summary, title="Outages", title_align="left", border_style="green"))

    sphinx_table = make_sphinx_geometry_table(sphinxGeometry)
    console.print(sphinx_table)

    srv_table = make_srv_table(doc)
    console.print(srv_table)

    if output_file:
        with open(output_file, "w") as file:
            file.write(console.export_html(inline_styles=True))
        console.print(f"HTML report written to {output_file}", style="bold green")



async def async_main(dirauthconf=None, htmlout=None):
    sphinxGeometry, authorities, mixes, gateways, servicenodes = parse_config(dirauthconf)

    cfg = Config()
    client = ThinClient(cfg)
    await client.start(asyncio.get_event_loop())
    doc = client.pki_document()
    client.stop()

    generate_report(sphinxGeometry, doc, authorities, mixes, gateways, servicenodes, output_file=htmlout)


@click.command()
@click.option("--htmlout", default="", help="Path to output HTML file.")
@click.option("--dirauthconf", required=True, help="Path to the directory authority configuration TOML file.")
def main(dirauthconf, htmlout):
    asyncio.run(async_main(dirauthconf, htmlout))


if __name__ == '__main__':
    main()
