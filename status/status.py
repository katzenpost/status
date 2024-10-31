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

def parse_config(dirauthconf):
    with open(dirauthconf, "rb") as f:
        config = tomli.load(f)
    authorities = {auth["Identifier"] for auth in config.get("Authorities", [])}
    mixes = {mix["Identifier"] for mix in config.get("Mixes", [])}
    gateways = {node["Identifier"] for node in config.get("GatewayNodes", [])}
    servicenodes = {node["Identifier"] for node in config.get("ServiceNodes", [])}
    return authorities, mixes, gateways, servicenodes

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

def generate_report(doc, authorities, mixes, gateways, servicenodes, operational_nodes, output_file=None):
    console = Console(record=bool(output_file))

    status_table = Table(title="Network Status", show_header=True, header_style="bold magenta", box=box.HEAVY_EDGE)
    status_table.add_column("Statistic", style="dim")
    status_table.add_column("Value", justify="right")

    num_mix_nodes = sum(len(layer) for layer in doc["Topology"])
    num_gateways = len(doc["GatewayNodes"])
    num_service_nodes = len(doc["ServiceNodes"])

    status_table.add_row("Mix Nodes", str(num_mix_nodes))
    status_table.add_row("Gateways", str(num_gateways))
    status_table.add_row("Service Nodes", str(num_service_nodes))

    dirauth_table = Table(title="Directory Authority Nodes", show_header=False, header_style="bold magenta", box=box.HEAVY_EDGE)
    dirauth_table.add_column("Node Name", style="dim")
    for node in authorities:
        dirauth_table.add_row(node)

    columns = Columns([Panel(status_table, title="Network Status Summary", title_align="left", border_style="green"),
                       Panel(dirauth_table, title="Directory Authorities", title_align="left", border_style="blue")])

    console.print(columns)

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

    outage_reports = [
        get_outage_report("Mix Nodes", mixes),
        get_outage_report("Gateway Nodes", gateways),
        get_outage_report("Service Nodes", servicenodes),
    ]

    for report in outage_reports:
        if report:
            console.print(report)

    if output_file:
        with open(output_file, "w") as file:
            file.write(console.export_html(inline_styles=True))
        console.print(f"HTML report written to {output_file}", style="bold green")


async def async_main(dirauthconf=None, htmlout=None):
    authorities, mixes, gateways, servicenodes = parse_config(dirauthconf)
    cfg = Config()
    client = ThinClient(cfg)
    await client.start(asyncio.get_event_loop())
    doc = client.pki_document()
    client.stop()

    operational_nodes = get_operational_nodes(doc)
    generate_report(doc, authorities, mixes, gateways, servicenodes, operational_nodes, output_file=htmlout)


@click.command()
@click.option("--htmlout", default="", help="Path to output HTML file.")
@click.option("--dirauthconf", required=True, help="Path to the directory authority configuration TOML file.")
def main(dirauthconf, htmlout):
    asyncio.run(async_main(dirauthconf, htmlout))


if __name__ == '__main__':
    main()
