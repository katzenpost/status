#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

import asyncio
import cbor2
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from thinclient import ThinClient, Config
from rich import box
import click

def generate_status_table(doc):
    table = Table(title="Network Status", show_header=True, header_style="bold magenta", box=box.HEAVY_EDGE)
    table.add_column("Statistic", style="dim")
    table.add_column("Value", justify="right")

    num_mix_nodes = sum(len(layer) for layer in doc["Topology"])
    gateways = len(doc["GatewayNodes"])
    service_nodes = len(doc["ServiceNodes"])

    table.add_row("Mix Nodes", str(num_mix_nodes))
    table.add_row("Gateways", str(gateways))
    table.add_row("Service Nodes", str(service_nodes))
    return table


def export_to_html(doc, html_file):
    console = Console(record=True)  # Record mode for HTML export
    table = generate_status_table(doc)

    # Print the table within a panel for a styled output
    console.print(Panel(table, title="Network Status Summary", title_align="left", border_style="green"))

    # Export the recorded output to HTML
    with open(html_file, "w") as file:
        file.write(console.export_html(inline_styles=True))
    console.print(f"HTML report written to {html_file}", style="bold green")


async def async_main(htmlout):
    cfg = Config()
    client = ThinClient(cfg)
    loop = asyncio.get_event_loop()
    await client.start(loop)
    doc = client.pki_document()
    client.stop()

    if htmlout:
        export_to_html(doc, htmlout)
    else:
        table = generate_status_table(doc)
        console = Console()
        console.print(Panel(table, title="Network Status Summary", title_align="left", border_style="green"))


@click.command()
@click.option("--htmlout", default="")
def main(htmlout):
    asyncio.run(async_main(htmlout))


if __name__ == '__main__':
    main()
