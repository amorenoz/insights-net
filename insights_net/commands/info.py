import click
from rich.console import Console
from rich.columns import Columns

from insights_net.main import maincli
from insights_net.commands.printing import print_section_header, print_archive_header


@maincli.command(name="info")
@click.pass_obj
def info(ctx):
    """
    Show basic information of the archives
    """
    data = ctx.client.available()
    if not data:
        print("Command not found")
        return

    console = Console()
    for archive, host_data in data.items():
        if not host_data:
            continue

        print_archive_header(console, "Archive: " + archive)
        if isinstance(host_data, str):
            console.print(host_data)
        else:
            print_results(console, host_data)
            print("")


def print_results(console, data):
    if data.get("models"):
        print_section_header(console, "Available Models")
        models = data.get("models")
        console.print(Columns(models, equal=True, expand=True))
        console.print("")

    if data.get("commands"):
        print_section_header(console, "Available Commands")
        for cmd in data.get("commands"):
            console.print("  {}".format(cmd))
