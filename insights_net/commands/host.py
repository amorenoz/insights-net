import click
from rich.console import Console

from insights_net.main import maincli
from insights_net.commands.printing import print_archive_header


@maincli.command(name="host")
@click.pass_obj
def host(ctx):
    """
    Show basic host information
    """
    data = ctx.client.evaluate("host_info")
    if not data:
        print("Command not found")
        return

    console = Console()

    for archive, host_data in data.items():
        if not host_data:
            continue

        print_archive_header(console, archive)
        if isinstance(host_data, str):
            console.print(host_data)
        else:
            print_results(console, host_data)


def print_results(console, data):
    console.print("[bold]HostName:[/bold] {}".format(data.get("hostname")))
    rh_ver = data.get("version")
    if rh_ver and isinstance(rh_ver, dict):
        console.print("[bold]Red Hat Version:[/bold]")
        console.print("  [bold]Product:[/bold] {}".format(rh_ver.get("product")))
        console.print("  [bold]Version:[/bold] {}".format(rh_ver.get("version")))
        console.print("  [bold]Code Name:[/bold] {}".format(rh_ver.get("code_name")))

    uname = data.get("uname")
    if uname and isinstance(rh_ver, dict):
        console.print("[bold]Kernel:[/bold]")
        console.print("  [bold]Version :[/bold] {}".format(uname.get("version")))
        console.print("  [bold]Release:[/bold] {}".format(uname.get("release")))
        console.print("  [bold]Arch:[/bold] {}".format(uname.get("arch")))

    up = data.get("uptime")
    if up and isinstance(up, dict):
        console.print(
            "[bold]Uptime for {} days {} hh:[/bold]mm".format(
                up.get("updays"), up.get("uphhmm")
            )
        )

    sel = data.get("selinux")
    if sel and isinstance(sel, dict):
        console.print(
            "[bold]Selinux:[/bold] {}".format(data.get("selinux").get("selinux_status"))
        )
    console.print("")
