import click
from rich.console import Console
from rich.table import Table
from rich.pretty import Pretty

from insights_net.main import maincli

# The following click commands only modify the attributes of ctx.
# The command's logic will then use these commands to obtain the relevant data


@maincli.group(name="ovs")
@click.pass_obj
def ovs(ctx):
    """
    Show the OVS configuration
    """
    setattr(ctx, "cmd_table_list", "ovs_table_list")
    setattr(ctx, "cmd_table", "ovs_table")
    setattr(ctx, "cmd_find_uuid", "ovs_find_uuid")


@ovs.command(name="list")
@click.argument("table", required=False, nargs=1)
@click.pass_obj
def ovs_list(ctx, table):
    """
    List the content of a OVS Table
    """
    return list_cmd(ctx, table)


@ovs.command(name="get")
@click.argument("table", required=True, nargs=1)
@click.argument("uuid", required=True, nargs=1)
@click.pass_obj
def ovs_get(ctx, table, uuid):
    """
    Get an element form the OVS Database
    """
    return get_cmd(ctx, table, uuid)


@maincli.group(name="ovn")
@click.pass_obj
def ovn(ctx):
    """
    Show the OVN configuration
    """
    pass


@ovn.group(name="nb")
@click.pass_obj
def nb(ctx):
    setattr(ctx, "cmd_table_list", "ovnnb_table_list")
    setattr(ctx, "cmd_table", "ovnnb_table")
    setattr(ctx, "cmd_find_uuid", "ovnnb_find_uuid")


@nb.command(name="list")
@click.argument("table", required=False, nargs=1)
@click.pass_obj
def nb_list(ctx, table):
    """
    List the content of a OVN NB Table
    """
    return list_cmd(ctx, table)


@nb.command(name="get")
@click.argument("table", required=True, nargs=1)
@click.argument("uuid", required=True, nargs=1)
@click.pass_obj
def nb_get(ctx, table, uuid):
    """
    Get an element form the NB Database
    """
    return get_cmd(ctx, table, uuid)


@ovn.group(name="sb")
@click.pass_obj
def sb(ctx):
    setattr(ctx, "cmd_table_list", "ovnsb_table_list")
    setattr(ctx, "cmd_table", "ovnsb_table")
    setattr(ctx, "cmd_find_uuid", "ovnsb_find_uuid")
    pass


@sb.command(name="list")
@click.argument("table", required=False, nargs=1)
@click.pass_obj
def sb_list(ctx, table):
    """
    List the content of a OVN SB Table
    """
    return list_cmd(ctx, table)


@sb.command(name="get")
@click.argument("table", required=True, nargs=1)
@click.argument("uuid", required=True, nargs=1)
@click.pass_obj
def sb_get(ctx, table, uuid):
    """
    Get an element form the SB Database
    """
    return get_cmd(ctx, table, uuid)


# Commands logic


def get_cmd(ctx, table, uuid):
    data = ctx.client.run_command(ctx.cmd_find_uuid, table, uuid)
    if not data:
        print("No data")
        return
    for archive, host_data in data.items():
        if not host_data:
            print("No data")
        console = Console()
        console.print(host_data)


def list_cmd(ctx, table):
    """
    List the content of a DB Tabel
    """
    if not table:
        tables = ctx.client.run_command(ctx.cmd_table_list)
        if not tables:
            print("No data")
            return

        for archive, host_data in tables.items():
            print("Archive: " + archive)
            print("*" * (9 + len(archive)))

            if not host_data:
                print("No data")
                continue

            if isinstance(host_data, str):
                print(host_data)
            else:
                console = Console()
                console.print("Available Tables:")
                console.print(host_data)
        return

    table_data = ctx.client.run_command(ctx.cmd_table, table)
    if not table_data:
        print("No data")
        return

    for archive, host_data in table_data.items():
        print("Archive: " + archive)
        print("*" * (9 + len(archive)))
        if not host_data:
            print("No data")
            continue
        if isinstance(host_data, str):
            print(host_data)
        else:
            print_results(host_data, table)


def print_results(table_data, table):
    console = Console()
    tt = Table(title=table)
    for header, value in table_data[next(iter(table_data.keys()))].items():
        if isinstance(value, dict):
            tt.add_column(header, justify="left", no_wrap=False, ratio=1, min_width=25)
        else:
            tt.add_column(header, justify="left", no_wrap=False, min_width=len(header))

    for elem in table_data.values():
        values = [Pretty(val) for val in elem.values()]
        tt.add_row(*values)

    console.print(tt)
