import click
from rich.console import Console
from rich.table import Table
from rich.pretty import Pretty

from insights_net.main import maincli


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
    setattr(ctx, "db", "OVNNBDump")


@ovn.group(name="sb")
@click.pass_obj
def sb(ctx):
    setattr(ctx, "db", "OVNSBDump")
    pass


@nb.command(name="list")
@click.argument("table", required=False, nargs=1)
@click.pass_obj
def nb_list(ctx, table):
    """
    List the content of a OVN NB Table
    """
    return list_cmd(ctx, table)


@sb.command(name="list")
@click.argument("table", required=False, nargs=1)
@click.pass_obj
def sb_list(ctx, table):
    """
    List the content of a OVN SB Table
    """
    return list_cmd(ctx, table)


def list_cmd(ctx, table):
    """
    List the content of a DB Tabel
    """
    if not table:
        tables = ctx.client.evaluate(ctx.db, "table_list()")
        if not tables:
            print("OVN data not available")
            return

        for archive, host_data in tables.items():
            if not host_data:
                continue

            print("Archive: " + archive)
            print("*" * (9 + len(archive)))
            if isinstance(host_data, str):
                print(host_data)
            else:
                console = Console()
                console.print("Available Tables:")
                console.print(host_data)
        return

    table_data = ctx.client.evaluate(ctx.db, 'table("{}")'.format(table))
    if not table_data:
        print("OVN data not available")
        return

    for archive, host_data in table_data.items():
        if not host_data:
            continue

        print("Archive: " + archive)
        print("*" * (9 + len(archive)))
        if isinstance(host_data, str):
            print(host_data)
        else:
            print_results(host_data, table)


def print_results(table_data, table):
    console = Console()
    tt = Table(title=table)
    for header, value in table_data[next(iter(table_data.keys()))].items():
        nowrap = False

        if isinstance(value, dict):
            tt.add_column(header, justify="left", no_wrap=False, ratio=1, min_width=25)
        else:
            tt.add_column(header, justify="left", no_wrap=False, min_width=len(header))

    for elem in table_data.values():
        values = [Pretty(val) for val in elem.values()]
        tt.add_row(*values)

    console.print(tt)


@nb.command(name="get")
@click.argument("table", required=True, nargs=1)
@click.argument("uuid", required=True, nargs=1)
@click.pass_obj
def nb_get(ctx, table, uuid):
    """
    Get an element form the NB Database
    """
    return get_cmd(ctx, table, uuid)


@sb.command(name="get")
@click.argument("table", required=True, nargs=1)
@click.argument("uuid", required=True, nargs=1)
@click.pass_obj
def sb_get(ctx, table, uuid):
    """
    Get an element form the SB Database
    """
    return get_cmd(ctx, table, uuid)


def get_cmd(ctx, table, uuid):
    data = ctx.client.evaluate(
        "OVNNBDump",
        'filter("{}", lambda x: x.get("_uuid").startswith("{}"))'.format(table, uuid),
    )
    if not data:
        print("OVN data not available")
        return

    console = Console()
    console.print(data)
