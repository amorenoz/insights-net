import click
from rich.console import Console
from rich.table import Table
from rich.pretty import Pretty

@click.group(name='ovn')
@click.pass_obj
def ovn(ctx):
    """
    Show the OVN configuration
    """
    pass

@click.group(name='nb')
@click.pass_obj
def nb(ctx):
    setattr(ctx, 'db', 'OVNNBDump')

@click.group(name='sb')
@click.pass_obj
def sb(ctx):
    setattr(ctx, 'db', 'OVNSBDump')
    pass

@click.command(name='list')
@click.argument('table', required=False, nargs=1)
@click.pass_obj
def list_cmd(ctx, table):
    """
    List the content of a OVN NB Table
    """
    if not table:
        tables = ctx.client.evaluate(ctx.db, 'table_list()')
        if not tables:
            print("OVN data not available")
            return

        for archive, host_data in tables.items():
            if not host_data:
                continue

            print("Archive: " + archive)
            print("*" * (9 + len(archive)))
            if isinstance (host_data, str):
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
        if isinstance (host_data, str):
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

@click.command(name='get')
@click.argument('table', required=True, nargs=1)
@click.argument('uuid', required=True, nargs=1)
@click.pass_obj
def get_cmd(ctx, table, uuid):
    """
    Get an element form the database
    """
    data = ctx.client.evaluate('OVNNBDump', 'filter("{}", lambda x: x.get("_uuid").startswith("{}"))'.format(table, uuid))
    if not data:
        print("OVN data not available")
        return

    console = Console()
    console.print(data)

nb.add_command(list_cmd)
nb.add_command(get_cmd)
sb.add_command(list_cmd)
sb.add_command(get_cmd)
ovn.add_command(nb)
ovn.add_command(sb)

