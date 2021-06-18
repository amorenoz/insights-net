# -*- coding: utf-8 -*-

import click

from insights_cmd.client import InsightsClient

from insights_cmd.commands.info import info
from insights_cmd.commands.host import host
from insights_cmd.commands.net import find_ip
from insights_cmd.commands.ovn import ovn

class Context(object):
    def __init__(self, verbose=False):
        self.client = InsightsClient(verbose)
        self.verbose = verbose

@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Be verbose")
@click.pass_context
def maincli(ctx, verbose):
    ctx.obj = Context(verbose=verbose)
    pass


@click.command(name='stop')
@click.pass_obj
def stop(obj):
    """
    Stop the background running kernel
    """
    obj.client.close()


@click.command(name='start')
@click.option("-p", "--plugins", default="", help="Comma separated list of packages to load")
@click.option("-c", "--config", default="", help="The insights configuration to apply")
@click.argument("paths", required=False, nargs=-1, type=click.Path(exists=True))
@click.pass_obj
def start(obj, paths, plugins, config):
    """
    Start the insights-core backend.
    """
    print("Run insights-shell with the '-k' flag")

maincli.add_command(stop)
maincli.add_command(start)
maincli.add_command(info)
maincli.add_command(host)
maincli.add_command(find_ip)
maincli.add_command(ovn)

def main():
    maincli()
