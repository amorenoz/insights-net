# -*- coding: utf-8 -*-

import click

from insights_cmd.client import InsightsClient

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
    Stop the background running insights kernel
    """
    obj.client.close()

def main():
    maincli()
