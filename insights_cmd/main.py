# -*- coding: utf-8 -*-

import click

from insights_cmd.shell import start_shell
from insights_cmd.command import COMMANDS, Control, init_client

from insights_cmd.commands.info import info
from insights_cmd.commands.host import host
from insights_cmd.commands.net import find_ip

class Context(object):
    def __init__(self, verbose=False):
        self.commands = dict()
        for name in COMMANDS:
            self.commands[name] = COMMANDS[name](verbose=verbose)

        setattr(self, "commands", self.commands)
        setattr(self, "verbose", verbose)

@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Be verbose")
@click.pass_context
def maincli(ctx, verbose):
    ctx.obj = Context(verbose=verbose)
    pass


@click.command(name='stop')
def stop():
    """
    Stop the background running kernel
    """
    control = Control()
    control.quit()

maincli.add_command(stop)

@click.command(name='start')
@click.option("-p", "--plugins", default="", help="Comma separated list of packages to load")
@click.option("-c", "--config", default="", help="The insights configuration to apply")
@click.argument("paths", required=False, nargs=-1, type=click.Path(exists=True))
@click.pass_obj
def start(obj, paths, plugins, config):
    """
    Start the insights-core backend.
    PATHS point to archives or paths to analyze. Leave off to target the current system.
    """
    return start_shell(paths=paths,
                       plugins=plugins,
                       config=config,
                       no_coverage=False,
                       no_defaults=False,
                       verbose=obj.verbose)

maincli.add_command(start)
maincli.add_command(info)
maincli.add_command(host)
maincli.add_command(find_ip)

def main():
    init_client()
    maincli()
