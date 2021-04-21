import click

from insights_cmd.command import command, backend, Command, COMMANDS
from insights_cmd.shell import Models

@command("info")
class Info(Command):
    """
    Extract basic information about insights-cmd
    """
    def __init__(self, *args, **kwargs):
        super(Info, self).__init__(*args, **kwargs)

    @backend
    def available(self):
        """
        Return available data sources
        """
        ret = dict()

        if isinstance(self._data, Models):
            ret[self._data.path] = self.get_sources(self._data)
        else:
            for path in self._data:
                ret[path] = self.get_sources(self._data)
        return ret

    def get_sources(self, model):
        return list(model.keys())

@click.command(name='info')
@click.pass_obj
def info(ctx):
    """
    Show basic information of the archives
    """
    cmd = ctx.commands.get("info")
    if not cmd:
        print("Command not found")
    if not cmd:
        print("Command not found")

    available=cmd.available()

    for archive in available.keys():
        print("Available Archives")
        print("------------------")
        print("  Name: {}".format(archive))
        print("  Available Data sources: {}".format(len(available[archive])))

    print("")
    print("Available Commands")
    print("------------------")
    for cmd in ctx.commands:
        archives = ctx.commands[cmd].available_archive()
        if len(archives) > 0:
            print("{}:".format(cmd))
            print("  {}".format(
                type(ctx.commands[cmd]).__doc__.strip()))
            print("  Available archives:")
            for archive in archives:
                print("   - {}".format(archive))
        print("")


