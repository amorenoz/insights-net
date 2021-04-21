import click

from insights_cmd.command import command, backend, Command, CommandDepends


host_depends=CommandDepends({
    "required": [[
    "insights_combiners_hostname_Hostname",
    "RedhatRelease",
    "SELinux",
    "Uname",
    "uptime",
    ]]
})

@command("host", host_depends)
class Host(Command):
    """
    Extract information about the host (currently only sos)
    """
    def __init__(self, *args, **kwargs):
        super(Host, self).__init__(*args, **kwargs)

    @backend
    def hostname(self):
        return self._data.insights_combiners_hostname_Hostname.fqdn

    @backend
    def rh_version(self):
        return self._data.RedhatRelease.parsed

    @backend
    def selinux(self):
        return self._data.SELinux.sestatus.data

    @backend
    def uname(self):
        uname = self._data.Uname.data
        return {
            'version': uname.get('version'),
            'release': uname.get('release'),
            'arch': uname.get('arch')
        }

    @backend
    def uptime(self):
        up = self._data.uptime
        return {
        "updays": up.updays,
        "uphhmm": up.uphhmm,
        "loadavg": up.loadavg,
        }


@click.command(name='host')
@click.pass_obj
def host(ctx):
    """
    Show basic host information
    """
    cmd = ctx.commands.get("host")
    if not cmd:
        print("Command not found")

    print("HostName: {}".format(cmd.hostname()))
    rh_ver = cmd.rh_version()
    print("Red Hat Version:")
    print("  Product: {}".format(rh_ver.get('product')))
    print("  Version: {}".format(rh_ver.get('version')))
    print("  Code Name: {}".format(rh_ver.get('code_name')))

    uname = cmd.uname()
    print("Kernel:")
    print("  Version : {}".format(uname.get('version')))
    print("  Release: {}".format(uname.get('release')))
    print("  Arch: {}".format(uname.get('arch')))

    up= cmd.uptime()
    print("Uptime for {} days {} hh:mm".format(up.get('updays'), up.get('uphhmm')))

    print("Selinux: {}".format(cmd.selinux().get('selinux_status')))


