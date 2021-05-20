from insights import fact

from insights.combiners.hostname import Hostname
from insights.combiners.selinux import SELinux
from insights.parsers.redhat_release import RedhatRelease
from insights.parsers.uname import Uname
from insights.parsers.uptime import Uptime


@fact(Hostname, RedhatRelease, SELinux, Uname, Uptime)
def host_info(hostname, release, selinux, uname, up):
    """
    Returns a sumary of the host information
    """
    return {"hostname": hostname.fqdn,
            "version": release.parsed,
            "selinux": selinux.sestatus.data,
            "uname": {
                'version': uname.data.get('version'),
                'release': uname.data.get('release'),
                'arch': uname.data.get('arch')
                },
            "uptime": {"updays": up.updays,
                 "uphhmm": up.uphhmm,
                 "loadavg": up.loadavg,
                 }
            }
