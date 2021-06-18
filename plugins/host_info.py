from insights import fact

from insights.combiners.hostname import Hostname
from insights.combiners.selinux import SELinux
from insights.parsers.redhat_release import RedhatRelease
from insights.parsers.uname import Uname
from insights.parsers.uptime import Uptime


@fact(optional=[Hostname, RedhatRelease, SELinux, Uname, Uptime])
def host_info(hostname, release, selinux, uname, up):
    """
    Returns a sumary of the host information
    """
    return {"hostname": hostname.fqdn if hostname else "Unavailable",
            "version": release.parsed if release else "Unavailable",
            "selinux": selinux.sestatus.data if selinux else "Unavailable",
            "uname": {
                'version': uname.data.get('version') if uname else "Unavailable",
                'release': uname.data.get('release') if uname else "Unavailable",
                'arch': uname.data.get('arch') if uname else "Unavailable"
                } ,
            "uptime": {"updays": up.updays if up else "Unavailable",
                 "uphhmm": up.uphhmm if up else "Unavailable",
                 "loadavg": up.loadavg if up else "Unavailable",
                 }
            }
