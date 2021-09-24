"""
Extensions to insights/parsers/ip.py
TODO: send PR to insights-core
"""
import re

from insights import parser
from insights.parsers import SkipException
from insights.parsers.ip import IpAddr, RouteDevices
from insights.core.context import SosArchiveContext
from insights.core.spec_factory import glob_file

ip_netns_ipaddr = glob_file(
    "/sos_commands/networking/ip_netns_exec_*_ip_address_show",
    context=SosArchiveContext,
)

ip_netns_iproute = glob_file(
    "/sos_commands/networking/ip_netns_exec_*_ip_route_show_table_all",
    context=SosArchiveContext,
)


@parser(ip_netns_ipaddr)
class NetNsIpAddr(IpAddr):
    """
    Extends IpAddr to also parse all namespaces
    """

    FILE_RE_STR = "ip_netns_exec_([\w_-]+)_ip_address_show"
    file_re = re.compile(FILE_RE_STR)

    def __init__(self, *args, **kwargs):
        super(NetNsIpAddr, self).__init__(*args, **kwargs)

    @property
    def netns(self):
        return self._netns

    def parse_content(self, content):
        match = self.file_re.match(self.file_name)
        if not match or not match.group(1):
            raise SkipException("Wrong file name")

        self._netns = match.group(1)

        return IpAddr.parse_content(self, content)


@parser(ip_netns_iproute)
class NetNsIpRoute(RouteDevices):
    """
    Extends RouteDevices to also parse all namespaces
    """

    FILE_RE_STR = "ip_netns_exec_([\w_-]+)_ip_route_show_table_all"
    file_re = re.compile(FILE_RE_STR)

    def __init__(self, *args, **kwargs):
        super(NetNsIpRoute, self).__init__(*args, **kwargs)

    @property
    def netns(self):
        return self._netns

    def parse_content(self, content):
        match = self.file_re.match(self.file_name)
        if not match or not match.group(1):
            raise SkipException("Wrong file name")

        self._netns = match.group(1)

        return RouteDevices.parse_content(self, content)
