import re

from insights.core.plugins import command
from insights.contrib import ipaddress
from insights.parsers.ip import IpAddr, RouteDevices, IpNeighShow
from insights.parsers.hosts import Hosts
from insights.parsers.iptables import IPTabPermanent, IP6TabPermanent, IPTables, IP6Tables
from insights.parsers.netstat import Netstat

from .ip import NetNsIpAddr, NetNsIpAddr, NetNsIpRoute
from .ofctl import OVSOfctlFlows


@command(optional=[
    IpAddr, RouteDevices, IpNeighShow, Hosts, IPTabPermanent, IP6TabPermanent,
    IP6Tables, IPTables, Netstat, NetNsIpAddr, NetNsIpRoute, OVSOfctlFlows
])
def find_ip(params, ipaddr, iproute, ipneigh, hosts, iptperm, ip6tperm, ip6tables,
            iptables, netstat, nsipaddr, nsiproute, ofctl):
    """
    Find an IP address in a number of possible places.
    Returns a dict with each key being the name of the place where a match was
    found:
    """
    ip_string = params.params.get('ip')
    ip_addr = ipaddress.ip_address(ip_string)
    result = dict()

    ## Find in ip addr
    allip = [ipaddr]
    if nsipaddr:
        for ns in nsipaddr:
            allip.append(ns)

    ipaddr_matches = find_in_ipaddrs(ip_addr, allip)
    if ipaddr_matches:
        result["ip_addr"] = ipaddr_matches

    # Find in ip route
    allroute = [iproute]
    if nsiproute:
        for nsr in nsiproute:
            allroute.append(nsr)

    route_matches = find_in_routes(ip_addr, allroute)
    if route_matches:
        result["ip_route"] = route_matches

    # Find in neigh
    neigh_matches = find_in_neigh(ip_addr, ipneigh)
    if neigh_matches:
        result["ip_neigh"] = neigh_matches

    # Find in hosts
    host_matches = find_in_hosts(ip_addr, hosts)
    if host_matches:
        result["hosts"] = host_matches

    # Find in iptables
    ipt_matches = find_in_iptables(ip_addr,
                                   [iptperm, ip6tperm, ip6tables, iptables])
    if ipt_matches:
        result["iptables"] = ipt_matches

    #Find in netstat
    netstat_matches = find_in_netstat(ip_addr, netstat)
    if netstat_matches:
        result["netstat"] = netstat_matches

    #Find in ovs ofctl dumps
    ofctl_matches = find_in_ofctl(ip_addr, ofctl)
    if ofctl_matches:
        result["ofctl"] = ofctl_matches

    return result

def find_in_ipaddrs(addr, ipaddr_parsers):
    """
    Finds an ip address in IPAddr objects
    Arg:
        addr: IpAddr object
        ipaddr_parsers: list of IPAddr Parsers
    """
    result = dict()
    ipdata = []
    for ipd in ipaddr_parsers:
        if not ipd:
            continue
        match = find_in_addrs(addr, ipd)
        if match:
            netns = ipd.netns if hasattr(ipd, "netns") else "default"
            result[netns] = match

    return result


def find_in_addrs(addr, ipdata):
    """
    Finds the ip address in the IpAddr parser
    Args:
        addr: IPAddr object
        ipdata: and instance of insights.parser.IpAddr
    """
    matches = []
    if not ipdata:
        return matches

    for iname, idata in ipdata.data.items():
        if any([addr == ipiface.ip for ipiface in idata.addresses]):
            matches.append(idata.data)

    return matches


def find_in_routes(addr, route_data):
    """
    Find the ip address in IPRouteDevice instances
    Addr:
        addr: IpAddr object
        route_data: list of IPRouteDevices
    """
    result = {}
    route_data = []
    for route in route_data:
        match = _find_in_routes(addr, route)
        if match:
            netns = route.netns if hasattr(route, "netns") else "default"
            result[netns] = match

    return result


def _find_in_routes(addr, rt):
    """
    Finds the ip address in the RouteDevices parser
    """
    matches = []
    if not rt:
        return matches

    for match, route in rt.data.items():
        if match == "default":
            continue

        if _compare_ip_or_net(addr, match):
            matches.append({
                'match': match,
                'routes': [r.__dict__ for r in route]
            })

    if len(matches) == 0 and rt.data.get('default'):
        matches.append({
            'match': 'default',
            'routes': [r.__dict__ for r in rt.data.get('default')]
        })

    return matches


def find_in_neigh(addr, neigh):
    """
    Find in IPNeighShow parser
    """
    matches = []
    if not neigh:
        return matches

    for neigh, data in neigh.data.items():
        if data.get('addr') == addr:
            append_data = data.copy()
            append_data['addr'] = neigh
            matches.append(append_data)

    return matches


def find_in_hosts(addr, host_parser):
    """
    Find in Hosts parser
    """
    matches = []
    if not host_parser:
        return matches

    for host_ip, hosts in host_parser.data.items():
        ip = ipaddress.ip_address(host_ip)
        if addr == ip:
            matches.extend(hosts)

    return matches


def find_in_iptables(addr, ipt_parsers):
    """
    Find an ipaddress in a list of insights.parser.IPTAblesConfiguration objects
    Args:
        addr: an IPAddress object
        ipt_parsers: list of insights.parser.IPTAblesConfiguration objects

    """
    matches = {}
    for data_source in ipt_parsers:
        if data_source is not None:
            match = find_in_iptables_common(addr, data_source)
            matches[data_source.__class__.__name__] = match

    return matches


def find_in_iptables_common(addr, ipt):
    """
    Only filter and nat tables supported
    ip: IPAddress object
    ipt: insights.parser.IPTAblesConfiguration
    """
    matches = []

    tables = ["filter", "nat"]
    for table in tables:
        for chain, rules in ipt.table_chains(table).items():
            for rule in rules:
                if find_in_rule(addr, rule['rule']):
                    matches.append({
                        "chain": chain,
                        "rule": rule,
                    })
    return matches


def find_in_rule(addr, rule):
    """
    Looks for the ipAddres object (IPv4Address or IPv6Address) in the iptables
    rule string.
    Current rule matching supports:
        -s {IP}[/mask]
        -d {IP}[/mask]
        --to-destination {IP}[:{port}[-{port}]]
        --to-source {IP}[:{port}[-{port}]]

    Maybe this functionality could go in the nftables parser?
    """
    matches = [{
        "regexp": re.compile('-s\s([\w.:/]*)\s'),
    }, {
        "regexp": re.compile('-d\s([\w.:/]*)\s'),
    }, {
        "regexp": re.compile('--to-source\s([\w.:]*)\s'),
    }, {
        "regexp": re.compile('--to-destination\s([\w.:]*)\s'),
    }, {
        "regexp": re.compile('--to-source\s([\w.:]*):\d+\s'),
    }, {
        "regexp": re.compile('--to-destination\s([\w.:]*):\d+\s'),
    }, {
        "regexp": re.compile('--to-source\s([\w.:]*):\d+-\d+\s'),
    }, {
        "regexp": re.compile('--to-destination\s([\w.:]*):\d+-\d+\s'),
    }]

    for match in matches:
        result = match.get('regexp').search(rule)
        if result:
            if _compare_ip_or_net(addr, result.group(1)):
                return True

    return False


def _compare_ip_or_net(addr, match):
    """
    Tries to compare match string with an ipaddress object
    The match string can be an IP address or a subnet
    """
    try:
        net = ipaddress.ip_network(match)
        if addr in net:
            return True
    except ValueError:
        ip = ipaddress.ip_address(match)
        if addr == ip:
            return True

    return False


def find_in_netstat(addr, netstat):
    """
    Find ip address in a Netstat Parsers object
    Returns a dict keyed by Local or Foreign dependin on what column the match
    was made, e.g:
        {
        "Local": [{'Proto': 'tcp',
                   'Recv-Q': '0',
                   'Send-Q': '0',
                   'Local Address': '127.0.0.1:6633',
                   'Foreign Address': '0.0.0.0:*',
                   'State': 'LISTEN',
                   'User': '42435',
                   'Inode': '368485',
                   'PID/Program name': '61707/openvswitch-a',
                   'Timer': 'off (0.00/0/0)',
                   'PID': '61707',
                   'Program name': 'openvswitch-a',
                   'Local IP': '127.0.0.1',
                   'Port': '6633'},...],
        "Foreign":[...]
        }
    """
    ipcons = 'Active Internet connections (servers and established)'
    if not netstat:
        return {}

    ns = netstat.datalist[ipcons]

    def compare_ip_port(addr, ip_port):
        """
        compares addr (IPAddress) with the ipport string {IP}:{Port}
        """
        ip, _, port = ip_port.rpartition(':')
        return addr == ipaddress.ip_address(ip)

    return {
        'Local':
        list(filter(lambda r: compare_ip_port(addr, r['Local Address']), ns)),
        'Foreign':
        list(filter(lambda r: compare_ip_port(addr, r['Foreign Address']),
                    ns)),
    }


def find_in_ofctl(addr, ofctls):
    """
    Finds in a list of plugin.OVSOfctlFlows dumps
    """
    if not ofctls:
        return

    result = {}
    for ofctl in ofctls:
        if not ofctl:
            continue
        flows = []
        for flow in ofctl.flow_dumps:
            for match, value in flow.get('match').items():
                # TODO: search on match fields that we know there might be
                # IP addresses
                try:
                    if _compare_ip_or_net(addr, value):
                        flows.append(flow)
                except ValueError:
                    pass

            for action in flow.get('actions'):
                # TODO: search on actions params that we know there might be
                # IP addresses
                try:
                    if _compare_ip_or_net(addr, action.get('params')):
                        flows.append(flow)
                except ValueError:
                    pass

        if flows:
            result[ofctl.bridge_name] = flows

    return result
