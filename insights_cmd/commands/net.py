import click
import re
from tabulate import tabulate

from functools import partial

from insights.contrib import ipaddress

from insights_cmd.command import command, backend, Command


@command("ip")
class IP(Command):
    """
    Get IP address information
    """
    def __init__(self, *args, **kwargs):
        super(IP, self).__init__(*args, **kwargs)

    @backend
    def find_in_host(self, ip):
        ipdata = self._data.IpAddr
        return self._find_in_addrs(ip, ipdata)

    def _find_in_addrs(self, ip, ipdata):
        """
        Finds the ip address in the IpAddr parser
        """
        matches = []
        addr = ipaddress.ip_address(ip)
        if not ipdata:
            return matches

        for iname, idata in ipdata.data.items():
            if any([addr == ipiface.ip for ipiface in idata.addresses]):
                matches.append(idata.data)

        return matches

    @backend
    def find_in_routes(self, ip):
        rt = self._data.RouteDevices.data
        return self._find_in_routes(ip, rt)

    def _find_in_routes(self, ip, rt):
        """
        Finds the ip address in the RouteDevices parser
        """
        addr = ipaddress.ip_address(ip)
        matches = []
        if not rt:
            return matches

        for match, route in rt.items():
            if match == "default":
                continue

            if self._compare_ip_or_net(addr, match):
                matches.append({
                    'match': match,
                    'routes': [r.__dict__ for r in route]
                })

        if len(matches) == 0 and rt.get('default'):
            matches.append({
                'match': 'default',
                'routes': [r.__dict__ for r in rt.get('default')]
            })

        return matches

    @backend
    def find_in_neigh(self, ip):
        matches = []
        addr = ipaddress.ip_address(ip)
        neighdata = self._data.IpNeighShow
        if not neighdata:
            return matches

        for neigh, data in neighdata.data.items():
            if data.get('addr') == addr:
                append_data = data.copy()
                append_data['addr'] = neigh
                matches.append(append_data)

        return matches

    @backend
    def find_in_hosts(self, ip):
        matches = []
        addr = ipaddress.ip_address(ip)
        host_data = self._data.Hosts.data
        if not host_data:
            return matches

        for host_ip, hosts in host_data.items():
            ip = ipaddress.ip_address(host_ip)
            if addr == ip:
                matches.extend(hosts)

        return matches

    @backend
    def find_in_iptables(self, ip):
        addr = ipaddress.ip_address(ip)
        matches = {}
        for config in [
                "IPTabPermanent", "IP6TabPermanent", "IPTables", "IP6Tables"
        ]:
            data_source = getattr(self._data, config, None)
            if data_source is not None:
                match = self.find_in_iptables_common(addr, data_source)
                matches[config] = match

        return matches

    def find_in_iptables_common(self, addr, ipt):
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
                    if self.find_in_rule(addr, rule['rule']):
                        matches.append({
                            "chain": chain,
                            "rule": rule,
                        })
        return matches

    def find_in_rule(self, addr, rule):
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
            "regexp":
            re.compile('--to-destination\s([\w.:]*):\d+-\d+\s'),
        }]

        for match in matches:
            result = match.get('regexp').search(rule)
            if result:
                if self._compare_ip_or_net(addr, result.group(1)):
                    return True

        return False

    def _compare_ip_or_net(self, addr, match):
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

    @backend
    def find_in_netstat(self, ip):
        """
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
        addr = ipaddress.ip_address(ip)
        ipcons = 'Active Internet connections (servers and established)'
        ns = self._data.Netstat.datalist[ipcons]

        def compare_ip_port(addr, ip_port):
            """
            compares addr (IPAddress) with the ipport string {IP}:{Port}
            """
            ip, _, port = ip_port.rpartition(':')
            return addr == ipaddress.ip_address(ip)

        return {
            'Local':
            list(
                filter(lambda r: compare_ip_port(addr, r['Local Address']),
                       ns)),
            'Foreign':
            list(
                filter(lambda r: compare_ip_port(addr, r['Foreign Address']),
                       ns)),
        }

    @backend
    def find_in_ofctl(self, ip):
        """
        Finds in plugin.ofctl dumps
        """
        addr = ipaddress.ip_address(ip)
        if 'OVSOfctlFlows' not in self._data:
            return

        ofctls = self._data.OVSOfctlFlows

        result = {}
        for ofctl in ofctls:
            flows = []
            for flow in ofctl.flow_dumps:
                for match, value in flow.get('match').items():
                    # TODO: search on match fields that we know there might be
                    # IP addresses
                    try:
                        if self._compare_ip_or_net(addr, value):
                            flows.append(flow)
                    except ValueError:
                        pass

                for action in flow.get('actions'):
                    # TODO: search on actions params that we know there might be
                    # IP addresses
                    try:
                        if self._compare_ip_or_net(addr, action.get('params')):
                            flows.append(flow)
                    except ValueError:
                        pass

            if flows:
                result[ofctl.bridge_name] = flows

        return result


@click.command(name='find-ip')
@click.argument("address", required=True, nargs=1)
@click.pass_obj
def find_ip(ctx, address):
    """
    Get all the available information regarding an IP(v4/6) address
    """
    cmd = ctx.commands.get("ip")
    host_matches = cmd.find_in_host(address)

    if len(host_matches) > 0:
        print("Host Interface Matches")
        print("----------------------")
        for iface in host_matches:
            print("  - Name: {}".format(iface.get('name')))
            print("    Type: {}".format(iface.get('type')))
            print("    Addresses:")
            for addr in iface.get('addr'):
                print("     - {}/{}".format(addr.get('addr'),
                                            addr.get('mask')))
            print("    MAC: {}".format(iface.get('mac')))
            print("    MTU: {}".format(iface.get('mtu')))
            print("    State: {}".format(iface.get('state')))
            print("    QDisc: {}".format(iface.get('qdisc')))
            print("")
        print("")

    neigh_matches = cmd.find_in_neigh(address)
    if len(neigh_matches) > 0:
        print("Neighbor Matches")
        print("----------------")
        for neigh in neigh_matches:
            print("  Address: {}".format(neigh.get('addr')))
            print("  Device: {}".format(neigh.get('dev')))
            print("  LLAdr: {}".format(neigh.get('lladdr')))
            print("  Reachibility: {}".format(neigh.get('nud')))
            print("")
        print("")

    route_matches = cmd.find_in_routes(address)
    if len(route_matches) > 0:
        print("Route Matches")
        print("--------------")
        for route in route_matches:
            print("{}: ".format(route.get('match')))
            for entry in route.get('routes'):
                print("    - Prefix: {}".format(entry.get('prefix')))
                print("      Via: {}".format(entry.get('via')))
                print("      Dev: {}".format(entry.get('dev')))
                print("      Table: {}".format(entry.get('table')))
                print("      Metric: {}".format(entry.get('metric')))
                print("      Pref: {}".format(entry.get('pref')))
                print("")
        print("")

    hosts_matches = cmd.find_in_hosts(address)
    if len(hosts_matches) > 0:
        print("Hosts Matches")
        print("--------------")
        for host in hosts_matches:
            print("    - Hostname: {}".format(host))
        print("")

    ipt_matches = cmd.find_in_iptables(address)
    if ipt_matches:
        for config, matches in ipt_matches.items():
            if len(matches) > 0:
                print("{} Matches".format(config))
                print("-" * (len(config) + 8))
                for match in matches:
                    rule = match.get('rule')
                    print("    - Chain: {}".format(match.get('chain')))
                    print("      Table: {}".format(rule.get('table')))
                    print("      Rule: {}".format(rule.get('rule')))
                print("")
        print("")

    ns_matches = cmd.find_in_netstat(address)
    if ns_matches:
        for where in ['Local', 'Foreign']:
            matches = ns_matches.get(where)
            if matches:
                print("")
                print("Netstat {} Address Matches".format(where))
                print("-" * (24 + len(where)))
                print(tabulate(matches, headers='keys'))

    ofctl_matches = cmd.find_in_ofctl(address)
    if ofctl_matches:
        for bridge in ofctl_matches.keys():
            flows = ofctl_matches.get(bridge)
            if flows:
                print("")
                print("Ofproto flow Matches on bridge {}".format(bridge))
                print("-" * (31 + len(bridge)))
                print("")

                drops = list(
                    filter(lambda x : {'action': 'drop'} in x['actions'], flows))

                if drops:
                    print("DROPS:")
                    print_ofproto_flows(drops)

                print("ALL FLOWS:")
                print_ofproto_flows(flows)

def print_ofproto_flows(flows):
    for table in set([flow['match'].get('table') for flow in flows]):
        print("   * Table {}".format(table))
        for flow in filter(
                lambda f: f['match'].get('table') == table, flows):
            print("     {}".format(flow.get('raw')))
    print("")
