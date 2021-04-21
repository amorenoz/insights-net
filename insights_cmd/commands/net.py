import click
import re

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
        matches = []
        addr = ipaddress.ip_address(ip)
        ipdata = self._data.IpAddr
        if not ipdata:
            return matches

        for iname, idata in ipdata.data.items():
            if any([addr == ipiface.ip for ipiface in idata.addresses]):
                matches.append(idata.data)

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
    def find_in_routes(self, ip):
        matches = []
        addr = ipaddress.ip_address(ip)
        rt = self._data.RouteDevices.data
        if not rt:
            return matches

        for match, route in rt.items():
            if match == "default":
                continue
            got_match = False
            try:
                net = ipaddress.ip_network(match)
                if addr in net:
                    got_match = True
            except ValueError:
                ip = ipaddress.ip_address(match)
                if addr == ip:
                    got_match = True

            if got_match:
                matches.append({
                    'match': match,
                    'routes': [r.__dict__ for r in route]
                })

        if len(matches) == 0 and rt.get('default'):
            matches.append(
                {'match': 'default',
                  'routes': [r.__dict__ for r in rt.get('default')]
                }
            )

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
                print("     - {}/{}".format(addr.get('addr'), addr.get('mask')))
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

