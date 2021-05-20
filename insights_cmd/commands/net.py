import click
from tabulate import tabulate

@click.command(name='find-ip')
@click.argument("address", required=True, nargs=1)
@click.pass_obj
def find_ip(ctx, address):
    """
    Get all the available information regarding an IP(v4/6) address
    """
    data = ctx.client.run_command("find_ip", ip=address)
    if not data:
        print("Command not found")

    host_matches = data.get('ip_addr')
    if host_matches:
        for netns, match in host_matches.items():
            if len(match) > 0:
                print("Network Interface Matches (Namespace: {})".format(netns))
                print("-" * (39+(len(netns))))
                for iface in match:
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
        print("")

    neigh_matches = data.get('ip_neigh')
    if neigh_matches:
        print("Neighbor Matches")
        print("----------------")
        for neigh in neigh_matches:
            print("  Address: {}".format(neigh.get('addr')))
            print("  Device: {}".format(neigh.get('dev')))
            print("  LLAdr: {}".format(neigh.get('lladdr')))
            print("  Reachibility: {}".format(neigh.get('nud')))
            print("")
        print("")

    route_matches = data.get('ip_route')
    if route_matches:
        for netns, match in route_matches.items():
            print("Route Matches (Namespace: {})".format(netns))
            print("-" * (27 + len(netns)))
            for route in match:
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

    hosts_matches = data.get('hosts')
    if len(hosts_matches) > 0:
        print("Hosts Matches")
        print("--------------")
        for host in hosts_matches:
            print("    - Hostname: {}".format(host))
        print("")

    ipt_matches = data.get('iptables')
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

    ns_matches = data.get('netstat')
    if ns_matches:
        for where in ['Local', 'Foreign']:
            matches = ns_matches.get(where)
            if matches:
                print("")
                print("Netstat {} Address Matches".format(where))
                print("-" * (24 + len(where)))
                print(tabulate(matches, headers='keys'))

    ofctl_matches = data.get('ofctl')
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
