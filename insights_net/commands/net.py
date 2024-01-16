import click
import yaml
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.emoji import Emoji
from rich.style import Style
from ovs.flow.ofp import OFPFlow
from ovs.flow.filter import OFFilter

from insights_net.main import maincli

from insights_net.commands.printing import (
    print_table,
    print_section_header,
    print_archive_header,
)


@maincli.command(name="find-ip")
@click.argument("address", required=True, nargs=1)
@click.option(
    "-l",
    "--list",
    "list_flag",
    is_flag=True,
    default=False,
    show_default=True,
    help="Show tables as lists of elements (useful if tables are too big)",
)
@click.pass_obj
def find_ip(ctx, address, list_flag):
    """
    Get all the available information regarding an IP(v4/6) address
    """
    data = ctx.client.run_command("find_ip", ip=address)
    if not data:
        print("Command not found")
        return

    console = Console()

    for archive, host_data in data.items():
        if not host_data:
            continue

        print_archive_header(console, archive)

        if isinstance(host_data, str):
            console.print(host_data)
        else:
            print_results(console, host_data, list_flag)
        print("")


def print_results(console, data, tables_as_lists=False):
    host_matches = data.get("ip_addr")
    if host_matches:
        for netns, match in host_matches.items():
            if len(match) > 0:
                print_section_header(
                    console, "Network Interface Matches (Namespace: {})".format(netns)
                )
                for iface in match:
                    console.print("  - Name: {}".format(iface.get("name")))
                    console.print("    Type: {}".format(iface.get("type")))
                    console.print("    Addresses:")
                    for addr in iface.get("addr"):
                        console.print(
                            "     - {}/{}".format(addr.get("addr"), addr.get("mask"))
                        )
                    console.print("    MAC: {}".format(iface.get("mac")))
                    console.print("    MTU: {}".format(iface.get("mtu")))
                    console.print("    State: {}".format(iface.get("state")))
                    console.print("    QDisc: {}".format(iface.get("qdisc")))
                    console.print("")
                console.print("")
        console.print("")

    neigh_matches = data.get("ip_neigh")
    if neigh_matches:
        print_section_header(console, "Neighbor Matches")
        for neigh in neigh_matches:
            console.print("  Address: {}".format(neigh.get("addr")))
            console.print("  Device: {}".format(neigh.get("dev")))
            console.print("  LLAdr: {}".format(neigh.get("lladdr")))
            console.print("  Reachibility: {}".format(neigh.get("nud")))
            console.print("")
        console.print("")

    route_matches = data.get("ip_route")
    if route_matches:
        for netns, match in route_matches.items():
            print_section_header(console, "Route Matches (Namespace: {})".format(netns))
            for route in match:
                console.print("{}: ".format(route.get("match")))
                for entry in route.get("routes"):
                    console.print(
                        "    - [bold]Prefix:[/bold] {}".format(entry.get("prefix"))
                    )
                    console.print("      [bold]Via:[/bold] {}".format(entry.get("via")))
                    console.print("      [bold]Dev:[/bold] {}".format(entry.get("dev")))
                    console.print(
                        "      [bold]Table:[/bold] {}".format(entry.get("table"))
                    )
                    console.print(
                        "      [bold]Metric:[/bold] {}".format(entry.get("metric"))
                    )
                    console.print(
                        "      [bold]Pref:[/bold] {}".format(entry.get("pref"))
                    )
                    console.print("")
                console.print("")

    hosts_matches = data.get("hosts")
    if host_matches and len(hosts_matches) > 0:
        print_section_header(console, "Hosts Matches")
        for host in hosts_matches:
            console.print("    - [bold] Hostname:[/bold] {}".format(host))
        console.print("")

    ipt_matches = data.get("iptables")
    if ipt_matches:
        for config, matches in ipt_matches.items():
            if len(matches) > 0:
                print_section_header(console, "{} Matches".format(config))
                for match in matches:
                    rule = match.get("rule")
                    console.print(
                        "    - [bold]Chain:[/bold] {}".format(match.get("chain"))
                    )
                    console.print(
                        "      [bold]Table:[/bold] {}".format(rule.get("table"))
                    )
                    console.print(
                        "      [bold]Rule:[/bold] {}".format(rule.get("rule"))
                    )
                console.print("")
        console.print("")

    ns_matches = data.get("netstat")
    if ns_matches:
        for where in ["Local", "Foreign"]:
            matches = ns_matches.get(where)
            if matches:
                print_section_header(
                    console, "Netstat {} Address Matches".format(where)
                )
                print_table(console, matches, "Netstat " + where, tables_as_lists)
                console.print("")

    ofctl_matches = data.get("ofctl")
    if ofctl_matches:
        for bridge in ofctl_matches.keys():
            flows = ofctl_matches.get(bridge)
            if flows:
                parsed_flows = [OFPFlow.from_string(f) for f in flows]
                print_section_header(
                    console, "Ofproto flow Matches on bridge {}".format(bridge)
                )
                console.print("")

                drop_filter = OFFilter("drop")

                drops = list(filter(drop_filter.evaluate, parsed_flows))

                if drops:
                    console.print("[bold] DROPS:[/bold]")
                    print_ofproto_flows(console, drops)

                console.print("[bold] ALL FLOWS:[/bold]")
                print_ofproto_flows(console, parsed_flows)
        console.print("")

    ovs_matches = data.get("ovs")
    if ovs_matches:
        print_section_header(console, "OpenvSwitch Configuration Matches")
        for table, rows in ovs_matches.items():
            console.print("   * Table {}".format(table))
            print_table(console, rows, table, tables_as_lists)
            console.print("")
        console.print("")

    nb_matches = data.get("nb")
    if nb_matches:
        print_section_header(console, "OVN North Bound Matches")
        for table, rows in nb_matches.items():
            console.print("   * Table {}".format(table))
            print_table(console, rows, table, tables_as_lists)
            console.print("")
        console.print("")

    sb_matches = data.get("sb")
    if sb_matches:
        print_section_header(console, "OVN South Bound Matches")
        for table, rows in sb_matches.items():
            console.print("   * Table {}".format(table))
            print_table(console, rows, table, tables_as_lists)
            console.print("")
        console.print("")

    pods_matches = data.get("pods")
    if pods_matches:
        print_section_header(console, "OCP Pod Matches")
        for pod in pods_matches:
            console.print(
                "   * Pod Name: {}  Namespace {} matches in field {}: {}".format(
                    pod.get("name"),
                    pod.get("namespace"),
                    pod.get("field"),
                    pod.get("match"),
                )
            )
            console.print("   * Pod full config:")
            console.print(yaml.dump(pod.get("full")))
            console.print("")
        console.print("")

    services_matches = data.get("services")
    if services_matches:
        print_section_header(console, "OCP Services Matches")
        for service in services_matches:
            console.print(
                "   * Service Name: {}  Namespace {} matches in field {}: {}".format(
                    service.get("name"),
                    service.get("namespace"),
                    service.get("field"),
                    service.get("match"),
                )
            )
            console.print("   * service full config:")
            console.print(yaml.dump(service.get("full")))
            console.print("")
        console.print("")

    ocpnet_matches = data.get("ocp_net")
    if ocpnet_matches:
        print_section_header(console, "OCP Network Configuration Matches")
        for conf in ocpnet_matches:
            console.print(
                "   * Network Name: {} matches in field {}: {}".format(
                    conf.get("name"), conf.get("field"), conf.get("match")
                )
            )
            console.print("   * Network full config:")
            console.print(yaml.dump(conf.get("full")))
            console.print("")
        console.print("")


def print_ofproto_flows(console, flows):
    """
    Args:
        console (rich.Console) console to print
        flows (list[OFPFlow]): list of flows to print
    """
    for table in set([flow.info.get("table") for flow in flows]):
        console.print("   * Table {}".format(table))
        for flow in filter(lambda f: f.info.get("table") == table, flows):
            console.print(Text("      {} ".format(str(flow)), style=Style()))
    console.print("")
