import re
from insights import parser, CommandParser
from insights.core.context import SosArchiveContext
from insights.core.spec_factory import simple_file, glob_file
from insights.parsers import SkipException
from ovs_dbg.ofp import OFPFlow
from ovs_dbg.filter import OFFilter

from insights_net.plugins.parsers.ovsdb import (
    OVSDBParser,
    OVSDBListParser,
    ovsdb_servers,
)

ovsdb_dump = simple_file(
    "/sos_commands/openvswitch/ovsdb-client_-f_list_dump", context=SosArchiveContext
)


@parser(ovsdb_dump)
class OVSDump(OVSDBListParser):
    def __init__(self, *args, **kwargs):
        super(OVSDump, self).__init__(*args, **kwargs)
        self._name = "Open_vSwitch"


ovs_db_local = ovsdb_servers(["*.sock"], "Open_vSwitch")


@parser(ovs_db_local)
class OVSLocal(OVSDBParser):
    def __init__(self, *args, **kwargs):
        super(OVSLocal, self).__init__(*args, **kwargs)
        self._name = "OpenvSwitch"

    def parse_content(self, data):
        self._tables = data


# Openflow parsers
ofctl_dump_flows = glob_file(
    "/sos_commands/openvswitch/ovs-ofctl_dump-flows*", context=SosArchiveContext
)

ofctl_show = glob_file(
    "/sos_commands/openvswitch/ovs-ofctl_show_*", context=SosArchiveContext
)


class OVSOfctlDumpBase(CommandParser):
    def __init__(self, *args, **kwargs):
        self._flow_list = None
        self._bridge_name = None
        super(OVSOfctlDumpBase, self).__init__(*args, **kwargs)

    def parse_content(self, content):
        if not content:
            raise SkipException("Empty Content!")

        try:
            self._flow_list = OVSFlowList(content)
        except Exception as e:
            raise SkipException("Failed to parse flows") from e

    @property
    def bridge_name(self):
        return self._bridge_name

    @property
    def flow_list(self):
        return self._flow_list


@parser(ofctl_dump_flows)
class OVSOfctlDump(OVSOfctlDumpBase):
    def __init__(self, *args, **kwargs):
        super(OVSOfctlDump, self).__init__(*args, **kwargs)

    def parse_content(self, content):
        if not content:
            raise SkipException("Empty Content")
        # Extract the bridge name
        try:
            self._bridge_name = self.file_path.split("ovs-ofctl_dump-flows_")[1]
        except Exception:
            raise SkipException("Invalid Path!")

        return super(OVSOfctlDump, self).parse_content(content)


@parser(ofctl_show)
class OVSOfctlShow(CommandParser):
    """
    Input example:
    ==============
    OFPT_FEATURES_REPLY (xid=0x2): dpid:0000f613db047547
    n_tables:254, n_buffers:0
    capabilities: FLOW_STATS TABLE_STATS PORT_STATS QUEUE_STATS ARP_MATCH_IP
    actions: output enqueue set_vlan_vid set_vlan_pcp strip_vlan mod_dl_src mod_dl_dst mod_nw_src mod_nw_dst mod_nw_tos mod_tp_src mod_tp_dst
     1(int-br-link): addr:e2:c2:43:a8:6c:97
         config:     0
         state:      0
         speed: 0 Mbps now, 0 Mbps max
     2(int-br-ex): addr:da:34:23:5e:25:18
         config:     0
         state:      0
         speed: 0 Mbps now, 0 Mbps max
     LOCAL(br-int): addr:f6:13:db:04:75:47
         config:     PORT_DOWN
         state:      LINK_DOWN
         speed: 0 Mbps now, 0 Mbps max
    OFPT_GET_CONFIG_REPLY (xid=0x4): frags=normal miss_send_len=0
    """

    def __init__(self, *args, **kwargs):
        super(OVSOfctlShow, self).__init__(*args, **kwargs)

    def parse_content(self, content):
        if not content:
            raise SkipException("Empty Content!")

        # Extract the bridge name
        try:
            self._bridge_name = self.file_path.split("ovs-ofctl_show_")[1]
        except:
            raise SkipException("Invalid Path!")

        # Parse table line, e.g:
        # n_tables:254, n_buffers:0
        n_tables, _, n_buffers = content[1].strip().partition(", ")
        self._tables = int(n_tables.split(":")[1])
        self._buffers = int(n_buffers.split(":")[1])

        # Parse capabilities, e.g:
        # capabilities: FLOW_STATS TABLE_STATS PORT_STATS QUEUE_STATS
        _, _, caps = content[2].strip().partition(": ")
        self._capabilities = caps.split(" ")

        # Parse actions, e.g:
        # actions: output enqueue set_vlan_vid set_vlan_pcp strip_vlan
        _, _, actions = content[3].strip().partition(": ")
        self._actions = actions.split(" ")

        # Parse ports
        port_re = re.compile("(\w+)\(([\w-]+)\): addr:([\w:]+)")
        self._ports = []
        port_idx = -1
        for line in content[4:-1]:
            line = line.strip()
            match = port_re.match(line)
            if match:
                num_str = match.group(1)
                num_int = 0  # represents LOCAL
                try:
                    num_int = int(num_str)
                except ValueError:
                    pass

                self._ports.append(
                    {
                        "num": num_int,
                        "name": match.group(2),
                        "addr": match.group(3),
                    }
                )
                port_idx += 1
            else:
                if port_idx < 0:
                    raise SkipException("Parsing error")

                keyword, _, info = line.partition(":")
                keyword = keyword.strip()
                info = info.strip()

                if keyword == "config":
                    self._ports[port_idx]["config"] = info
                elif keyword == "state":
                    self._ports[port_idx]["state"] = info
                elif keyword == "speed":
                    m_now, _, m_max = info.partition(", ")
                    self._ports[port_idx]["speed"] = {
                        "now": m_now.split("now")[0].strip(),
                        "max": m_max.split("max")[0].strip(),
                    }

    @property
    def bridge_name(self):
        """
        (str): Get the bridge name
        """
        return self._bridge_name

    def port(self, num):
        """
        (dict) or None: Get the port with matching num
        """
        for port in self._ports:
            if port["num"] == num:
                return port

        return None

    @property
    def ports(self):
        """
        (list): Returns the list of port dicts
        """
        return self._ports

    @property
    def capabilities(self):
        """
        (list): Returns the list of capabilities
        """
        return self._capabilities

    @property
    def actions(self):
        """
        (list): Returns the list of actions
        """
        return self._actions

    @property
    def tables(self):
        """
        (int): Returns the number of tables
        """
        return self._tables

    @property
    def buffers(self):
        """
        (int): Returns the number of buffers
        """
        return self._buffers


class OVSFlowList(object):
    """OVSFlowList represents a list of flows

    It parsers a list of strings and exposes some useful commands

    Args:
        flow_list(list(str)): list of strings with flows
    """

    def __init__(self, flow_list):
        self._flows = []
        for flow_string in flow_list:
            if " reply " in flow_string:
                continue
            self._flows.append(OFPFlow.from_string(flow_string))

    @property
    def flows(self):
        return self._flows

    @property
    def len(self):
        return len(self._flows)

    def find(self, expr):
        """
        Find flows that match expr.

        expr(str): an expression following ovs-dbg's flitering syntax (see
            https://ovs-dbg.readthedocs.io/en/latest/ofparse.html#filtering)

        The filtering syntax is defined as follows

        [! | not ] KEY[OPERATOR VALUE] [ && | and | || | or] ...

        Where:
            “=” checks for equality
            “<” numerical ‘less than’
            “>” numerical ‘greater than’
            “~=” mask matching (valid for fields such as IPv4, IPv6 and Ethernet)

            VALUE: The value to be compared against

            && | and: combines the filters applying logical AND
            || | or: combines the filters applying logical OR
            ! | not: applies the logical NOT to the filter

        For fields or actions that are flags (e.g: tcp or drop), the OPERATOR and VALUE can be omitted

        Examples:

        n_bytes>0 and drop
        nw_src~=192.168.1.1 or arp.tsa=192.168.1.1
        ! tcp && output.port=2
        """
        result = []
        filt = OFFilter(expr)
        for flow in self._flows:
            if filt.evaluate(flow):
                result.append(flow)
        return result
