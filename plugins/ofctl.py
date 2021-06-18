import re

from insights import CommandParser, parser, datasource
from insights.parsers import SkipException, split_kv_pairs
from insights.specs import Specs

# Include the spec in the sosreport context
from insights.core.context import SosArchiveContext
from insights.core.spec_factory import SpecSet, glob_file, simple_file

from .ofp_actions import decode_action_line


class OVSSpec(SpecSet):
    ofctl_dump_flows = glob_file(
        "/sos_commands/openvswitch/ovs-ofctl_dump-flows*",
        context=SosArchiveContext)

    ofctl_show = glob_file("/sos_commands/openvswitch/ovs-ofctl_show_*",
                           context=SosArchiveContext)


@parser(OVSSpec.ofctl_dump_flows)
class OVSOfctlFlows(CommandParser):
    def __init__(self, *args, **kwargs):
        self._field_decoders = {
            "duration": lambda x: float(x.replace('s', '')),
            "table": int,
            "idle_age": int,
            "importance": int,
            "hard_age": int,
            "priority": int,
            "in_port": self._decode_port,
            "n_bytes": int,
            "n_packets": int,
        }

        super(OVSOfctlFlows, self).__init__(*args, **kwargs)

    def parse_content(self, content):
        if not content:
            raise SkipException("Empty Content!")

        self._bridges = []
        self.parsing_errs = {}

        # Extract the bridge name
        try:
            self._bridge_name = self.file_path.split(
                "ovs-ofctl_dump-flows_")[1]
        except:
            raise SkipException("Invalid Path!")

        for line in content:
            if self._is_header(line):
                continue

            try:
                # Actions are a whole different thing that might contain multiple ','s and '='s
                # They should be handled separately. In fact, I don't know if blind sting splitting
                # would work. Imagine this:
                # actions=strip_vlan,load:0x5->NXM_NX_REG13[],load:0x4->NXM_NX_REG11[],load:0x9->NXM_NX_REG12[],load:0xc->OXM_OF_METADATA[],load:0x4->NXM_NX_REG14[],resubmit(,8)
                line_parts = line.split("actions=")

                if len(line_parts) != 2:
                    raise SkipException("Invalid Content!")

                flow = dict()
                flow['raw'] = line
                flow_list = split_kv_pairs(line_parts[0].split(","), split_on='=')
                if flow_list:
                    flow['match'] = dict(map(self._decode_field,
                                             flow_list.items()))
                    flow['actions'] = decode_action_line(line_parts[1])

                    self._bridges.append(flow)

            except Exception as e:
                self.parsing_errs[line] = e
                continue

        if not self._bridges:
            raise SkipException("Invalid Content!")

    def _decode_field(self, elem):
        return (elem[0], elem[1]) if elem[0] not in self._field_decoders else (
            elem[0], self._field_decoders[elem[0]](elem[1]))

    def _is_header(self, line):
        return 'NXST_FLOW' in line

    @property
    def bridge_name(self):
        """
        (str): It will return bridge interface name on success else returns
        `None` on failure.
        """
        return self._bridge_name

    @property
    def flow_dumps(self):
        """
        (list): It will return list of flows added under bridge else returns
        empty list `[]` on failure.
        """
        return self._bridges

    def _decode_port(self, port):
        """
        ports can be either numerical or strings
        (int) or (str) depending on input field
        """
        try:
            return int(port)
        except ValueError:
            ## Treat it as a string. Remove the extra quotes
            return port.replace('"', '')


@parser(OVSSpec.ofctl_show)
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
        #n_tables:254, n_buffers:0
        n_tables, _, n_buffers = content[1].strip().partition(', ')
        self._tables = int(n_tables.split(':')[1])
        self._buffers = int(n_buffers.split(':')[1])

        # Parse capabilities, e.g:
        # capabilities: FLOW_STATS TABLE_STATS PORT_STATS QUEUE_STATS
        _, _, caps = content[2].strip().partition(': ')
        self._capabilities = caps.split(' ')

        # Parse actions, e.g:
        # actions: output enqueue set_vlan_vid set_vlan_pcp strip_vlan
        _, _, actions = content[3].strip().partition(': ')
        self._actions = actions.split(' ')

        # Parse ports
        port_re = re.compile('(\w+)\(([\w-]+)\): addr:([\w:]+)')
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

                self._ports.append({
                    "num": num_int,
                    "name": match.group(2),
                    "addr": match.group(3),
                })
                port_idx += 1
            else:
                if port_idx < 0:
                    raise SkipException("Parsing error")

                keyword, _, info = line.partition(':')
                keyword = keyword.strip()
                info = info.strip()

                if keyword == 'config':
                    self._ports[port_idx]["config"] = info
                elif keyword == 'state':
                    self._ports[port_idx]["state"] = info
                elif keyword == 'speed':
                    m_now, _, m_max = info.partition(', ')
                    self._ports[port_idx]["speed"] = {
                        "now": m_now.split('now')[0].strip(),
                        "max": m_max.split('max')[0].strip(),
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
