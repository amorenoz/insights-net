import re

from insights import CommandParser, parser, datasource
from insights.parsers import SkipException, split_kv_pairs
from insights.specs import Specs

# Include the spec in the sosreport context
from insights.core.context import SosArchiveContext
from insights.core.spec_factory import SpecSet, glob_file

from . ofp_actions import decode_action_line


class OVSSpec(SpecSet):
    ofctl_dump_flows = glob_file("/sos_commands/openvswitch/ovs-ofctl_dump-flows*",
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

        # Extract the bridge name
        try:
            self._bridge_name = self.file_path.split("ovs-ofctl_dump-flows_")[1]
        except:
            raise SkipException("Invalid Path!")

        for line in content:
            if self._is_header(line):
                continue
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
                flow['match'] = dict(map(self._decode_field, flow_list.items()))
                flow['actions'] = decode_action_line(line_parts[1])
                self._bridges.append(flow)

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

