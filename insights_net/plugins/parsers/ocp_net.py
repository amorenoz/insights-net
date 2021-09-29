"""
Plugin that deals with must-gather gather_network_logs content
"""

from insights.core.plugins import parser
from insights.parsers import SkipException
from insights.core.spec_factory import glob_file, RawFileProvider

from insights_net.plugins.datasources import GZFileProvider
from insights_net.plugins.parsers.ovsdb import OVSDBDumpParser
from insights_net.plugins.parsers.ovs import OVSOfctlDumpBase


"""
OVN Databases from network_logs/ovnkube*{nb,sb}db.gz
"""
# Cannot put MustGatherContext because it fails to detect the context if
# we have gather_network_logs
ocp_nb = glob_file("*/network_logs/ovnkube-*_nbdb.gz", kind=GZFileProvider)
ocp_sb = glob_file("*/network_logs/ovnkube-*_sbdb.gz", kind=GZFileProvider)


@parser(ocp_nb)
class OCPNB(OVSDBDumpParser):
    def __init__(self, *args, **kwargs):
        super(OCPNB, self).__init__(*args, **kwargs)

    def parse_content(self, content):
        self.pod_name = self.file_name.rpartition("_nbdb.gz")
        return super(OCPNB, self).parse_content(content)


@parser(ocp_sb)
class OCPSB(OVSDBDumpParser):
    def __init__(self, *args, **kwargs):
        super(OCPSB, self).__init__(*args, **kwargs)

    def parse_content(self, content):
        self.pod_name = self.file_name.rpartition("_sbdb.gz")
        return super(OCPSB, self).parse_content(content)


"""
Ofproto dumps
"""
ocp_flows = glob_file("*/network_logs/*ofctl_dump_flows*")


@parser(ocp_flows)
class OCPOfclDumpFlows(OVSOfctlDumpBase):
    def __init__(self, *args, **kwargs):
        super(OCPOfclDumpFlows, self).__init__(*args, **kwargs)

    @property
    def hostname(self):
        return self._hostname

    def parse_content(self, content):
        if not content:
            raise SkipException("Empty Content")

        # Extract the bridge name
        try:
            parts = self.file_name.split("_ovs_ofctl_dump_flows_")
            self._hostname = parts[0]
            self._bridge_name = parts[1]
        except:
            raise SkipException("Invalid Path!")

        return super(OCPOfclDumpFlows, self).parse_content(content)
