"""
Plugin that deals with must-gather gather_network_logs content
"""
import gzip

from insights.core.plugins import parser
from insights.core.spec_factory import glob_file, RawFileProvider

from .ovsdb import OVSDBDumpParser
from .ofctl import OVSOfctlFlows

class GZFileProvider(RawFileProvider):
    """
    Class used in datasources that returns the contents of a gzipped file as
    a list of lines
    """
    def load(self):
        self.loaded = True
        with gzip.open(self.path, 'rt', encoding="utf-8") as f:
            return [l.rstrip("\n") for l in f]

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

