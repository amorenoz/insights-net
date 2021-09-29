from insights import parser
from insights.core.context import SosArchiveContext
from insights.core.spec_factory import simple_file

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
