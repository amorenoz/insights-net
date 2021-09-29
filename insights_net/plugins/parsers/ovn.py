import os

from insights import parser
from insights.core.spec_factory import simple_file, simple_command

from insights_net.plugins.parsers.ovsdb import (
    OVSDBListParser,
    OVSDBParser,
    ovsdb_servers,
)

# Openstack
ovn_nb_dump = simple_file(
    "sos_commands/ovn_central/podman_exec_ovn-dbs-bundle-podman-0_ovsdb-client_-f_list_dump_unix.var.run.openvswitch.ovnnb_db.sock"
)
ovn_sb_dump = simple_file(
    "sos_commands/ovn_central/podman_exec_ovn-dbs-bundle-podman-0_ovsdb-client_-f_list_dump_unix.var.run.openvswitch.ovnsb_db.sock"
)


@parser(ovn_nb_dump)
class OVNNBDump(OVSDBListParser):
    def __init__(self, *args, **kwargs):
        super(OVNNBDump, self).__init__(*args, **kwargs)


@parser(ovn_sb_dump)
class OVNSBDump(OVSDBListParser):
    def __init__(self, *args, **kwargs):
        super(OVNSBDump, self).__init__(*args, **kwargs)


# Local
ovn_nb_db = ovsdb_servers(["*.sock", "ovnnb_db.sock"], "OVN_Northbound")
ovn_sb_db = ovsdb_servers(["*.sock", "ovnsb_db.sock"], "OVN_Southbound")
ovs_db = ovsdb_servers(["*.sock"], "Open_vSwitch")


@parser(ovn_nb_db)
class OVNNB(OVSDBParser):
    def __init__(self, *args, **kwargs):
        super(OVNNB, self).__init__(*args, **kwargs)

    def parse_content(self, data):
        self._tables = data


@parser(ovn_sb_db)
class OVNSB(OVSDBParser):
    def __init__(self, *args, **kwargs):
        super(OVNSB, self).__init__(*args, **kwargs)

    def parse_content(self, data):
        self._tables = data


@parser(ovn_sb_db)
class OVSDB(OVSDBParser):
    def __init__(self, *args, **kwargs):
        super(OVSDB, self).__init__(*args, **kwargs)

    def parse_content(self, data):
        self._tables = data
