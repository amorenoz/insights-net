""" OVN combiners

OVN information can be obtained from lists, dumps or live database.
Combine them all into a single combiner per database type
"""

from insights.core.plugins import combiner

from insights_net.plugins.parsers.ovn import (
    OVNNBDump,
    OVNSBDump,
    OVNNBLocal,
    OVNSBLocal,
)
from insights_net.plugins.parsers.ocp_net import OCPNB, OCPSB
from insights_net.plugins.combiners.ovs import OVSDBCommandMetaClass, OVSDBCombiner


@combiner([OVNNBDump, OVNNBLocal, OCPNB])
class OVNNB(OVSDBCombiner, metaclass=OVSDBCommandMetaClass, cmd_name="ovnnb"):
    def __init__(self, dump, local, ocp):
        super(OVNNB, self).__init__(dump, local, ocp)


@combiner([OVNSBDump, OVNSBLocal, OCPSB])
class OVNSB(OVSDBCombiner, metaclass=OVSDBCommandMetaClass, cmd_name="ovnsb"):
    def __init__(self, dump, local, ocp):
        super(OVNSB, self).__init__(dump, local, ocp)
