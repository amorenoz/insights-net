""" OVS and OVN combiners

OVN information can be obtained from lists, dumps or live database.
Combine them all into a single combiner per database type
"""

from insights.core.plugins import combiner

from insights_net.plugins.commands import CommandMetaClass, command
from insights_net.plugins.parsers.ovn import (
    OVNNBDump,
    OVNSBDump,
    OVNNBLocal,
    OVNSBLocal,
)
from insights_net.plugins.parsers.ocp_net import OCPNB, OCPSB
from insights_net.plugins.parsers.ovs import OVSDump, OVSLocal
from insights_net.plugins.parsers.ovsdb import OVSDBMixin


class OVSDBCommandMetaClass(CommandMetaClass):
    """
    OVSDBCommandMetaClass is a CommandMetaClass taht, used by OVSDBMixin
    instances, exposes the some functions provided by such Mixin as commands.

    It accepts one argument that is a string to be prepended to all commands
    exposed.
    """

    @classmethod
    def __prepare__(cls, name, bases, **kwargs):
        return super().__prepare__(name, bases, **kwargs)

    def __new__(cls, name, bases, namespace, **kwargs):
        return super().__new__(cls, name, bases, namespace)

    def __init__(cls, name, bases, namespace, cmd_name="", *kwargs):
        super().__init__(name, bases, namespace)
        functions_to_commands = [
            "table_list",
            "columns",
            "table",
            "row",
            "find",
            "find_uuid",
        ]

        for cmd in functions_to_commands:
            full_name = "{db}_{cmd}".format(db=cmd_name, cmd=cmd)
            orig_func = getattr(cls, cmd)
            doc = orig_func.__doc__

            setattr(cls, full_name, cls._create_wrapper(orig_func, full_name, doc))

    @classmethod
    def _create_wrapper(cls, orig_func, name, doc):
        def func(self, *args, **kwargs):
            return orig_func(self, *args, **kwargs)

        func.__name__ = name
        func.__doc__ = doc
        return command(func)


class OVSDBCombiner(OVSDBMixin):
    """
    OVSDBCombiner is a base class for OVSDBMixin combiners that combine
    dump, local and ocp OVSDB Parsers
    """

    def __init__(self, dump, local, ocp):
        if local:
            # Prefer local
            if isinstance(local, list):
                local = local[0]
            self._tables = local.tables
            self._name = local.name
        elif dump:
            if isinstance(dump, list):
                dump = dump[0]
            self._tables = dump.tables
            self._name = dump.name
        elif ocp:
            if isinstance(ocp, list):
                ocp = ocp[0]
            self._tables = ocp.tables
            self._name = ocp.name
        else:
            raise Exception("No OVSDB data available")


@combiner([OVNNBDump, OVNNBLocal, OCPNB])
class OVNNB(OVSDBCombiner, metaclass=OVSDBCommandMetaClass, cmd_name="ovnnb"):
    def __init__(self, dump, local, ocp):
        super(OVNNB, self).__init__(dump, local, ocp)


@combiner([OVNSBDump, OVNSBLocal, OCPSB])
class OVNSB(OVSDBCombiner, metaclass=OVSDBCommandMetaClass, cmd_name="ovnsb"):
    def __init__(self, dump, local, ocp):
        super(OVNSB, self).__init__(dump, local, ocp)


@combiner([OVSDump, OVSLocal])
class OVS(OVSDBCombiner, metaclass=OVSDBCommandMetaClass, cmd_name="ovs"):
    def __init__(self, dump, local):
        super(OVS, self).__init__(dump, local, None)
