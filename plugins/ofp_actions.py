import re
import sys
from abc import ABC, abstractmethod

class DecodeError(Exception):
    pass

class FieldDecoder(ABC):
    @abstractmethod
    def regexp_str(self):
        pass

    @classmethod
    def decode_field(self, string):
        pass


DEFAULT_REGEXP = r"[\w]+"
MAC_REGEXP = r"[\w:]+"
IP_REGEXP = r"[\d.]+"
DEC_REGEXP = r"\d+"
HEX_REGEXP = r"[x0-9A-Fa-f]+"
DATA_REGEXP = r"[\.0-9A-Fa-f]+"


class StringFieldDecoder(FieldDecoder):
    def __init__(self, regexp):
        self._regex = regexp

    def regexp_str(self):
        return self._regex

    @classmethod
    def decode_field(cls, string):
        return string


IPFieldDecoder = StringFieldDecoder(IP_REGEXP)
MACFieldDecoder = StringFieldDecoder(MAC_REGEXP)
SimpleStringFieldDecoder = StringFieldDecoder(DEFAULT_REGEXP)


class SubFieldDecoder(FieldDecoder):
    SUBFIELD_REGEXP = r"\w+\[(?:\d+)?(?:..)?(?:\d+)?\]"
    SUBFIELD_SEL_REGEXP = r"(\w+)\[(\d+)?(?:..)?(\d+)?\]"
    sel_regexp = re.compile(SUBFIELD_SEL_REGEXP)

    @classmethod
    def regexp_str(cls):
        return cls.SUBFIELD_REGEXP

    @classmethod
    def decode_field(cls, string):
        match = cls.sel_regexp.match(string)
        if match is None:
            raise DecodeError("Failed to decode subfield %s" % string)

        sf = {
            "field": match.group(1),
        }
        if start := match.group(2):
            sf["start"] = int(start)
        if end := match.group(3):
            sf["end"] = int(end)
        return sf


class DataFieldDecoder(FieldDecoder):
    DATA_REGEXP = r"[\.0-9A-Fa-f]+"

    @classmethod
    def regexp_str(cls):
        return DATA_REGEXP

    @classmethod
    def decode_field(cls, string):
        return bytes.fromhex(string.replace('.', ''))


a = DataFieldDecoder()


class IntFieldDecoder(FieldDecoder):
    def __init__(self, regexp):
        self._regexp = regexp

    def regexp_str(self):
        return self._regexp

    @classmethod
    def decode_field(cls, string):
        return int(string, 0)


DecFieldDecoder = IntFieldDecoder(DEC_REGEXP)
HexFieldDecoder = IntFieldDecoder(HEX_REGEXP)


class ActionDecoder(ABC):
    @abstractmethod
    def regexp(self):
        """
        Must return the regexp object
        """
        pass

    @abstractmethod
    def decode_action(self, actions, match):
        """
        Populates the action object based on match
        """
        pass


class SingleKeyValueDecoder(ActionDecoder):
    def __init__(self,
                 keyword,
                 regexp,
                 field_decoder=SimpleStringFieldDecoder):
        self._keyword = keyword
        self._regex = re.compile(
            regexp.format(self._keyword, field_decoder.regexp_str()))
        self._field_decoder = field_decoder

    def regexp(self):
        return self._regex

    def decode_action(self, actions, match):
        value = self._field_decoder.decode_field(match.group(1))

        actions.append({"action": self._keyword, "params": value})


class ColonDecoder(SingleKeyValueDecoder):
    """
    Decodes actions such as 'keyword:argument'
    """
    REGEXP = r"{}:({})"

    def __init__(self, keyword, field_decoder=SimpleStringFieldDecoder):
        super(ColonDecoder, self).__init__(keyword, self.REGEXP, field_decoder)


class ParenthesisDecoder(SingleKeyValueDecoder):
    """
    Decodes actions such as 'keyword(argument)'
    """
    REGEXP = r"{}\(({})\)"

    def __init__(self, keyword, field_decoder=SimpleStringFieldDecoder):
        super(ParenthesisDecoder, self).__init__(keyword, self.REGEXP,
                                                 field_decoder)


class KeywordDecoder(ActionDecoder):
    def __init__(self, keyword):
        self._keyword = keyword

    def regexp(self):
        return re.compile(self._keyword)

    def decode_action(self, actions, match):
        actions.append({"action": self._keyword})
        return True


# TODO: Convert into parenthesyslist instance
#class CTDecoder(ActionDecoder):
#    @classmethod
#    def regexp(cls):
#        reg = r'ct\((commit)?,?(force)?,?(table=(\d+))?,?(zone=(\w+)\[(\d+)?(..)?(\d+)?\])?,?(zone=(\d+))?,?(nat)?,?({})?,?(exec\((.*)\))?\)'.format(
#            NatDecoder().regexp_str())
#        return re.compile(reg)
#
#    @classmethod
#    def decode_action(cls, actions, match):
#        params = {}
#
#        # (commit)?
#        if match.group(1):
#            params["commit"] = True
#
#        # (force)?
#        if match.group(2):
#            params["force"] = True
#
#        # (table=(\d+))
#        if match.group(3):
#            params["table"] = int(match.group(4))
#
#        # (zone=(\w+)\[(\d+)?(..)?(\d+)?\])?,?(zone=(\d+))?
#        if match.group(5):
#            params["zone"] = {
#                "source": match.group(6),
#            }
#            if start := match.group(7):
#                params["zone"]["start"] = start
#            if end := match.group(9):
#                params["zone"]["end"] = end
#
#        # (zone=(\d+))?
#        if match.group(10):
#            params["zone_imm"] = match.group(11)
#
#        # (nat)?
#        if match.group(12):
#            params["nat"] = True
#
#        # (nat(...))?
#        if match.group(13):
#            params["nat"] = NatDecoder().decode_field(match.group(13))
#
#        # ?(exec\((.*)\))??
#        if match.group(14):
#            params["exec"] = decode_action_line(match.group(15))
#
#        actions.append({
#            "action": "ct",
#            "params": params
#        })
#


class NatDecoder(ActionDecoder, FieldDecoder):
    """
    Nat can, itself, be an action or a field in the "ct" action
    """
    REGEXP_GROUP = r'nat\((\w+)?(=[\w\d\.:\[\]-]*)?,?(\w+)?,?(\w+)?,?(\w+)?\)'
    REGEXP_FIELD = r'nat\((?:\w+)?(?:=[\w\d\.:\[\]-]*)?,?(?:\w+)?,?(?:\w+)?,?(?:\w+)?\)'
    _field_regex = re.compile(REGEXP_GROUP)
    _port_regex = re.compile('(?:[\w.:\]\[]+)(?:-[\w.:\]\[]+)?(?::(\d+-\d+))')
    # Action Decoder Implementatio'n
    @classmethod
    def regexp(cls):
        return re.compile(cls.REGEXP_GROUP)

    @classmethod
    def decode_action(cls, actions, match):
        params = cls._decode_match(match)
        actions.append({"action": "nat", "params": params})

    # Field Decoder Implementation
    @classmethod
    def decode_field(cls, string):
        match = cls._field_regex.match(string)
        if not match:
            raise DecodeError("Could not decode nat field: {}".format(string))
        return cls._decode_match(match)

    @classmethod
    def regexp_str(cls):
        return cls.REGEXP_FIELD

    @classmethod
    def _decode_match(cls, match):
        params = {}
        if match.group(1) is None:
            raise DecodeError("wrong nat format")

        nat_type = match.group(1)
        params["type"] = nat_type

        if match.group(2):
            # get rid of =
            addr_str = match.group(2)[1:]

            # get ports
            # We cannot simply split by ':' because of IPV6 addresses
            # Extract the ports by regexp
            port_match = cls._port_regex.match(addr_str)
            if port_match is not None:
                ports = port_match.group(1)
                port_range = ports.split('-')
                params['port_min'] = port_range[0]
                if len(port_range) == 2:
                    params['port_max'] = port_range[1]

                # Remove the ports from the address string, including ":"
                addr_str = addr_str[:len(addr_str) - len(ports) - 1]

            # get IP range
            ip_range = addr_str.split('-')
            if len(ip_range) == 2:
                params["addr_min"] = ip_range[0].strip('[]')
                params["addr_max"] = ip_range[1].strip('[]')
            else:
                params["addr"] = addr_str.strip('[]')

        for flag in ["persistent", "hash", "random"]:
            if flag in [match.group(3), match.group(4), match.group(5)]:
                params[flag] = True

        return params


class ResubmitDecoder(ActionDecoder):
    @classmethod
    def regexp(cls):
        reg = r"(commit,)?(force,)?(table=(\d+))?"
        return re.compile(r'resubmit\((\w+)?,(\d+)(,ct)?\)')

    @classmethod
    def decode_action(cls, actions, match):
        """
        Decodes the resubmit action
        """
        params = {}
        if not match.group(1) and not match.group(2):
            raise DecodeError("expected inport or table")

        if match.group(1):
            params["inport"] = match.group(1)
        if match.group(2):
            params["table"] = int(match.group(2))

        params["ct"] = match.group(3) is not None

        actions.append({"action": "resubmit", "params": params})


##class PushPopDecoder(ActionDecoder):
##    @classmethod
##    def regexp(cls):
##        return re.compile(r'(push|pop):(\w+)\[(\d+)?(...)?(\d+)?\]')
##
##    @classmethod
##    def decode_field(cls, actions, match):
##        """
##        Decodes the resubmit action
##        """
##        action = match.group(1)
##        params = {}
##        if match.group(2):
##            params["destination"] = match.group(2)
##        else:
##            raise DecodeError("no destination in PushPopDecoder")
##
##        if match.group(3):
##            params["start"] = match.group(3)
##
##        if match.group(5):
##            params["end"] = match.group(5)
##
##        actions.append({
##            "action": action,
##            "params": params
##        })


class LoadDecoder(ActionDecoder):
    @classmethod
    def regexp(cls):
        return re.compile(r'load:(\w+)->({})'.format(
            SubFieldDecoder.regexp_str()))

    @classmethod
    def decode_action(cls, actions, match):
        params = {}
        if match.group(1):
            params["value"] = int(match.group(1), 0)
        if match.group(2):
            params["destination"] = SubFieldDecoder.decode_field(
                match.group(2))

        actions.append({"action": "load", "params": params})
        return True


class SubActionFieldDecoder(FieldDecoder):
    """
    Decodes an action that has another action string in it, e.g:
        clone(action_str)
    """
    REGEXP_FIELD = r'.*'

    @classmethod
    def regexp_str(cls):
        return cls.REGEXP_FIELD

    @classmethod
    def decode_field(cls, string):
        return decode_action_line(string)


class MoveDecoder(ActionDecoder):
    @classmethod
    def regexp(cls):
        sf_regex = SubFieldDecoder.regexp_str()
        return re.compile('move:({})->({})'.format(sf_regex, sf_regex))

    @classmethod
    def decode_action(cls, actions, match):
        params = {}
        if match.group(1):
            params["source"] = SubFieldDecoder.decode_field(match.group(1))
        else:
            raise DecodeError("no source registry in move action")

        if match.group(2):
            params["destination"] = SubFieldDecoder.decode_field(
                match.group(2))
        else:
            raise DecodeError("no destination registry in move action")

        actions.append({"action": "move", "params": params})
        return True


class ParenthesisFieldDecoder(FieldDecoder):
    def __init__(self, keyword, field_decoder):
        self._keyword = keyword
        self._field_decoder = field_decoder
        self._regex = r"{}\({}\)".format(keyword, field_decoder.regexp_str())

    def regexp_str(self):
        return self._regex

    def decode_field(self, string):
        # remove "keyword(" and send to field_decoder
        substr = string[len(self._keyword):].strip('()')
        value = self._field_decoder.decode_field(substr)
        return value


class EqualKeyValFieldDecoder(FieldDecoder):
    def __init__(self, keyword, field_decoder):
        self._keyword = keyword
        self._field_decoder = field_decoder
        self._regex = r"{}={}".format(keyword, field_decoder.regexp_str())

    def regexp_str(self):
        return self._regex

    def decode_field(self, string):
        # remove "keyword=" and send to field_decoder
        substr = string[len(self._keyword) + 1:]
        value = self._field_decoder.decode_field(substr)
        return value


class FlagFieldDecoder(FieldDecoder):
    def __init__(self, keyword):
        self._keyword = keyword

    def regexp_str(self):
        return self._keyword

    def decode_field(self, string):
        return string == self._keyword


class ParenthesisListDecoder(ActionDecoder):
    """
    Decodes comma separated list of fields. E.g:
        keyword:(f1,f2,f3)
    Args:
        keyword: the keyword string of the action
        fields: list of tuples (field_name, field_decoder)

    """
    def __init__(self, keyword, fields):
        # just to be sure
        self._fields = fields
        field_regexp = ",?".join(
            [r"({})?".format(field[1].regexp_str()) for field in fields])
        regexp_str = r"{}\({}\)".format(keyword, field_regexp)
        self._regexp = re.compile(regexp_str)
        self._fields = fields
        self._keyword = keyword

    def regexp(self):
        return self._regexp

    def decode_action(self, actions, match):
        params = {}
        for i in range(1, len(self._fields) + 1):
            field = self._fields[i - 1]
            field_name = field[0]
            field_decoder = field[1]
            if match.group(i):
                value = field_decoder.decode_field(match.group(i))
                params[field_name] = value

        actions.append({"action": self._keyword, "params": params})


ControllerDecoder = ParenthesisListDecoder("controller", [
    ("reason", EqualKeyValFieldDecoder("reason", SimpleStringFieldDecoder)),
    ("max_len", EqualKeyValFieldDecoder("max_len", DecFieldDecoder)),
    ("id", EqualKeyValFieldDecoder("id", SimpleStringFieldDecoder)),
    ("userdata", EqualKeyValFieldDecoder("userdata", DataFieldDecoder())),
    ("pause", FlagFieldDecoder("pause")),
    ("meter_id", EqualKeyValFieldDecoder("meter_id",
                                         SimpleStringFieldDecoder)),
])

# e.g: multipath(eth_src,50,modulo_n,1,0,NXM_NX_REG0[])
MultipathDecoder = ParenthesisListDecoder("multipath", [
    ("fields", SimpleStringFieldDecoder),
    ("basis", DecFieldDecoder),
    ("algorithm", SimpleStringFieldDecoder),
    ("max_link", DecFieldDecoder),
    ("arg", DecFieldDecoder),
    ("subfield", SubFieldDecoder),
])

CTDecoder = ParenthesisListDecoder("ct", [
    ("commit", FlagFieldDecoder("commit")),
    ("force", FlagFieldDecoder("force")),
    ("table", EqualKeyValFieldDecoder("table", DecFieldDecoder)),
    ("zone", EqualKeyValFieldDecoder("zone", SubFieldDecoder)),
    ("zone_imm", EqualKeyValFieldDecoder("zone", DecFieldDecoder)),
    ("zone_imm", EqualKeyValFieldDecoder("zone", DecFieldDecoder)),
    ("nat", FlagFieldDecoder("nat")),
    ("nat", NatDecoder()),
    ("exec", ParenthesisFieldDecoder("exec", SubActionFieldDecoder())),
])


class BundleMembersFieldDecoder:
    REGEXP = "members:[\d,]+"

    @classmethod
    def regexp_str(cls):
        return cls.REGEXP

    @classmethod
    def decode_field(self, string):
        members = string.split(':')[1]
        return [int(i) for i in members.split(',')]


# e.g: bundle(eth_src,0,hrw,ofport,members:4,8)
BundleDecoder = ParenthesisListDecoder("bundle", [
    ("fields", SimpleStringFieldDecoder),
    ("basis", DecFieldDecoder),
    ("algorithm", SimpleStringFieldDecoder),
    ("ofport", SimpleStringFieldDecoder),
    ("subfield", SubFieldDecoder),
    ("members", BundleMembersFieldDecoder()),
])

#class ControllerDecoder(ActionDecoder):
#    @classmethod
#    def regexp(cls):
#        return re.compile(
#            r'controller\((reason=(\w+))?,?(max_len=(\d+))?,?(id=(\w+))?,?(userdata=([\w\.]+))?,?(pause)?,?(meter_id=(\w+))?\)')
#
#    @classmethod
#    def decode_field(cls, actions, match):
#        params = {}
#        if match.group(1):
#            params["reason"] = match.group(2)
#
#        if match.group(3):
#            params["max_len"] = int(match.group(4), 0)
#
#        if match.group(5):
#            params["id"] = int(match.group(6), 0)
#
#        if match.group(7):
#            params["userdata"] = bytes.fromhex(match.group(8).replace('.', ''))
#
#        if match.group(9):
#            params["pause"] = True
#
#        if match.group(10):
#            params["meter_id"] = int(match.group(11), 0)
#
#        actions.append({
#             "action": "controller",
#             "params": params
#        })
#


class ConjunctionDecoder:
    @classmethod
    def regexp(cls):
        return re.compile(r'conjunction\((\d+),(\d+)/(\d+)\)')

    @classmethod
    def decode_action(cls, actions, match):
        params = {}
        params["id"] = match.group(1)
        params["clause"] = match.group(2)
        params["n_clauses"] = match.group(3)

        actions.append({"action": "conjunction", "params": params})


class EnqueueDecoder:
    @classmethod
    def regexp(cls):
        return re.compile(r'enqueue:(\d+):(\d+)')

    @classmethod
    def decode_action(cls, actions, match):
        params = {}
        params["port"] = match.group(1)
        params["queue"] = match.group(2)

        actions.append({"action": "conjunction", "params": params})


action_decoders = {
    "drop":
    KeywordDecoder("drop"),
    "exit":
    KeywordDecoder("exit"),
    "ct_clear":
    KeywordDecoder("ct_clear"),
    "dec_ttl":
    KeywordDecoder("dec_ttl"),
    "strip_vlan":
    KeywordDecoder("strip_vlan"),
    "pop_queue":
    KeywordDecoder("pop_queue"),
    "dec_mpls_ttl":
    KeywordDecoder("dec_mpls_ttl"),
    "dec_nsh_ttl":
    KeywordDecoder("dec_nsh_ttl"),
    "mod_dl_src":
    ColonDecoder("mod_dl_src", MACFieldDecoder),
    "mod_dl_dst":
    ColonDecoder("mod_dl_dst", MACFieldDecoder),
    "mod_nw_src":
    ColonDecoder("mod_nw_src", IPFieldDecoder),
    "mod_nw_dst":
    ColonDecoder("mod_nw_dst", IPFieldDecoder),
    "mod_tp_src":
    ColonDecoder("mod_tp_src", DecFieldDecoder),
    "mod_tp_dst":
    ColonDecoder("mod_tp_dst", DecFieldDecoder),
    "mod_vlan_vid":
    ColonDecoder("mod_vlan_vid", DecFieldDecoder),
    "mod_vlan_pcp":
    ColonDecoder("mod_vlan_pcp", DecFieldDecoder),
    "mod_nw_tos":
    ColonDecoder("mod_nw_tos", DecFieldDecoder),
    "mod_nw_ecn":
    ColonDecoder("mod_nw_ecn", DecFieldDecoder),
    "output": [
        ColonDecoder("output", DecFieldDecoder),
        ColonDecoder("output", SubFieldDecoder)
    ],
    "set_tunnel":
    ColonDecoder("set_tunnel", HexFieldDecoder),
    "set_tunnel64":
    ColonDecoder("set_tunnel64", DecFieldDecoder),
    "set_queue":
    ColonDecoder("set_queue", DecFieldDecoder),
    "note":
    ColonDecoder("note", DataFieldDecoder()),
    "group":
    ColonDecoder("group", DecFieldDecoder),
    "CONTROLLER":
    KeywordDecoder("CONTROLLER"),
    "NORMAL":
    KeywordDecoder("NORMAL"),
    "LOCAL":
    KeywordDecoder("LOCAL"),
    "push":
    ColonDecoder("push", SubFieldDecoder),
    "pop":
    ColonDecoder("pop", SubFieldDecoder),
    "load":
    LoadDecoder(),
    "move":
    MoveDecoder(),
    "resubmit":
    ResubmitDecoder,
    "ct":
    CTDecoder,
    "controller":
    ControllerDecoder,
    "multipath":
    MultipathDecoder,
    "bundle":
    BundleDecoder,
    "conjunction":
    ConjunctionDecoder(),
    "enqueue":
    EnqueueDecoder(),
    "set_mpls_ttl":
    ParenthesisDecoder("set_mpls_ttl", DecFieldDecoder),
    "set_mpls_tc":
    ParenthesisDecoder("set_mpls_tc", DecFieldDecoder),
    "set_mpls_label":
    ParenthesisDecoder("set_mpls_label", DecFieldDecoder),
    "push_mpls":
    ColonDecoder("push_mpls", HexFieldDecoder),
    "pop_mpls":
    ColonDecoder("pop_mpls", HexFieldDecoder),
    "nat":
    NatDecoder(),
    "clone":
    ParenthesisDecoder("clone", SubActionFieldDecoder)
}

# TODO: The following actions are not decodable yet
# bundle_load
# learn
# fin_timeout
# dec_ttl
# sample
# actions=output(port=1,max_len=100)
# check_pkt_larger
# set_field
# delete_field
# encap
# decap
# output_trunc


def decode_action_line(line):
    actions = []
    action_regex = re.compile(r"(\w+)")
    while line != "":
        some_match = False
        # Match the action name
        act_name = action_regex.match(line)
        if act_name is None:
            raise DecodeError("Failed to get action name: {}".format(line))
        name = act_name.group(1)

        decoders = []
        decoder = action_decoders.get(name, None)
        if not decoder:
            raise DecodeError(
                "Could not find a decoder for action name {}".format(name))
        if isinstance(decoder, list):
            decoders.extend(decoder)
        else:
            decoders.append(decoder)

        for decoder in decoders:
            got_match = False
            regexp = decoder.regexp()
            match = regexp.match(line)
            if match:
                got_match = True
                decoder.decode_action(actions, match)
                some_match = True
                line = line[match.end():].strip()
                if len(line) > 0 and line[0] == ',':
                    line = line[1:]
                break
        if not got_match:
            raise DecodeError(
                "All decoders for action action {} failed to match. Line: {}".
                format(name, line))

    return actions
