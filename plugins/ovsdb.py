import json
from insights import CommandParser, parser, Parser
from insights.core.spec_factory import simple_file
from insights.parsers import SkipException
from insights.core.context import SosArchiveContext

ovsdb_dump = simple_file("/sos_commands/openvswitch/ovsdb-client_-f_list_dump",
                         context=SosArchiveContext)


class OVSDBParser(Parser):
    """
    Base class for OVSDB data
    Expects _tables to have
    """
    def __init__(self, *args, **kwargs):
        self._tables = dict()
        self._name = ""
        super(OVSDBParser, self).__init__(*args, **kwargs)

    @property
    def tables(self):
        """
        (dict): Returns all the tables
        """
        return self._tables

    @property
    def name(self):
        """
        (string): Returns the database name
        """
        return self._name

    def table_list(self):
        """
        (list): Returns all the tables
        """
        return list(self._tables.keys())

    def columns(self, table):
        """
        (list): Returns the list columns in a particular table
        """
        first = self._tables.get(next(self._tables.get(table).keys()))
        return first.keys()

    def table(self, name):
        """
        (dict) or (None): Returns the table with the given name
        """
        return self._tables.get(name)

    def row(self, table, uuid):
        """
        (dict) or (None): Finds the row that with the given uuid
        """
        table = self._tables.get(table)
        if table:
            return table.get(uuid)
        return None

    def find(self, table, column, value):
        """
        (list): Finds the row that in the table that matches the column's value
        """
        table = self._tables.get(table)
        if table:
            return list(
                (row for row in table.values() if row.get(column) == value))
        return []

    def filter(self, table, function):
        """
        (list): Filters the table based on the given callable filter
        """
        table = self._tables.get(table)
        if table:
            return list(filter(function, table.values()))
        return []

class OVSDBListParser(OVSDBParser):
    """
    Input example:
    ==============
    AutoAttach table

    Bridge table
    _uuid               : 45711587-9496-4d14-8dfe-67a8c273e610
    auto_attach         : []
    controller          : [65c7f516-5bef-41f1-b633-94d6375fa356]
    datapath_id         : "000048df37ce6d70"
    datapath_type       : system
    datapath_version    : "<unknown>"
    external_ids        : {bridge-id=br-link}
    fail_mode           : secure
    flood_vlans         : []
    flow_tables         : {}
    ipfix               : []
    mcast_snooping_enable: false
    mirrors             : []
    name                : br-link
    netflow             : []
    other_config        : {mac-table-size="50000"}
    ports               : [8918bf51-abfa-4b2e-961f-2dca931bf2a8, acb08497-7deb-4ca7-bc9d-d1119dc2d85f, dcf4d708-b4d8-4948-8570-d2a6a05e7949]


    """
    def __init__(self, *args, **kwargs):
        super(OVSDBListParser, self).__init__(*args, **kwargs)

    def parse_content(self, content):
        current_table = dict()
        current_table_name = ""
        current_uuid = ""
        current_row = dict()
        for line in content:
            line = line.strip()
            if not line:
                continue

            table_name, _, keyword = line.partition(' ')
            if keyword == "table":
                # New Table, save old row and table
                if current_uuid != "":
                    current_table[current_row['_uuid']] = current_row
                    current_uuid = ""

                if current_table_name != "":
                    self._tables[current_table_name] = current_table

                current_table_name = table_name
                current_table = dict()

            else:
                column, _, value = line.partition(':')
                column = column.strip()
                value = value.strip()
                converted = self._convert_value(value)

                if not value or not column:
                    raise SkipException("Wrong format")

                if column == '_uuid':
                    # New rowect, save old row if any
                    if current_uuid != "":
                        current_table[current_row['_uuid']] = current_row

                    current_uuid = converted
                    current_row = dict()

                current_row[column] = converted


    def _convert_dict(self, value):
        """
        Convert a dictionary field value
        e.g:
        {classless_static_route="{169.254.169.254/32,192.168.199.2, 0.0.0.0/0,192.168.199.1}", dns_server="{172.16.0.1, 10.0.0.1}", domain_name="\"openstackgate.local\"", lease_time="43200", mtu="1442", router="192.168.199.1", server_id="192.168.199.1", server_mac="fa:16:3e:0b:ba:9d"}
        """
        dict_value = value.strip('{')
        result = {}
        while True:
            (key, found, rest) = dict_value.partition('=')
            if not found:
                break

            key = key.strip('"')

            item = None
            new_dict_value=""

            if rest[0] == '"':
                start = 1
                while True:
                    pos = rest.find('"', start)
                    if pos == len(rest):
                        # Error, we did not find the end of the string
                        raise Exception("Wrong format %s" % value)

                    if rest[pos-1] != '\\':
                        # found a non escaped "
                        item = rest[1:pos]
                        new_dict_value = rest[pos+1:].strip(', ')
                        break

                    start = pos+1
            else:
                (item, comma, new_dict_value) = rest.partition(', ')
                if not comma:
                    (item, curly, new_dict_value) = rest.partition('}')
                    if not curly:
                        raise Exception("Wrong format %s" % value)

            result[key] = self._convert_single_value(item)
            dict_value = new_dict_value

        return result

    def _convert_value(self, value):
        if value[0] == '[':
            converted = []
            for val in value.strip('[]').split(', '):
                if val:
                    converted.append(self._convert_single_value(val))
            return converted
        elif value[0] == '{':
            converted = self._convert_dict(value)
        else:
            converted = self._convert_single_value(value)

        return converted

    def _convert_single_value(self, value):
        value = value.strip('\\"')
        try:
            int_val = int(value)
            return int_val
        except ValueError:
            pass

        try:
            float_val = float(value)
            return float_val
        except ValueError:
            pass

        if value == "true":
            return True
        elif value == "false":
            return False

        return value

class OVSDBDumpParser(OVSDBParser):
    """
    A parser that reads a OVSDB Dump file.
    Only the fist database will be parsed. Further databases or transactions will be ignored
    """
    def parse_content(self, content):
        if len(content) < 2:
            #raise SkipException("Wrong format")
            raise Exception("Wrong format")

        #First line should be OVSDB CLUSTER {} {}
        header = content[0]
        if header[0:13] != "OVSDB CLUSTER":
            #raise SkipException("Wrong format")
            raise Exception("Wrong format: {} ".format(header))

        dump = json.loads(content[1])
        name = dump.get('name')
        if not name:
            #raise SkipException("Wrong format")
            raise Exception("Wrong format")

        prev_data = dump.get('prev_data')
        if not prev_data or len (prev_data) != 2:
            #raise SkipException("Wrong format")
            raise Exception("Wrong format")

        self._tables = prev_data[1]

@parser(ovsdb_dump)
class OVSVswitchDB(OVSDBListParser):
    def __init__(self, *args, **kwargs):
        super(OVSVswitchDB, self).__init__(*args, **kwargs)
        self._name = "Open_vSwitch"
