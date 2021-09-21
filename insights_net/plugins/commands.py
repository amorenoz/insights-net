""" Defines classes and functions that help locate commands within insights
components.

A command is nothing but an insight component (fact, combiner, parser, etc)
that has a function that can be run with arbitrary parameters
"""


class CommandMetaClass(type):
    def __init__(cls, clsname, superclasses, attributedict):
        cls.has_commands = True


def command(func):
    func.is_cmd = True
    return func
