# -*- coding: utf-8 -*-

from functools import wraps
import jupyter_client
import json
import sys
from IPython.display import JSON

COMMANDS={}
CLIENT=None

def command(name, reqs = None):
    def register(cls):
        COMMANDS[name] = cls
        setattr(cls, "instance_name", name)
        setattr(cls, "requirements", reqs)
        return cls
    return register

def load_commands(holder):
    instances={}
    for name in COMMANDS.keys():
        print(COMMANDS[name])
        instances[name] = COMMANDS[name](holder, backend=True)
    return instances

def init_client():
    cf=jupyter_client.find_connection_file()
    global CLIENT
    CLIENT = jupyter_client.BlockingKernelClient(connection_file=cf)
    CLIENT.load_connection_file()

def prepare_args(*args):
    processed = []
    for arg in args:
        if isinstance(arg, str):
            processed.append("'{}'".format(arg))

    return processed

def backend(func):
    @wraps(func)
    def wrapper(obj, *args, **kwargs):
        if obj.backend:
            ret =  func(obj, *args, **kwargs)
            # Wrap response in a dict to ensure JSON object is created properly
            return JSON({"response": ret})
        else:
            cmd = "{name}.{func}({args})".format(
                name=obj.__class__.instance_name,
                func=func.__name__,
                args=','.join(prepare_args(*args)))
            name = "{f}_{args}".format(f=func.__name__, args=",".join(args))
            return obj.run_background_cmd(name, cmd)

    return wrapper


class CommandDepends(dict):
    """
    CommandDepends is a dictionary representing the Command Dependencies
    It must have the following keys:
        (mandatory) required: [list of lists of model names that must be simultaneously
            present
    """
    def satisfied(self, available):
        """
        Returns whether the required dependencies are satisfied
        """
        reqs = self.get('required')
        if reqs is None:
            return True

        for req_set in self.get('required'):
            if all(elem in available for elem in req_set):
                return True

        return False

    def __repr__(self):
        return "Requirements: {}".format(" or ".join(self.get('required')))

class Command(object):
    instance_name = ""
    requirements = None
    def __init__(self, data=None, backend=False, verbose=False):
        """
        Command constructor
        In the backend it's initalizied with the insights data holder
        In the frontend it's initialized with the kernel client
        """
        if backend:
            self.backend = True
            self._data = data
        else:
            self.backend = False
            self._client = CLIENT
            if not self._client:
                raise Exception("IPython kernel client not initialized")

        self.response=dict()
        self.output=dict()
        self.status=dict()
        self.verbose=verbose

    @property
    def requirements(self):
        return type(self).requirements

    @backend
    def available_archive(self):
        """
        Returns the archives for which this command has satisfied dependencies
        """
        av_archives=[]
        # Find if it's model or holder
        try:
            getattr(self._data, "evaluate")
            if (not self.requirements or
                self.requirements.satisfied(self._data)):
                av_archives.append(self._data.path)
        except AttributeError:
            av_archives.append(
                [p for p in self._data.keys() if
                    (not self.requirements or
                        self.requirements.satisfied(self._data[p]))])

        return av_archives

    def run_background_cmd(self, name, cmd):
        def output_hook(msg):
            msg_type = msg["header"]["msg_type"]
            content = msg["content"]
            if self.verbose:
                print(msg)
            if msg_type == "stream":
                stream = getattr(sys, content["name"])
                stream.write(content['text'])
            elif msg_type == "execute_result":
                data= content["data"].get("application/json","").get("response")
                self.response[name]=data
            elif msg_type == "status":
                self.status[name]=content.get('execution_state', 'unknown')
            elif msg_type == "error":
                print("\n".join(content["traceback"]), file=sys.stderr)

        o = self._client.execute_interactive(cmd, output_hook=output_hook)
        return self.response.get(name)


class Control(Command):
    def __init__(self, *args, **kwargs):
        super(Control, self).__init__(*args, **kwargs)

    def quit(self):
        self.run_background_cmd("quit", "quit")

