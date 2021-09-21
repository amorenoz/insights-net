# -*- coding: utf-8 -*-

from functools import wraps
import jupyter_client
import json
import sys

client = None


class InsightsClient:
    INIT_COMMANDS = """
from functools import partial
from IPython.display import JSON
from insights.shell import Models
def kresponse(data):
    return JSON({'response': data})

def kfind_command(models, name):
    for model_name, model_cls in models.items():
        if hasattr(model_cls, 'has_commands'):
            for a_name in dir(model_cls):
                attr = getattr(model_cls, a_name)
                if hasattr(attr, 'is_cmd') and name == a_name:
                    # Evaluate the model
                    model_instance = getattr(models, model_name)
                    return partial(attr, model_instance)
    return None

def klist_commands(models):
    res = {}
    for model_cls in models.values():
        if hasattr(model_cls, 'has_commands'):
            for a_name in dir(model_cls):
                attr = getattr(model_cls, a_name)
                if hasattr(attr, 'is_cmd'):
                    res[a_name] = attr.__doc__.strip()
    return res

def krun_command_models(models, name, *args, **kwargs):
    cmd = kfind_command(models, name)
    if not cmd:
        return None
    return cmd(*args, **kwargs)

def krun_command(name, *args, **kwargs):
    result = {}
    # FIXME: Export models' path
    for path, model in (models.items() if isinstance(models, Holder) else [(models._tmp, models)]):
        result[path] = krun_command_models(model, name, *args, **kwargs)

    return result
"""

    def __init__(self, verbose=False):
        self._client = None
        self.response = dict()
        self.output = dict()
        self.status = dict()
        self.verbose = verbose

        cf = jupyter_client.find_connection_file()
        self._client = jupyter_client.BlockingKernelClient(connection_file=cf)
        self._client.load_connection_file()
        self._run_init_commands()

    def _run_init_commands(self):
        self.__run("init", self.INIT_COMMANDS)

    def close(self):
        return self.__run("quit", "quit")

    def evaluate(self, name, subargs=""):
        command = """
        result = {{}}
        # FIXME: Export models' path
        for path, model in (models.items() if isinstance(models, Holder) else [(models._tmp, models)]):
            {name} = model.evaluate('{name}')
            if {name}:
                result[path] = {name}{subargs}

        kresponse(result)
        """.format(name=name, subargs="." + subargs if subargs else "")

        return self.__run(name, command)

    def run_command(self, name, **kwargs):
        """
        Run a command. Returns a dictionary indexed by archive name with the results
        """
        command = "krun_command('{name}', {kwargs})".format(
            name=name,
            kwargs=",".join([
                "=".join([key, self._prepare_arg(kwargs[key])])
                for key in kwargs.keys()
            ]))
        return self._run(name, command)

    def available(self):
        """
        Returns the available models and commands in a dictionary indexed by archive
        Returns:
            dict [str: dictionary ['models': list[str], 'commands' : list[str]]]
        """
        command = """
        result = {}
        for path, model in (models.items() if isinstance(models, Holder) else [(models._tmp, models)]):
            result[path] = {
                        'models': [str(m) for m in model.keys()],
                        'commands': [" : ".join([name, help]) for name, help in klist_commands(model).items()]
                        }
        kresponse(result)
        """
        return self.__run("available", command)

    def _prepare_arg(self, arg):
        if isinstance(arg, str):
            return ("'{}'".format(arg))

    def _run(self, name, cmd):
        cmd = "kresponse({})".format(cmd)
        return self.__run(name, cmd)

    def __run(self, name, cmd):
        if self.verbose:
            print("Running command: {}".format(cmd), file=sys.stderr)

        def output_hook(msg):
            msg_type = msg["header"]["msg_type"]
            content = msg["content"]
            if self.verbose:
                print(msg)
            if msg_type == "stream":
                stream = getattr(sys, content["name"])
                stream.write(content['text'])
            elif msg_type == "execute_result":
                data = content["data"].get("application/json",
                                           "").get("response")
                self.response[name] = data
            elif msg_type == "status":
                self.status[name] = content.get('execution_state', 'unknown')
            elif msg_type == "error":
                print("\n".join(content["traceback"]), file=sys.stderr)

        o = self._client.execute_interactive(cmd, output_hook=output_hook)
        return self.response.get(name)
