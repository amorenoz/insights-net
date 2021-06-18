# -*- coding: utf-8 -*-

from functools import wraps
import jupyter_client
import json
import sys

client=None

class InsightsClient:
    INIT_COMMANDS= "\n".join([
        "from IPython.display import JSON",
        "from insights.shell import Models",
        "def kresponse(data):",
        "    return JSON({'response': data})",
        "def krun_command(name, **kwargs):",
        "   if isinstance(models, Models):",
        "       return {",
        "           models.path(): models.run_command(name, **kwargs)",
        "       }",
        "   else:",
        "       return {",
        "               path: models.get(path).run_command(name, **kwargs)",
        "                   for path in models.keys()",
        "           }"])

    def __init__(self, verbose=False):
        self._client = None
        self.response=dict()
        self.output=dict()
        self.status=dict()
        self.verbose=verbose

        cf=jupyter_client.find_connection_file()
        self._client = jupyter_client.BlockingKernelClient(connection_file=cf)
        self._client.load_connection_file()
        self._run_init_commands()


    def _run_init_commands(self):
        self.__run("init", self.INIT_COMMANDS)

    def close(self):
        return self.__run("quit", "quit")

    def evaluate(self, name, subargs=""):
        command = "\n".join([
            "result={}",
            "if isinstance(models, Models):",
            "   {name} = models.evaluate('{name}')".format(name=name),
            "   if not {name}:".format(name=name),
            "       kresponse(None)",
            "   else:",
            "       value = {name}{subargs}".format(
                        name=name, subargs="." + subargs if subargs else ""),
            "       result = {models.path(): value}",
            "else:",
            "   result = {}",
            "   for path, model in models.items():",
            "       value = None",
            "       {name} = model.evaluate('{name}')".format(name=name),
            "       if {name}:".format(name=name),
            "           value = {name}{subargs}".format(
                name=name, subargs="." + subargs if subargs else ""),
            "       result[path] = value",
            "kresponse(result)"
        ])

        return self.__run(name, command)

    def run_command(self, name, **kwargs):
        command = "krun_command('{name}', {kwargs})".format(
            name=name,
            kwargs=",".join(
                [ "=".join([key, self._prepare_arg(kwargs[key])])
                    for key in kwargs.keys()])
        )
        return self._run(name, command)

    def list_commands(self):
        return self._run("list", "list(models.get_commands().keys())")

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
                data= content["data"].get("application/json","").get("response")
                self.response[name]=data
            elif msg_type == "status":
                self.status[name]=content.get('execution_state', 'unknown')
            elif msg_type == "error":
                print("\n".join(content["traceback"]), file=sys.stderr)

        o = self._client.execute_interactive(cmd, output_hook=output_hook)
        return self.response.get(name)

