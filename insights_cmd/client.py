# -*- coding: utf-8 -*-

from functools import wraps
import jupyter_client
import json
import sys

client=None

class InsightsClient:
    INIT_COMMANDS= "\n".join([
        "from IPython.display import JSON",
        "def kresponse(data):",
        "    return JSON({'response': data})"
    ])

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

    def evaluate(self, name):
        command = "models.evaluate('{}')".format(name)
        return self._run(name, command)

    def run_command(self, name, **kwargs):
        command = "models.run_command('{name}', {kwargs})".format(
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

