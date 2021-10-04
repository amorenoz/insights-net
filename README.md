# insights-net

Network analysis tool based on [insights-core](https://github.com/RedHatInsights/insights-core).

It provides:

- A set of plugins that support parsing networking-related logs
- A CLI tool that allows running commands to extract information from log archives.

## Getting started

After cloning the repository, create a venv and install the tool

(Optional) Create a virtual environment:

    $ python -m venv venv && . ./venv/bin/activate

Install the tool using pip:

    $ pip install insights-net

Or install the tool from the repository directly:

    $ (venv) pip install .

## Run insights shell

`insights-net` supports connecting to a running instance of insights shell and
extract information from it. For more details about `insights shell`, visit the
[insights documentation](https://insights-core.readthedocs.io/en/latest/).

Run `insights shell` on kernel-mode ("-k" or "--kernel") on the archives you want to analyze and specify the load insights-net plugins:


    $ insights shell -k  -p insights_net.plugins samples/ovn/sosreport-compute-0-2021-06-03-awkezkh samples/ovn/sosreport-controller-0-2021-06-03-qjzsrnv
    NOTE: When using the `ipython kernel` entry point, Ctrl-C will not work.

    To exit, you will have to explicitly quit this process, by either sending
    "quit" from a client, or using Ctrl-\ in UNIX-like environments.

    To read more about this, see https://github.com/ipython/ipython/issues/2049


    To connect another client to this kernel, use:
        --existing kernel-3973772.json


Now, in another terminal, you can run insights-net to introspect the archives:

    $ insights-net
    Usage: insights-net [OPTIONS] COMMAND [ARGS]...

    Options:
      -v, --verbose  Be verbose
      --help         Show this message and exit.

    Commands:
      find-ip  Get all the available information regarding an IP(v4/6) address
      host     Show basic host information
      info     Show basic information of the archives
      ovn      Show the OVN configuration
      ovs      Show the OVS configuration
      stop     Stop the background running insights kernel


## Extracting data from running running OVSDB servers

`insights-net` has a plugin that supports extracting OVS, OVN NB and OVN SB information from a running ovsdb-server that serves such databases.

In order to use it, start an ovsdb-server you want to inspect (you might want to use the help of [ovs-offline](https://ovs-dbg.readthedocs.io/en/latest/ovs-offline.html)). **Note only unix-domain socket transport is supported.**

Then, just add the directory where the socket file stored to the `insights shell` command line as another archive, e.g:


    insights shell -k -p insights_net.plugins /var/run/openvswitch


You can now examine the OVS or OVN databases using the insights-net command line (see [Available commands(#available-commands))

Other commands (such as `insights-net find-ip`) will also process information from such OVSDB instances


## Available commands:

### host: Dump a brief summary of the host information:
Example output:


```
 $ insights-net host
╭──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│                  📜 Archive: /home/amorenoz/devel/sosreports/ovn/sosreport-compute-0-2021-06-03-awkezkh/ 📜                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
HostName: compute-0.redhat.local
Red Hat Version:
  Product: Red Hat Enterprise Linux
  Version: 8.2
  Code Name: Ootpa
Kernel:
  Version : 4.18.0
  Release: 193.51.1.el8_2
  Arch: x86_64
Uptime for 1 days 19:45 hh:mm
Selinux: enabled

╭──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│                 📜 Archive: /home/amorenoz/devel/sosreports/ovn/sosreport-controller-0-2021-06-03-qjzsrnv 📜                 │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
HostName: controller-0.redhat.local
Red Hat Version:
  Product: Red Hat Enterprise Linux
  Version: 8.2
  Code Name: Ootpa
Kernel:
  Version : 4.18.0
  Release: 193.51.1.el8_2
  Arch: x86_64
Uptime for 1 days 19:57 hh:mm
Selinux: enabled

```


### find-ip: Find IP address information:
It looks in the following logs to find information about the IP Address:

- Interface addresses (utput of "ip addr")
- Routes (output of "ip route")
- Neighbours (output of "ip neigh")
- Hosts (content of "/etc/hosts")
- Iptables
- Netstat (output of "ss" or "netstat")
- OVS Flow dumps (output of "ovs-ofctl dump-flows")
- OVN NB and SB databases
- OCP Pods, Services and Configuration


### ovs | ovn: Inspect the OVS and OVN database
It supports printing the tables and finding elements by UUID:


    insights-net ovs list {TABLE_NAME} [--list]

or

    insights-net ovn nb list {TABLE_NAME} [--list]

or

    insights-net ovn sb list {TABLE_NAME} [--list]


## Contribute

Are you debugging a networking issue and you would like a tool to automate any information collection, processing or visualization? Do reach out to:

Adrián Moreno <amorenoz@redhat.com> IRC:amorenoz

And, off course, PRs are welcome :)
