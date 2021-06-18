# insights-cmd

Experimental analysis commands based on [insights-core](https://github.com/RedHatInsights/insights-core). It allows running small commands on data living in an insighs-core shell.

## Getting started

After cloning the repository, jump into the pipenv shell and update the dependencies:

    $ pipenv shell
    (insights-cmd)
    $ pipenv update

Run `insights shell` on the archives you want to analyze specifying the "-k" flag and the "-p" option poniting to the `plugins` directory 

    (insights-cmd)
    $ insights shell -k -p plugins $ARCHIVE1 $ARCHIVE2...

Run any command:

    (insights-cmd)
    $ export PYTHONPATH=$PWD
    (insights-cmd)
    $ ./bin/insights-cmd info

## TODO
- Currently, insights-cmd relies on a yet-to-be-merged functionality that currently lives [a fork](https://github.com/amorenoz/insights-core/commits/commands). The plan is to get this functionality in insights-core but in the meantime the Pipfile points to this branch.
- Documentation and cleanup
- More tools
- Support mustgather reports and ocp parsers
- package the tool
- Write a decend contributig guide

## Contribute
I know this tool is still very raw, but PRs are very welcome!



