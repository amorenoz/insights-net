import click

@click.command(name='info')
@click.pass_obj
def info(ctx):
    """
    Show basic information of the archives
    """
    data = ctx.client.available()
    if not data:
        print("Command not found")
        return

    for archive, host_data in data.items():
        if not host_data:
            continue

        print("Archive: " + archive)
        print("*" * (9 + len(archive)))
        if isinstance (host_data, str):
            print(host_data)
        else:
            print_results(host_data)
            print("")

def print_results(data):
    if data.get('models'):
        print("Available Models")
        print("----------------")
        models = data.get('models')
        # Print in 3 columns
        maxlen = len(max(models, key=len)) + 4
        fmt = "{{:<{len}}}{{:<{len}}}{{:<}}".format(len=maxlen)
        for a,b,c in zip(models[::3],models[1::3],models[2::3]):
            print(fmt.format(a, b, c))

        print("")

    if data.get('commands'):
        print("Available Commands")
        print("------------------")
        for cmd in data.get('commands') :
            print("  {}".format(cmd))


