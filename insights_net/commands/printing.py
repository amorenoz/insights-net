from rich.emoji import Emoji
from rich.panel import Panel
from rich.pretty import Pretty
from rich.table import Table
from rich.text import Text


def print_section_header(console, text):
    console.print("* " + text, style="bold")
    console.print("  " + "-" * len(text), style="bold")


def print_archive_header(console, name):
    console.print(
        Panel(
            Text(
                Emoji.replace(":scroll:")
                + " Archive: %s " % name
                + Emoji.replace(":scroll:"),
                style="bold",
                justify="center",
            )
        )
    )


def print_table(console, data, title, tables_as_lists=False):
    """
    Prints a table content
    Args:
        console (rich.Console) where text is to be printed
        data (list(dict)): list of dictionaries of table items.
            Columns are the keys of the elements
    """
    if not data:
        return

    if tables_as_lists:
        for row in data:
            console.print(row)
        return
    else:
        tt = Table(title=title)
        for header, value in data[0].items():
            if isinstance(value, dict):
                tt.add_column(
                    header, justify="left", no_wrap=False, ratio=1, min_width=25
                )
            else:
                tt.add_column(
                    header, justify="left", no_wrap=False, min_width=len(header)
                )

        for elem in data:
            values = [Pretty(val) for val in elem.values()]
            tt.add_row(*values)

        console.print(tt)
