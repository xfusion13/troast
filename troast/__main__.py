import typer
from troast.logger import init_logger, logger, console
from troast import __version__
from troast.lib.commands import auth, file, range, gendict

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode='rich',
    context_settings={'help_option_names': ['-h', '--help']},
    pretty_exceptions_show_locals=False
)

app.add_typer(
    range.app,
    name=range.COMMAND_NAME,
    help=range.HELP
)
app.add_typer(
    file.app,
    name=file.COMMAND_NAME,
    help=file.HELP
)

app.add_typer(
    auth.app,
    name=auth.COMMAND_NAME,
    help=auth.HELP
)

app.add_typer(
    gendict.app,
    name=gendict.COMMAND_NAME,
    help=gendict.HELP
)

if __name__ == '__main__':
    app(prog_name='troast')