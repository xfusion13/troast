import typer
from troast.lib.troast import Troast

app = typer.Typer()
COMMAND_NAME = 'gen-dict'
HELP = "Generate dictionary"

@app.callback(no_args_is_help=True, invoke_without_command=True)
def main(
    inputfile : typer.FileText = typer.Option(...,   "-i", help= "Pass a list of machine accounts"),
    outfile   : str            = typer.Option(...,   "-o", help= "Log results to file.")):

    gen_dict(inputfile, outfile)