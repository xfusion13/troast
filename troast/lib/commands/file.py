import typer
from troast.lib.troast import Troast

app = typer.Typer()
COMMAND_NAME = 'file'
HELP = "Pass the file contains list of RID:HOSTNAMES to check machine's passwords."

@app.callback(no_args_is_help=True, invoke_without_command=True)
def main(
    dc_ip           : str            = typer.Option(...,   '-dc-ip',         help= "IP address or FQDN of domain controller"),
    inputfile       : typer.FileText = typer.Option(...,   "-i",             help= "Pass a list of machine accounts to validate. Format machinename$"),
    outresults      : str            = typer.Option(None,  "-or",            help= "Log results to file."),
    outhashes       : str            = typer.Option(None,  "-oh",            help= "Log hashes to file."),
    outlosted       : str            = typer.Option(None,  "-ol",            help= "Log losted hashes to file."),
    rate            : int            = typer.Option(1,     "-rate",          help= "Rate. Higher is faster, but with a greater risk of dropped packages."),
    verbose         : bool           = typer.Option(False, "-verbose",       help= "Verbose output displaying failed attempts.")):

    Troast( dc_ip=dc_ip,
            inputfile=inputfile,
            outresults=outresults,
            outhashes=outhashes,
            outlosted=outlosted,
            rate=rate,
            mode='file',
            verbose=verbose
        
        ).run()