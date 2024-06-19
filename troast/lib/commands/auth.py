import typer
from troast.lib.troast import Troast

app = typer.Typer()
COMMAND_NAME = 'auth'
HELP = 'Query the domain machine accounts.'

@app.callback(no_args_is_help=True, invoke_without_command=True)
def main(
    dc_ip           : str  = typer.Option(...,   '-dc-ip',         help= "IP address or FQDN of domain controller"),
    domain          : str  = typer.Option(...,   '-d',             help="Target domain"),
    username        : str  = typer.Option(None,  '-u',             help="Username"),
    password        : str  = typer.Option(None,  '-p',             help="Password"),
    hashes          : str  = typer.Option(None, "-hashes",         metavar="LMHASH:NTHASH", help="LM and NT hashes, format is LMHASH:NTHASH"),
    aes             : str  = typer.Option(None, '-aes',            metavar="HEX KEY", help='AES key to use for Kerberos Authentication (128 or 256 bits)'),
    no_pass         : bool = typer.Option(False, "-no-pass",       help="don't ask for password (useful for -k)"),
    kerberos        : bool = typer.Option(False, "-k",             help='Use Kerberos authentication'),
    ldaps           : bool = typer.Option(False, '-ldaps',         help='Use LDAPS instead of LDAP'),
    targeted        : bool = typer.Option(False, '-targeted',      help="Search for computer accounts with logoncount=0."),
    outresults      : str  = typer.Option(None,  "-or",            help= "Log results to file."),
    outhashes       : str  = typer.Option(None,  "-oh",            help= "Log hashes to file."),
    outlosted       : str  = typer.Option(None,  "-ol",            help= "Log losted hashes to file."),
    rate            : int  = typer.Option(1,     "-rate",          help= "Rate. Higher is faster, but with a greater risk of dropped packages."),
    verbose         : bool = typer.Option(False, "-verbose",       help= "Verbose output displaying failed attempts."),):

    Troast( dc_ip=dc_ip,
            domain=domain,
            username=username,
            password=password,
            hashes=hashes,
            aes=aes,
            no_pass=no_pass,
            kerberos=kerberos,
            ldaps=ldaps,
            targeted=targeted,
            outresults=outresults,
            outhashes=outhashes,
            outlosted=outlosted,
            rate=rate,
            mode='auth',
            verbose=verbose
        
        ).run()