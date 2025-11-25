# conviso/app.py
import typer
from conviso.commands import projects
from conviso.commands import assets
from conviso.commands import requirements
from conviso.commands import vulnerabilities
from conviso.commands import bulk
from conviso.core.logger import log, set_verbosity
import conviso.schemas.projects_schema

app = typer.Typer(help="Conviso Platform CLI")

# Registra os subcomandos
app.add_typer(projects.app, name="projects", help="Manage projects in the Conviso Platform.")
app.add_typer(assets.app, name="assets", help="Manage assets in the Conviso Platform.")
app.add_typer(requirements.app, name="requirements", help="List requirements/playbooks.")
app.add_typer(vulnerabilities.app, name="vulns", help="List vulnerabilities/issues.")
app.add_typer(bulk.app, name="bulk", help="Bulk operations via CSV.")

# Global verbosity options
@app.callback()
def main(
    quiet: bool = typer.Option(False, "--quiet", help="Silence non-error output."),
    verbose: bool = typer.Option(False, "--verbose", help="Show verbose logs (GraphQL requests, etc.)."),
):
    set_verbosity(quiet=quiet, verbose=verbose)

if __name__ == "__main__":
    log("Starting Conviso CLI...")
    app()
