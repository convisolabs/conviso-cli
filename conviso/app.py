# conviso/app.py
import typer
from conviso.commands import projects
from conviso.commands import assets
from conviso.commands import requirements
from conviso.commands import vulnerabilities
from conviso.commands import bulk
from conviso.commands import sbom
from conviso.core.logger import log, set_verbosity
from conviso.core.notifier import info, warning
from conviso.core.version import check_for_updates, DEFAULT_REMOTE_URL, read_local_version
import conviso.schemas.projects_schema
import subprocess
import sys
import os

app = typer.Typer(help="Conviso Platform CLI")

# Registra os subcomandos
app.add_typer(projects.app, name="projects", help="Manage projects in the Conviso Platform.")
app.add_typer(assets.app, name="assets", help="Manage assets in the Conviso Platform.")
app.add_typer(requirements.app, name="requirements", help="List requirements/playbooks.")
app.add_typer(vulnerabilities.app, name="vulns", help="List vulnerabilities/issues.")
app.add_typer(bulk.app, name="bulk", help="Bulk operations via CSV.")
app.add_typer(sbom.app, name="sbom", help="List/import SBOM components.")

# Global verbosity options
@app.callback()
def main(
    quiet: bool = typer.Option(False, "--quiet", help="Silence non-error output."),
    verbose: bool = typer.Option(False, "--verbose", help="Show verbose logs (GraphQL requests, etc.)."),
):
    set_verbosity(quiet=quiet, verbose=verbose)
    try:
        local, remote, outdated = check_for_updates()
        if outdated and remote:
            info(f"A new CLI version is available: {remote} (current: {local}).")
            info(f"Update: download latest from {DEFAULT_REMOTE_URL.rsplit('/', 1)[0]}")
    except Exception as exc:
        warning(f"Version check skipped due to error: {exc}")

@app.command("upgrade")
def upgrade_cli():
    """
    Attempt to self-update the CLI by running 'git pull --ff-only' in the repo root.
    If git is not available or fails, prints manual instructions.
    """
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    git_cmd = ["git", "-C", repo_root, "pull", "--ff-only"]
    info("Attempting to upgrade Conviso CLI (git pull)...")
    try:
        result = subprocess.run(git_cmd, capture_output=True, text=True, check=False)
    except Exception as exc:
        warning(f"Upgrade failed: {exc}")
        warning("Manual upgrade: git pull && pip install .")
        raise typer.Exit(code=1)
    if result.returncode != 0:
        warning(f"git pull failed (code {result.returncode}): {result.stderr.strip()}")
        warning("Manual upgrade: git pull && pip install .")
        raise typer.Exit(code=1)
    info(result.stdout.strip() or "git pull completed.")
    info("Upgrade finished. If installed via pip, rerun 'pip install .' to refresh entrypoints.")
    info(f"Current version: {read_local_version()}")


if __name__ == "__main__":
    log(f"Starting Conviso CLI v{read_local_version()}...")
    app()
