import typer
from conviso.commands import projects
from conviso.commands import assets
from conviso.commands import requirements
from conviso.commands import vulnerabilities
from conviso.commands import bulk
from conviso.commands import sbom
from conviso.commands import tasks
from conviso.commands import accesscontrol
from conviso.core.logger import log, set_verbosity
from conviso.core.concurrency import set_default_workers
from conviso.core.output_prefs import set_output_preferences
from conviso.core.notifier import info, warning
from conviso.core.version import check_for_updates, DEFAULT_REMOTE_URL, read_local_version
import subprocess
import os
import sys
from typing import Optional
from pathlib import Path

app = typer.Typer(help="Conviso Platform CLI")

app.add_typer(projects.app, name="projects", help="Manage projects in the Conviso Platform.")
app.add_typer(assets.app, name="assets", help="Manage assets in the Conviso Platform.")
app.add_typer(requirements.app, name="requirements", help="List requirements/playbooks.")
app.add_typer(vulnerabilities.app, name="vulns", help="List vulnerabilities/issues.")
app.add_typer(bulk.app, name="bulk", help="Bulk operations via CSV.")
app.add_typer(sbom.app, name="sbom", help="List/import SBOM components.")
app.add_typer(tasks.app, name="tasks", help="Execute YAML tasks from requirements.")
app.add_typer(accesscontrol.app, name="accesscontrol", help="Manage access control and user profile settings.")

@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    quiet: bool = typer.Option(False, "--quiet", help="Silence non-error output."),
    verbose: bool = typer.Option(False, "--verbose", help="Show verbose logs (GraphQL requests, etc.)."),
    workers: int = typer.Option(8, "--workers", help="Default worker threads for parallel operations across commands."),
    repeat_header_every: int = typer.Option(
        0,
        "--repeat-header",
        help="Repeat table headers every N rows (global output option). 0 disables.",
    ),
    columns: Optional[str] = typer.Option(
        None,
        "--columns",
        help="Comma-separated columns for table/csv output (global output option). Example: --columns id,title,status",
    ),
):
    set_verbosity(quiet=quiet, verbose=verbose)
    set_default_workers(workers)
    set_output_preferences(repeat_header_every=repeat_header_every, columns=columns)

    if ctx.resilient_parsing:
        return
    try:
        local, remote, outdated, remote_missing = check_for_updates()
        if outdated and remote:
            info(f"A new CLI version is available: {remote} (current: {local}).")
            info(f"Update: download latest from {DEFAULT_REMOTE_URL.rsplit('/', 1)[0]}")
        elif remote_missing:
            # Avoid noisy output when offline; surface only in verbose mode.
            log("Could not check remote version (network blocked or unavailable). Set CONVISO_CLI_REMOTE_VERSION to override.", style="yellow", verbose_only=True)
    except Exception as exc:
        warning(f"Version check skipped due to error: {exc}")


@app.command("upgrade")
def upgrade_cli():
    """
    Attempt to self-update the CLI from a local git checkout when available.
    If the installed package is not inside a git repository, print the correct
    manual reinstall guidance instead of trying to pull inside site-packages.
    """

    def _find_git_checkout(start: Path) -> Optional[Path]:
        for candidate in [start, *start.parents]:
            if (candidate / ".git").exists() and (candidate / "pyproject.toml").exists():
                return candidate
        return None

    module_root = Path(__file__).resolve().parents[2]
    cwd_root = _find_git_checkout(Path.cwd())
    package_root = _find_git_checkout(module_root)
    repo_root = cwd_root or package_root

    if not repo_root:
        warning("This Conviso CLI installation is not running from a git checkout.")
        info(f"Loaded package from: {module_root}")
        info(f"Python executable: {sys.executable}")
        warning("Manual upgrade from a repository checkout: python3 -m pip install -e .")
        warning("If you installed a wheel, reinstall the desired wheel with: python3 -m pip install --force-reinstall <wheel>")
        warning("If the shell still points to an older binary after reinstalling, run: hash -r")
        raise typer.Exit(code=1)

    git_cmd = ["git", "-C", str(repo_root), "pull", "--ff-only"]
    info(f"Attempting to upgrade Conviso CLI from git checkout: {repo_root}")
    try:
        result = subprocess.run(git_cmd, capture_output=True, text=True, check=False)
    except Exception as exc:
        warning(f"Upgrade failed: {exc}")
        warning(f"Manual upgrade: git -C {repo_root} pull --ff-only && python3 -m pip install -e {repo_root}")
        raise typer.Exit(code=1)
    if result.returncode != 0:
        warning(f"git pull failed (code {result.returncode}): {result.stderr.strip()}")
        warning(f"Manual upgrade: git -C {repo_root} pull --ff-only && python3 -m pip install -e {repo_root}")
        raise typer.Exit(code=1)
    info(result.stdout.strip() or "git pull completed.")
    info(f"Upgrade finished. Refresh the current environment with: python3 -m pip install -e {repo_root}")
    info("If the shell still points to an older binary after reinstalling, run: hash -r")
    info(f"Current version: {read_local_version()}")


if __name__ == "__main__":
    app()
