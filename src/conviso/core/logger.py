# conviso/core/logger.py
from rich.console import Console
import os

console = Console()

# Verbosity controls (set in conviso.app)
QUIET = False
VERBOSE = False

def set_verbosity(quiet: bool = False, verbose: bool = False):
    global QUIET, VERBOSE
    QUIET = quiet
    VERBOSE = verbose

def log(message: str, style="cyan", force: bool = False, verbose_only: bool = False):
    """Prints a colored log message to the console."""
    if QUIET and not force:
        return
    if verbose_only and not VERBOSE:
        return
    console.print(f"[{style}]{message}[/{style}]")
