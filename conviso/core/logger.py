# conviso/core/logger.py
from rich.console import Console

console = Console()

def log(message: str, style="cyan"):
    """Prints a colored log message to the console."""
    console.print(f"[{style}]{message}[/{style}]")
