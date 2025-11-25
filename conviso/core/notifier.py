import typer
from rich.console import Console

console = Console()

def success(message: str, icon: str = "✅ "):
    """Standard success notification."""
    console.print(f"{icon} [bold green]{message}[/bold green]")

def error(message: str, exit_on_error: bool = False, icon: str = "❌ "):
    """Standard error notification."""
    console.print(f"{icon} [bold red]{message}[/bold red]")
    if exit_on_error:
        raise typer.Exit(code=1)

def warning(message: str, icon: str = "⚠️"):
    """Standard warning notification."""
    console.print(f"{icon} [bold yellow]{message}[/bold yellow]")

def info(message: str, icon: str = "ℹ️ "):
    """Standard info notification."""
    console.print(f"{icon} [cyan]{message}[/cyan]")

def summary(message, error_count=0):
    typer.echo(f"🧾 {str(message)}")
    if error_count:
        typer.echo(f"⚠️  {error_count} error(s) occurred.")

