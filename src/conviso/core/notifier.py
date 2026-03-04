import typer
from rich.console import Console

console = Console()

def success(message: str, icon: str = "✅ "):
    """Standard success notification."""
    console.print(f"{icon} {message}", markup=False, style="bold green")

def error(message: str, exit_on_error: bool = False, icon: str = "❌ "):
    """Standard error notification."""
    console.print(f"{icon} {message}", markup=False, style="bold red")
    if exit_on_error:
        raise typer.Exit(code=1)

def warning(message: str, icon: str = "⚠️"):
    """Standard warning notification."""
    console.print(f"{icon} {message}", markup=False, style="bold yellow")

def info(message: str, icon: str = "ℹ️ "):
    """Standard info notification."""
    console.print(f"{icon} {message}", markup=False, style="cyan")

def summary(message, error_count=0):
    typer.echo(f"🧾 {str(message)}")
    if error_count:
        typer.echo(f"⚠️  {error_count} error(s) occurred.")


def format_duration(seconds: float) -> str:
    """
    Human-friendly duration formatting.
    Examples: 0.42s -> 420ms, 12.3s -> 12.30s, 1075.39s -> 17m 55.39s
    """
    try:
        total = float(seconds)
    except Exception:
        return f"{seconds}s"
    if total < 1:
        return f"{int(total * 1000)}ms"
    hours = int(total // 3600)
    total -= hours * 3600
    minutes = int(total // 60)
    total -= minutes * 60
    if hours > 0:
        return f"{hours}h {minutes}m {total:.2f}s"
    if minutes > 0:
        return f"{minutes}m {total:.2f}s"
    return f"{total:.2f}s"


def timed_summary(message_without_time: str, elapsed_seconds: float, error_count: int = 0):
    summary(f"{message_without_time} in {format_duration(elapsed_seconds)}.", error_count=error_count)
