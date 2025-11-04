# conviso/core/output_manager.py
import json
import csv
import sys
from rich.console import Console
from rich.table import Table
from typing import List, Dict

console = Console()

def export_data(data: List[Dict], columns: List[str], fmt: str, output: str = None):
    """Exports data in table, JSON, or CSV formats."""
    if fmt == "json":
        result = json.dumps(data, indent=2)
    elif fmt == "csv":
        result = export_csv(data, columns)
    else:
        render_table(data, columns)
        return

    if output:
        with open(output, "w") as f:
            f.write(result)
        console.print(f"[green]File saved to {output}[/green]")
    else:
        console.print(result)

def export_csv(data: List[Dict], columns: List[str]) -> str:
    """Converts data to CSV format."""
    output = sys.stdout
    writer = csv.DictWriter(output, fieldnames=columns)
    writer.writeheader()
    writer.writerows(data)
    return ""

def render_table(data: List[Dict], columns: List[str]):
    """Renders data as a styled table."""
    table = Table(show_header=True, header_style="bold cyan")
    for c in columns:
        table.add_column(c)
    for row in data:
        table.add_row(*(str(row.get(c, "")) for c in columns))
    console.print(table)
