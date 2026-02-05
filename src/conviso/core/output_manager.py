# conviso/core/output_manager.py
"""
Output Manager
---------------
Centralizes all CLI output logic:
 - Table rendering (Rich)
 - JSON and CSV exports
 - Integration with schema definitions
 - Consistent CLI-wide formatting
"""

import json
import csv
import sys
from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.table import Table
from conviso.core.notifier import info, success, error

console = Console()


def export_data(data: List[Dict], schema=None, fmt: str = "table", output: str = None, title: str = None):
    """Exports data in table, JSON, or CSV formats using unified schema-driven output."""

    # --- Prepare columns for table/CSV ---
    if schema and hasattr(schema, "display_headers"):
        columns = list(schema.display_headers.values())
        field_keys = list(schema.display_headers.keys())
    elif data:
        field_keys = list(data[0].keys())
        columns = field_keys
    else:
        console.print("[yellow]⚠️ No data to export.[/yellow]")
        return

    # --- JSON output ---
    if fmt == "json":
        result = json.dumps(data, indent=2, ensure_ascii=False)

        # If output file is specified, save to disk
        if output:
            with open(output, "w", encoding="utf-8") as f:
                f.write(result)
            console.print(f"[green]File saved to {output}[/green]")
        else:
            # Print directly to stdout without escaping characters
            print(result)
        return

    # --- CSV output ---
    elif fmt == "csv":
        if output:
            with open(output, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=field_keys)
                writer.writeheader()
                writer.writerows(data)
            console.print(f"[green]File saved to {output}[/green]")
        else:
            writer = csv.DictWriter(sys.stdout, fieldnames=field_keys)
            writer.writeheader()
            writer.writerows(data)
        return

    # --- TABLE output ---
    else:
        # Detect numeric columns to right-align
        def _is_numeric_column(key: str) -> bool:
            for row in data:
                val = row.get(key)
                if val is None or val == "":
                    continue
                try:
                    float(val)
                except Exception:
                    return False
            return True

        numeric_cols = {k: _is_numeric_column(k) for k in field_keys}

        table = Table(
            title=title or "Results",
            show_header=True,
            header_style="bold cyan",
            row_styles=["none", "dim"],  # zebra striping for readability
        )
        for col_key, col_name in zip(field_keys, columns):
            table.add_column(
                col_name,
                overflow="ellipsis",
                max_width=25,
                justify="right" if numeric_cols.get(col_key) else "left",
                no_wrap=False,
            )

        for row in data:
            table.add_row(*(str(row.get(k, "")) for k in field_keys))

        console.print(table)



# ---------------------- TABLE RENDERING ---------------------- #
def render_table(data: List[Dict[str, Any]], schema: Optional[Any] = None, title: Optional[str] = None):
    """Render data as a styled table using schema definitions."""
    if not data:
        console.print("[yellow]⚠️ No data to display.[/yellow]")
        return

    table = Table(show_header=True, header_style="bold cyan", title=title or "Results")

    # Determine display fields and headers
    if schema and hasattr(schema, "display_fields") and hasattr(schema, "display_headers"):
        fields = schema.display_fields
        headers = schema.display_headers
    else:
        fields = list(data[0].keys())
        headers = {f: f for f in fields}

    for f in fields:
        table.add_column(headers.get(f, f), overflow="fold")

    for row in data:
        table.add_row(*(str(row.get(f, "")) for f in fields))

    console.print(table)


# ---------------------- JSON EXPORT ---------------------- #
def _export_json(data: List[Dict[str, Any]], output: Optional[str] = None):
    """Export data as JSON to stdout or file."""
    json_data = json.dumps(data, indent=2, ensure_ascii=False)
    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(json_data)
        success(f"JSON file exported to {output}")
    else:
        console.print_json(data=json_data)


# ---------------------- CSV EXPORT ---------------------- #
def _export_csv(data: List[Dict[str, Any]], schema: Optional[Any] = None, output: Optional[str] = None):
    """Export data as CSV file or stdout."""
    if not data:
        console.print("[yellow]⚠️ No data to export.[/yellow]")
        return

    fields = schema.display_fields if schema else list(data[0].keys())
    headers = [schema.display_headers.get(f, f) for f in fields] if schema else fields

    if output:
        with open(output, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()
            for row in data:
                writer.writerow({h: row.get(f, "") for f, h in zip(fields, headers)})
        success(f"CSV file exported to {output}")
    else:
        writer = csv.DictWriter(sys.stdout, fieldnames=headers)
        writer.writeheader()
        for row in data:
            writer.writerow({h: row.get(f, "") for f, h in zip(fields, headers)})
