# conviso/core/security_gate_formatter.py
"""
Security Gate Formatter
-----------------------
Renders security gate results to the terminal using Rich.
Responsible ONLY for data rendering (tables, summaries, hint lines).
Status messages (success/error/warning) must go through notifier.py.
"""

import re
import shutil
from typing import Optional, List, Dict, Any

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich import box as rich_box

console = Console()

CLI_DESCRIPTION_MAX_CHARS = 300
CODE_BLOCK_PATTERN = re.compile(r"```.*?```", re.DOTALL)
MARKDOWN_HEADER_PATTERN = re.compile(r"^#{1,6}\s+", re.MULTILINE)
MARKDOWN_LINK_PATTERN = re.compile(r"\[([^\]]+)\]\([^)]+\)")


# ---------------------------------------------------------------------------
# Platform gate — severity summary
# ---------------------------------------------------------------------------

def format_severity_summary(reason: Optional[Dict[str, Any]]) -> None:
    """
    Render a per-severity summary table (CRITICAL / HIGH / MEDIUM / LOW) to
    the terminal using Rich.  ``reason`` is the ``reason`` sub-object from the
    ``securityGateRun`` GraphQL response.
    """
    table = Table(
        title="Severity Summary",
        show_header=True,
        header_style="bold cyan",
        box=rich_box.SIMPLE_HEAD,
    )
    table.add_column("Severity", style="bold", min_width=10)
    table.add_column("Count", justify="right", min_width=6)
    table.add_column("Limit", justify="right", min_width=6)
    table.add_column("Status", min_width=8)

    _SEVERITY_STYLE = {
        "CRITICAL": "bold white on red",
        "HIGH": "bold red",
        "MEDIUM": "yellow",
        "LOW": "green",
    }

    for severity in ["critical", "high", "medium", "low"]:
        severity_data = (reason or {}).get(severity)
        if severity_data is None:
            table.add_row(
                Text(severity.upper(), style=_SEVERITY_STYLE.get(severity.upper(), "")),
                "—",
                "—",
                "⚪ N/A",
            )
            continue

        limit = severity_data.get("limit")
        count = severity_data.get("count", 0)
        gate_status = (severity_data.get("status") or "").upper()

        limit_str = str(limit) if limit is not None else "N/A"

        if gate_status == "FAIL" or (limit is not None and count > limit):
            status_cell = Text("❌ FAIL", style="bold red")
        elif gate_status == "WARNING":
            status_cell = Text("⚠️  WARN", style="bold yellow")
        else:
            status_cell = Text("✅ PASS", style="bold green")

        table.add_row(
            Text(severity.upper(), style=_SEVERITY_STYLE.get(severity.upper(), "")),
            str(count),
            limit_str,
            status_cell,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Platform gate — failing vulnerabilities
# ---------------------------------------------------------------------------

def format_failing_vulnerabilities_table(
    collection: List[Dict[str, Any]],
    total_count: int,
    displayed_count: Optional[int] = None,
) -> None:
    """
    Render the failing vulnerabilities as a Rich table.
    ``total_count``    — totalCount from the API metadata.
    ``displayed_count`` — how many items are in ``collection`` (defaults to
                          ``len(collection)``).
    """
    if not collection:
        return

    shown = displayed_count if displayed_count is not None else len(collection)
    title = f"Failing Vulnerabilities ({shown} of {total_count} shown)"

    table = Table(
        title=title,
        show_header=True,
        header_style="bold red",
        box=rich_box.ROUNDED,
        row_styles=["none", "dim"],
    )
    table.add_column("ID", min_width=6, no_wrap=True)
    table.add_column("Severity", min_width=8)
    table.add_column("Title", min_width=30, max_width=50, overflow="ellipsis")
    table.add_column("File:Line", min_width=20, max_width=35, overflow="ellipsis")
    table.add_column("CVSS", justify="right", min_width=5)
    table.add_column("Description", min_width=40, max_width=60, overflow="ellipsis")

    _SEV_STYLE = {
        "CRITICAL": "bold white on red",
        "HIGH": "bold red",
        "MEDIUM": "yellow",
        "LOW": "green",
        "NOTIFICATION": "cyan",
    }

    for vuln in collection:
        severity = (vuln.get("severity") or "UNKNOWN").upper()
        file_path = vuln.get("file") or ""
        line = vuln.get("line")
        file_location = f"{file_path}:{line}" if file_path and line else file_path or "—"
        cvss = vuln.get("cvssScore")
        cvss_str = str(cvss) if cvss is not None else "—"
        raw_desc = _strip_markdown(vuln.get("description") or "")
        desc = raw_desc[:250] + ("…" if len(raw_desc) > 250 else "")

        table.add_row(
            str(vuln.get("id") or "—"),
            Text(severity, style=_SEV_STYLE.get(severity, "")),
            vuln.get("title") or "Untitled",
            file_location,
            cvss_str,
            desc,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Helper text formatters (pure strings — printed by the command layer)
# ---------------------------------------------------------------------------

def format_failure_header(total_count: int) -> str:
    plural = "vulnerability" if total_count == 1 else "vulnerabilities"
    return f"🔴 Security Gate FAILED — {total_count} {plural} exceeded threshold."


def format_pass_message() -> str:
    return "✅ Security Gate PASSED."


def format_full_details_hint(output_path: Optional[str] = None) -> str:
    if output_path:
        return f"💡 Full vulnerability details saved to: {output_path}"
    return "💡 Full vulnerability details: re-run with --output gate-result.json"


def format_truncation_notice(total_count: int, shown: int, issues_url: Optional[str] = None) -> List[str]:
    """Return notice lines when not all failing vulns could be displayed."""
    remaining = total_count - shown
    if remaining <= 0:
        return []
    plural = "vulnerability" if remaining == 1 else "vulnerabilities"
    lines = [f"   … {remaining} more {plural} exceeded threshold."]
    if issues_url:
        lines.append(f"   View all: {issues_url}")
    return lines


# ---------------------------------------------------------------------------
# Local-rules gate — summary table
# ---------------------------------------------------------------------------

def format_local_rules_summary(issues: List[Dict[str, Any]], rules: dict) -> None:
    """
    Render results of local rule evaluation (YAML mode).
    ``issues`` — list of {value: SEVERITY, count: N} from issuesStats.
    ``rules``  — parsed rules dict from the YAML file.
    """
    parsed_issues = {item["value"].upper(): item["count"] for item in issues}

    # Build per-severity: maximum from rules
    limits: Dict[str, int] = {}
    for rule in rules.get("rules", []):
        for sev, cfg in rule.get("severity", {}).items():
            limits[sev.upper()] = cfg.get("maximum", 0)

    table = Table(
        title="Security Gate — Local Rules Evaluation",
        show_header=True,
        header_style="bold cyan",
        box=rich_box.SIMPLE_HEAD,
    )
    table.add_column("Severity", style="bold", min_width=10)
    table.add_column("Count", justify="right", min_width=6)
    table.add_column("Maximum", justify="right", min_width=8)
    table.add_column("Result", min_width=8)

    _SEV_STYLE = {
        "CRITICAL": "bold white on red",
        "HIGH": "bold red",
        "MEDIUM": "yellow",
        "LOW": "green",
    }

    any_fail = False
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if severity not in limits:
            continue
        count = parsed_issues.get(severity, 0)
        maximum = limits[severity]
        if count > maximum:
            result_cell = Text("❌ FAIL", style="bold red")
            any_fail = True
        else:
            result_cell = Text("✅ PASS", style="bold green")

        table.add_row(
            Text(severity, style=_SEV_STYLE.get(severity, "")),
            str(count),
            str(maximum),
            result_cell,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Internal utilities
# ---------------------------------------------------------------------------

def _strip_markdown(text: str) -> str:
    """Strip common Markdown formatting for terminal display."""
    text = CODE_BLOCK_PATTERN.sub(" ", text)
    text = MARKDOWN_HEADER_PATTERN.sub("", text)
    text = MARKDOWN_LINK_PATTERN.sub(r"\1", text)
    text = text.replace("**", "").replace("__", "").replace("`", "")
    return re.sub(r"\s+", " ", text).strip()
