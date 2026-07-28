# conviso/commands/security_gate.py
"""
Security Gate Command Module
-----------------------------
Evaluates whether an asset's open vulnerabilities comply with configured
security policies ("security gate").

Two execution modes:

1. Platform mode (default, no --rules-file):
   Calls the ``securityGateRun`` GraphQL query.  The Conviso Platform
   applies its own configured thresholds and returns PASS / FAIL with a
   breakdown of failing vulnerabilities.

2. Local-rules mode (--rules-file <path>):
   Reads a YAML rules file, validates it against the JSON Schema, then
   queries ``issuesStats`` for each severity level (optionally scoped by
   ``max_days_to_fix``).  The threshold comparison is performed locally.

Exit codes:
  0 — gate PASSED (all rules satisfied).
  1 — gate FAILED (threshold exceeded) OR technical error (network / auth /
      invalid input).  The error message distinguishes both cases.
"""

import json
import time
import yaml
import jsonschema
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional

import typer

from conviso.clients.client_graphql import graphql_request
from conviso.core.notifier import info, success, error, warning
from conviso.core.security_gate_formatter import (
    format_severity_summary,
    format_failing_vulnerabilities_table,
    format_failure_header,
    format_pass_message,
    format_full_details_hint,
    format_truncation_notice,
    format_local_rules_summary,
)

app = typer.Typer(help="Run security gate checks against the Conviso Platform.")

# ---------------------------------------------------------------------------
# GraphQL queries
# ---------------------------------------------------------------------------

_SECURITY_GATE_RUN_QUERY = """
query SecurityGateRun($assetId: ID!, $page: Int!, $perPage: Int!) {
  securityGateRun(assetId: $assetId) {
    asset {
      id
      name
    }
    executionDate
    issuesUrl
    reason {
      low    { limit count status }
      medium { limit count status }
      high   { limit count status }
      critical { limit count status }
    }
    status
    failingVulnerabilities(pagination: { page: $page, perPage: $perPage }) {
      collection {
        id
        title
        description
        severity
        cvssScore
        file
        line
        platformUrl
      }
      metadata {
        totalCount
      }
    }
  }
}
"""

_ISSUES_STATS_QUERY = """
query IssuesStats(
  $asset_id: [ID!],
  $company_id: ID!,
  $statuses: [IssueStatusLabel!],
  $end_date: ISO8601DateTime
) {
  issuesStats(
    companyId: $company_id
    filters: {
      assetIds: $asset_id
      statuses: $statuses
      createdAtRange: {
        endDate: $end_date
      }
    }
  ) {
    severities {
      value
      count
    }
  }
}
"""

# Vulnerability statuses considered "open / pending resolution"
_OPEN_STATUSES = ["IDENTIFIED", "IN_PROGRESS", "AWAITING_VALIDATION"]

# How many failing vulns to fetch per page (platform mode)
_PAGE_SIZE = 10


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------

@app.command("assert-security-rules")
def assert_security_rules(
    asset_id: int = typer.Option(
        ...,
        "--asset-id",
        "-a",
        help="Asset ID on the Conviso Platform.",
        envvar="CONVISO_ASSET_ID",
    ),
    company_id: Optional[int] = typer.Option(
        None,
        "--company-id",
        "-c",
        help="Company ID. Required when --rules-file is provided.",
        envvar="CONVISO_COMPANY_ID",
    ),
    rules_file: Optional[Path] = typer.Option(
        None,
        "--rules-file",
        "-r",
        help=(
            "Path to a local YAML rules file. "
            "If omitted, the platform-configured rules are used."
        ),
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the full security gate result to a JSON file.",
    ),
):
    """
    Assert that an asset's vulnerabilities comply with security gate rules.

    Without --rules-file: delegates to the Conviso Platform (securityGateRun).
    With --rules-file:    evaluates YAML-defined thresholds locally via issuesStats.
    """
    # --- Conditional parameter validation (Typer has no native conditional required) ---
    if rules_file and not company_id:
        error(
            "--company-id is required when --rules-file is provided. "
            "Set it via --company-id or the CONVISO_COMPANY_ID environment variable."
        )
        raise typer.Exit(code=1)

    started_at = time.perf_counter()

    try:
        if rules_file:
            _run_local_rules_gate(asset_id, company_id, rules_file, output)
        else:
            _run_platform_gate(asset_id, output)
    except typer.Exit:
        raise
    except Exception as exc:
        error(f"Unexpected error during security gate execution: {exc}")
        raise typer.Exit(code=1)

    elapsed = time.perf_counter() - started_at
    info(f"Security gate check completed in {elapsed:.2f}s.")


# ---------------------------------------------------------------------------
# Platform gate flow
# ---------------------------------------------------------------------------

def _run_platform_gate(asset_id: int, output: Optional[str]) -> None:
    """Execute the security gate using Conviso Platform-configured rules."""
    info(f"Running security gate (platform rules) for asset {asset_id}...")

    try:
        # First request: page 1 to get total count and initial collection
        data = graphql_request(
            _SECURITY_GATE_RUN_QUERY,
            {"assetId": str(asset_id), "page": 1, "perPage": _PAGE_SIZE},
        )
    except Exception as exc:
        error(
            f"Failed to contact Conviso Platform API: {exc}\n"
            "This is a technical error, NOT a gate policy failure. "
            "Check your API key and network connectivity."
        )
        raise typer.Exit(code=1)

    result = data.get("securityGateRun")
    if result is None:
        error(
            "The API returned no result for securityGateRun. "
            "Ensure the asset ID is correct and the platform has a security gate configured."
        )
        raise typer.Exit(code=1)

    asset_info = result.get("asset") or {}
    asset_name = asset_info.get("name", "Unknown")
    gate_status = (result.get("status") or "").upper()
    reason = result.get("reason") or {}
    execution_date = result.get("executionDate", "Unknown")
    issues_url = result.get("issuesUrl")

    failing_vulns_raw = result.get("failingVulnerabilities") or {}
    metadata = failing_vulns_raw.get("metadata") or {}
    total_count = metadata.get("totalCount") or 0
    collection = failing_vulns_raw.get("collection") or []

    # Fetch remaining pages if there are more failing vulns than the first page
    if total_count > _PAGE_SIZE:
        collection = _fetch_all_failing_pages(asset_id, total_count, collection)

    # Inject the full collection back so the output JSON is complete
    result["failingVulnerabilities"] = {
        "collection": collection,
        "metadata": {"totalCount": total_count},
    }

    # Display
    info(f"Asset: {asset_name} (ID: {asset_id})")
    info(f"Execution date: {execution_date}")

    format_severity_summary(reason)

    if output:
        _write_json_output(result, output)

    if gate_status == "FAIL":
        error(format_failure_header(total_count))
        format_failing_vulnerabilities_table(collection, total_count, len(collection))
        for line in format_truncation_notice(total_count, len(collection), issues_url):
            typer.echo(line)
        typer.echo(format_full_details_hint(output))
        raise typer.Exit(code=1)

    success(format_pass_message())


def _fetch_all_failing_pages(
    asset_id: int,
    total_count: int,
    first_page_collection: list,
) -> list:
    """Fetch pages 2..N of failing vulnerabilities and merge with page 1."""
    import math
    total_pages = math.ceil(total_count / _PAGE_SIZE)
    all_items = list(first_page_collection)

    for page_num in range(2, total_pages + 1):
        try:
            data = graphql_request(
                _SECURITY_GATE_RUN_QUERY,
                {"assetId": str(asset_id), "page": page_num, "perPage": _PAGE_SIZE},
                log_request=True,
                verbose_only=True,
            )
            page_result = data.get("securityGateRun") or {}
            page_items = (page_result.get("failingVulnerabilities") or {}).get("collection") or []
            all_items.extend(page_items)
        except Exception as exc:
            warning(
                f"Could not fetch page {page_num} of failing vulnerabilities: {exc}. "
                "Continuing with partial results."
            )
            break

    return all_items


# ---------------------------------------------------------------------------
# Local-rules gate flow
# ---------------------------------------------------------------------------

def _run_local_rules_gate(
    asset_id: int,
    company_id: int,
    rules_file: Path,
    output: Optional[str],
) -> None:
    """Evaluate local YAML rules against the live issuesStats from the Platform."""
    info(f"Running security gate (local rules) for asset {asset_id}...")

    # --- Parse YAML ---
    try:
        raw = rules_file.read_text(encoding="utf-8")
        rules = yaml.safe_load(raw)
    except Exception as exc:
        error(f"Failed to read or parse rules file '{rules_file}': {exc}")
        raise typer.Exit(code=1)

    # --- Validate against JSON Schema ---
    schema_path = Path(__file__).resolve().parents[1] / "security_gate_rules_schema.json"
    try:
        with open(schema_path) as f:
            json_schema = json.load(f)
        jsonschema.validate(rules, json_schema)
    except jsonschema.exceptions.ValidationError as exc:
        error(f"Rules file validation failed: {exc.message}")
        raise typer.Exit(code=1)
    except FileNotFoundError:
        error(f"Internal error: JSON schema not found at {schema_path}.")
        raise typer.Exit(code=1)

    info(f"Rules loaded from '{rules_file.name}':")
    info(f"  {yaml.dump(rules, default_flow_style=True).strip()}")

    # --- Determine if any severity has max_days_to_fix ---
    days_by_severity = _extract_days_by_severity(rules)
    has_sla_filter = any(d > 0 for d in days_by_severity.values())

    # Reference "now" in UTC — single anchor for all comparisons
    now_utc = datetime.now(timezone.utc)
    # End of today in UTC (23:59:59)
    end_of_today_utc = now_utc.replace(hour=23, minute=59, second=59, microsecond=0)

    all_issues: list = []

    if has_sla_filter:
        # Fetch per-severity with individual date cutoffs
        seen: set = set()
        for severity, max_days in days_by_severity.items():
            cutoff_dt = end_of_today_utc - timedelta(days=max_days)
            # Only vulnerabilities created BEFORE the cutoff are out of SLA
            end_date_iso = cutoff_dt.isoformat()

            try:
                data = graphql_request(
                    _ISSUES_STATS_QUERY,
                    {
                        "asset_id": [str(asset_id)],
                        "company_id": str(company_id),
                        "statuses": _OPEN_STATUSES,
                        "end_date": end_date_iso,
                    },
                )
            except Exception as exc:
                error(
                    f"Failed to fetch issues stats for severity '{severity}': {exc}\n"
                    "This is a technical error, NOT a gate policy failure."
                )
                raise typer.Exit(code=1)

            severities = (data.get("issuesStats") or {}).get("severities") or []
            for item in severities:
                sev_value = (item.get("value") or "").upper()
                if sev_value == severity.upper() and sev_value not in seen:
                    seen.add(sev_value)
                    all_issues.append(item)
    else:
        # Fetch all severities in a single call (no date filter)
        try:
            data = graphql_request(
                _ISSUES_STATS_QUERY,
                {
                    "asset_id": [str(asset_id)],
                    "company_id": str(company_id),
                    "statuses": _OPEN_STATUSES,
                    "end_date": None,
                },
            )
        except Exception as exc:
            error(
                f"Failed to fetch issues stats: {exc}\n"
                "This is a technical error, NOT a gate policy failure."
            )
            raise typer.Exit(code=1)

        all_issues = (data.get("issuesStats") or {}).get("severities") or []

    # Ensure every severity has a default count of 0 if not returned by the API
    # (avoids KeyError in validate_rules when the API skips severities with 0 vulns)
    sev_map = {item.get("value", "").upper(): item.get("count", 0) for item in all_issues}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev not in sev_map:
            sev_map[sev] = 0
    all_issues_normalized = [{"value": k, "count": v} for k, v in sev_map.items()]

    # --- Evaluate rules ---
    gate_response = validate_rules(all_issues_normalized, rules)
    format_local_rules_summary(all_issues_normalized, rules)

    if output:
        output_payload = {
            "mode": "local_rules",
            "asset_id": asset_id,
            "company_id": company_id,
            "rules_file": str(rules_file),
            "issues": all_issues_normalized,
            "result": gate_response,
        }
        _write_json_output(output_payload, output)

    if gate_response["locked"]:
        error(
            "Security Gate FAILED: vulnerabilities exceed rules-defined thresholds.\n"
            f"Summary: {json.dumps(gate_response['summary'], indent=2)}"
        )
        raise typer.Exit(code=1)

    success(format_pass_message())


# ---------------------------------------------------------------------------
# Rule evaluation helpers
# ---------------------------------------------------------------------------

def validate_rules(issues: list, rules: dict) -> dict:
    """
    Evaluate the security gate rules against the current vulnerability counts.

    Returns a dict:
      {
        "locked": bool,               # True if any threshold is exceeded
        "summary": [{"from": "any", "severity": {...}}]
      }
    """
    response: dict = {
        "locked": False,
        "summary": [{"from": "any", "severity": {}}],
    }
    parsed_issues = {
        (item.get("value") or "").upper(): item.get("count", 0)
        for item in issues
    }

    for i, rule in enumerate(rules.get("rules", [])):
        if i >= len(response["summary"]):
            response["summary"].append({"from": rule.get("from", "any"), "severity": {}})

        for criticity, rule_cfg in rule.get("severity", {}).items():
            sev_key = criticity.upper()
            count = parsed_issues.get(sev_key, 0)
            maximum = rule_cfg.get("maximum", 0)

            if count > maximum:
                response["locked"] = True

            response["summary"][i]["severity"][criticity] = {
                "count": count,
                "maximum": maximum,
                "exceeded": count > maximum,
            }

    return response


def _extract_days_by_severity(rules: dict) -> dict:
    """
    Returns {severity_lower: max_days_to_fix} for each severity in the rules.
    Severities without max_days_to_fix get a value of 0 (no SLA filter).
    """
    days: dict = {}
    for rule in rules.get("rules", []):
        for severity, cfg in rule.get("severity", {}).items():
            days[severity.lower()] = cfg.get("max_days_to_fix", 0)
    return days


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _write_json_output(data: dict, output_path: str) -> None:
    """Write data as pretty-printed JSON to a file."""
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        info(f"Security gate result saved to: {output_path}")
    except Exception as exc:
        warning(f"Could not write output file '{output_path}': {exc}")
