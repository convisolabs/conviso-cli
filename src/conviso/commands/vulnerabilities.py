# conviso/commands/vulnerabilities.py
"""
Vulnerabilities Command Module
-----------------------------
Lists vulnerabilities (issues) with optional filters (asset IDs, pagination).
"""

import typer
from typing import Optional, List, Tuple
import json
import re
from datetime import date, datetime, timedelta, timezone
import requests
import time
from conviso.core.notifier import info, error, summary, success, warning, timed_summary
from conviso.core.concurrency import parallel_map, resolve_workers
from conviso.clients.client_graphql import graphql_request
from conviso.core.output_manager import export_data
from conviso.schemas.vulnerabilities_schema import schema
from conviso.schemas.vulnerabilities_timeline_schema import timeline_schema, timeline_last_schema

app = typer.Typer(help="List and manage vulnerabilities (WEB, NETWORK, SOURCE).")


@app.command("list")
def list_vulnerabilities(
    company_id: int = typer.Option(..., "--company-id", "-c", help="Company ID."),
    asset_ids: Optional[str] = typer.Option(None, "--asset-ids", "-a", help="Comma-separated asset IDs to filter."),
    project_ids: Optional[str] = typer.Option(None, "--project-ids", "-P", help="Comma-separated project IDs to filter."),
    severities: Optional[str] = typer.Option(None, "--severities", "-s", help="Comma-separated severities (NOTIFICATION,LOW,MEDIUM,HIGH,CRITICAL)."),
    asset_tags: Optional[str] = typer.Option(None, "--asset-tags", "-t", help="Comma-separated asset tags."),
    project_types: Optional[str] = typer.Option(None, "--project-types", help="Comma-separated project types (e.g. PENETRATION_TEST, WEB_PENETRATION_TESTING)."),
    cves: Optional[str] = typer.Option(None, "--cves", help="Comma-separated CVE identifiers."),
    issue_types: Optional[str] = typer.Option(None, "--types", help="Comma-separated failure types (e.g. WEB_VULNERABILITY, DAST_FINDING, SAST_FINDING, SOURCE_CODE_VULNERABILITY, NETWORK_VULNERABILITY, SCA_FINDING, IAC_FINDING, SECRET_FINDING, CONTAINER_FINDING)."),
    days_back: Optional[int] = typer.Option(None, "--days-back", help="Filter by created date in the last N days (sets --created-start automatically)."),
    created_start: Optional[str] = typer.Option(None, "--created-start", help="Created at >= (YYYY-MM-DD)."),
    created_end: Optional[str] = typer.Option(None, "--created-end", help="Created at <= (YYYY-MM-DD)."),
    risk_until_start: Optional[str] = typer.Option(None, "--risk-until-start", help="Risk accepted until >= (YYYY-MM-DD)."),
    risk_until_end: Optional[str] = typer.Option(None, "--risk-until-end", help="Risk accepted until <= (YYYY-MM-DD)."),
    compromised_env: bool = typer.Option(False, "--compromised-env", help="Filter compromised environment = true."),
    data_classification: Optional[str] = typer.Option(None, "--data-classification", help="Comma-separated data classifications (PII,PAYMENT_CARD_INDUSTRY,NON_SENSITIVE,NOT_DEFINED)."),
    business_impact: Optional[str] = typer.Option(None, "--business-impact", help="Comma-separated business impact levels (LOW,MEDIUM,HIGH,NOT_DEFINED)."),
    exploitability: Optional[str] = typer.Option(None, "--attack-surface", "-A", help="Attack surface (INTERNET_FACING,INTERNAL,NOT_DEFINED)."),
    assignee_emails: Optional[str] = typer.Option(None, "--assignees", help="Comma-separated assignee emails."),
    author: Optional[str] = typer.Option(None, "--author", help="Filter by author name (contains, case-insensitive)."),
    grep: Optional[str] = typer.Option(
        None,
        "--grep",
        help="Local free-text search across all returned fields (case-insensitive), e.g. --grep jwt.",
    ),
    contains: Optional[List[str]] = typer.Option(
        None,
        "--contains",
        help="Local field-specific filter in 'field=value' format (case-insensitive). Repeatable and combined with AND, e.g. --contains status=ANALYSIS --contains author=fernando. Deep fields (codeSnippet,fileName,vulnerableLine,request,response,url,method,parameters) auto-enable deep search.",
    ),
    deep_search: bool = typer.Option(
        False,
        "--deep-search",
        help="Force deep field resolution for local search (auto-enabled for deep --contains fields like codeSnippet/fileName/vulnerableLine/request/response/url/method/parameters).",
    ),
    workers: Optional[int] = typer.Option(None, "--workers", help="Override worker threads for this command (defaults to global --workers)."),
    resolve_snippet_urls: bool = typer.Option(
        True,
        "--resolve-snippet-urls/--no-resolve-snippet-urls",
        help="With deep search (manual or auto), fetch snippet file content when codeSnippet is an URL (common in IAC).",
    ),
    page: int = typer.Option(1, "--page", "-p", help="Page number."),
    per_page: int = typer.Option(50, "--per-page", "-l", help="Items per page."),
    all_pages: bool = typer.Option(False, "--all", help="Fetch all pages."),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table, json, csv, sarif."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file for json/csv/sarif."),
):
    """List vulnerabilities (issues) for a company, optionally filtered by asset IDs."""
    info(f"Listing vulnerabilities for company {company_id} (page {page}, per_page {per_page})...")
    started_at = time.perf_counter()
    fmt_lower = fmt.lower()

    SEVERITY_ALLOWED = {"NOTIFICATION", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    ATTACK_SURFACE_ALLOWED = {"INTERNET_FACING", "INTERNAL", "NOT_DEFINED"}

    query = """
    query Issues($companyId: ID!, $pagination: PaginationInput!, $filters: IssuesFiltersInput) {
      issues(companyId: $companyId, pagination: $pagination, filters: $filters) {
        collection {
          id
          title
          description
          status
          type
          asset {
            name
            assetsTagList
            company { label }
          }
          author { name }
          assignedUsers { name email }
          ... on SastFinding {
            severity
            solution
            reference
            impactLevel
            detail { vulnerableLine fileName codeSnippet }
          }
          ... on ScaFinding {
            severity
            solution
            reference
            impactLevel
            detail { package affectedVersion patchedVersion cve fileName }
          }
          ... on DastFinding {
            severity
            solution
            reference
            impactLevel
          }
          ... on NetworkVulnerability {
            severity
            solution
            reference
            impactLevel
          }
          ... on SourceCodeVulnerability {
            severity
            solution
            reference
            impactLevel
            detail { vulnerableLine fileName codeSnippet }
          }
          ... on IacFinding {
            severity
            solution
            reference
            impactLevel
            detail { vulnerableLine fileName codeSnippet }
          }
          ... on SecretFinding {
            severity
            solution
            reference
            impactLevel
            detail { vulnerableLine fileName codeSnippet }
          }
          ... on WebVulnerability {
            severity
            solution
            reference
            impactLevel
            detail { url method parameters }
          }
          ... on ContainerFinding {
            severity
            solution
            reference
            impactLevel
            detail { package affectedVersion patchedVersion cve }
          }
        }
        metadata {
          currentPage
          limitValue
          totalCount
          totalPages
        }
      }
    }
    """
    query_with_blob = """
    query Issues($companyId: ID!, $pagination: PaginationInput!, $filters: IssuesFiltersInput) {
      issues(companyId: $companyId, pagination: $pagination, filters: $filters) {
        collection {
          id
          title
          description
          status
          type
          asset {
            name
            assetsTagList
            company { label }
          }
          author { name }
          assignedUsers { name email }
          ... on SastFinding {
            severity
            solution
            reference
            impactLevel
            detail { vulnerableLine fileName codeSnippetBlob: codeSnippet(blob: true) codeSnippet }
          }
          ... on ScaFinding {
            severity
            solution
            reference
            impactLevel
            detail { package affectedVersion patchedVersion cve fileName }
          }
          ... on DastFinding {
            severity
            solution
            reference
            impactLevel
          }
          ... on NetworkVulnerability {
            severity
            solution
            reference
            impactLevel
          }
          ... on SourceCodeVulnerability {
            severity
            solution
            reference
            impactLevel
            detail { vulnerableLine fileName codeSnippetBlob: codeSnippet(blob: true) codeSnippet }
          }
          ... on IacFinding {
            severity
            solution
            reference
            impactLevel
            detail { vulnerableLine fileName codeSnippetBlob: codeSnippet(blob: true) codeSnippet }
          }
          ... on SecretFinding {
            severity
            solution
            reference
            impactLevel
            detail { vulnerableLine fileName codeSnippetBlob: codeSnippet(blob: true) codeSnippet }
          }
          ... on WebVulnerability {
            severity
            solution
            reference
            impactLevel
            detail { url method parameters }
          }
          ... on ContainerFinding {
            severity
            solution
            reference
            impactLevel
            detail { package affectedVersion patchedVersion cve }
          }
        }
        metadata {
          currentPage
          limitValue
          totalCount
          totalPages
        }
      }
    }
    """
    query_light = """
    query Issues($companyId: ID!, $pagination: PaginationInput!, $filters: IssuesFiltersInput) {
      issues(companyId: $companyId, pagination: $pagination, filters: $filters) {
        collection {
          id
          title
          status
          type
          asset {
            name
            assetsTagList
            company { label }
          }
          author { name }
          assignedUsers { name email }
          ... on SastFinding {
            severity
            detail { vulnerableLine fileName codeSnippet }
          }
          ... on ScaFinding {
            severity
            detail { package affectedVersion patchedVersion cve fileName }
          }
          ... on DastFinding { severity }
          ... on NetworkVulnerability { severity }
          ... on SourceCodeVulnerability {
            severity
            detail { vulnerableLine fileName codeSnippet }
          }
          ... on IacFinding {
            severity
            detail { vulnerableLine fileName codeSnippet }
          }
          ... on SecretFinding {
            severity
            detail { vulnerableLine fileName codeSnippet }
          }
          ... on WebVulnerability { severity }
          ... on ContainerFinding {
            severity
            detail { package affectedVersion patchedVersion cve }
          }
        }
        metadata {
          currentPage
          limitValue
          totalCount
          totalPages
        }
      }
    }
    """
    deep_issue_query = """
    query IssueSearchDetail($id: ID!) {
      issue(id: $id) {
        id
        ... on SastFinding {
          detail { fileName vulnerableLine codeSnippetBlob: codeSnippet(blob: true) codeSnippet }
        }
        ... on SourceCodeVulnerability {
          detail { fileName vulnerableLine codeSnippetBlob: codeSnippet(blob: true) codeSnippet }
        }
        ... on IacFinding {
          detail { fileName vulnerableLine codeSnippetBlob: codeSnippet(blob: true) codeSnippet }
        }
        ... on SecretFinding {
          detail { fileName vulnerableLine codeSnippetBlob: codeSnippet(blob: true) codeSnippet }
        }
        ... on ScaFinding {
          detail { package affectedVersion patchedVersion cve fileName }
        }
        ... on ContainerFinding {
          detail { package affectedVersion patchedVersion cve }
        }
      }
    }
    """
    deep_web_dast_query = """
    query IssueWebDastDetail($id: ID!) {
      issue(id: $id) {
        id
        ... on WebVulnerability {
          detail { url method parameters request response }
        }
        ... on DastFinding {
          detail { url method parameters request response }
        }
      }
    }
    """
    deep_web_dast_query_top_level = """
    query IssueWebDastDetailTopLevel($id: ID!) {
      issue(id: $id) {
        id
        ... on WebVulnerability {
          method
          url
          request
          response
          parameters
        }
        ... on DastFinding {
          method
          url
          request
          response
          parameters
        }
      }
    }
    """
    deep_web_dast_query_fallback = """
    query IssueWebDastDetailFallback($id: ID!) {
      issue(id: $id) {
        id
        ... on WebVulnerability { detail { url method parameters } }
        ... on DastFinding { detail { url method parameters } }
      }
    }
    """

    def _split_ids(value: Optional[str]):
        if not value:
            return None
        ids = []
        for raw in value.split(","):
            raw = raw.strip()
            if not raw:
                continue
            try:
                ids.append(int(raw))
            except ValueError:
                continue
        return ids or None

    def _split_strs(value: Optional[str]):
        if not value:
            return None
        vals = [v.strip() for v in value.split(",") if v.strip()]
        return vals or None

    filters = {}
    assets_list = _split_ids(asset_ids)
    projects_list = _split_ids(project_ids)
    severities_list = _split_strs(severities)
    if severities_list:
        new = []
        for s in severities_list:
            up = s.upper()
            if up not in SEVERITY_ALLOWED:
                error(f"Ignoring invalid severity: {s}")
                continue
            new.append(up)
        severities_list = new or None
    asset_tags_list = _split_strs(asset_tags)
    project_types_list = _split_strs(project_types)
    if project_types_list:
        project_types_list = [p.upper() for p in project_types_list]
    cves_list = _split_strs(cves)
    types_list = _split_strs(issue_types)
    data_class_list = _split_strs(data_classification)
    business_impact_list = _split_strs(business_impact)
    assignee_list = _split_strs(assignee_emails)
    if business_impact_list:
        business_impact_list = [b.upper() for b in business_impact_list]

    if days_back is not None:
        if days_back < 0:
            error("--days-back must be >= 0.")
            raise typer.Exit(code=1)
        if created_start:
            error("Use either --days-back or --created-start, not both.")
            raise typer.Exit(code=1)
        created_start = (date.today() - timedelta(days=days_back)).isoformat()

    created_range = None
    if created_start or created_end:
        created_range = {"startDate": created_start, "endDate": created_end}
    risk_range = None
    if risk_until_start or risk_until_end:
        risk_range = {"startDate": risk_until_start, "endDate": risk_until_end}

    if assets_list:
        filters["assetIds"] = assets_list
    if projects_list:
        filters["projectIds"] = projects_list
    if severities_list:
        filters["severities"] = severities_list
    if asset_tags_list:
        filters["assetTags"] = asset_tags_list
    if project_types_list:
        filters["projectTypes"] = project_types_list
    if cves_list:
        filters["cves"] = cves_list
    if types_list:
        filters["failureTypes"] = [t.upper() for t in types_list]
    if created_range:
        filters["createdAtRange"] = created_range
    if risk_range:
        filters["riskAcceptedUntilRange"] = risk_range
    if compromised_env:
        filters["compromisedEnvironment"] = True
    if data_class_list:
        filters["dataClassification"] = data_class_list
    if business_impact_list:
        filters["businessImpact"] = business_impact_list
    if exploitability:
        up = exploitability.upper()
        if up not in ATTACK_SURFACE_ALLOWED:
            error(f"Ignoring invalid attack surface: {exploitability}")
        else:
            filters["exploitability"] = up
    if assignee_list:
        filters["assigneeEmails"] = assignee_list

    author_filter = (author or "").strip().lower() or None
    grep_filter = (grep or "").strip().lower() or None

    field_aliases = {
        "id": "id",
        "title": "title",
        "type": "type",
        "status": "status",
        "severity": "severity_raw",
        "asset": "asset",
        "tags": "tags",
        "author": "author",
        "assignee": "assignee",
        "company": "company",
        "description": "description",
        "solution": "solution",
        "reference": "reference",
        "impactlevel": "impactLevel",
        "filename": "fileName",
        "vulnerableline": "vulnerableLine",
        "codesnippet": "codeSnippet",
        "snippet": "codeSnippet",
        "code": "codeSnippet",
        "file": "fileName",
        "line": "vulnerableLine",
        "package": "package",
        "affectedversion": "affectedVersion",
        "patchedversion": "patchedVersion",
        "cve": "cve",
        "url": "url",
        "method": "method",
        "request": "request",
        "response": "response",
        "parameters": "parameters",
        "params": "parameters",
    }
    contains_filters: List[Tuple[str, str]] = []
    contains_values_by_field: dict[str, list[str]] = {}
    for raw in contains or []:
        entry = (raw or "").strip()
        if not entry:
            continue
        if "=" not in entry:
            warning(f"Ignoring invalid --contains entry '{entry}'. Use field=value.")
            continue
        field_raw, value_raw = entry.split("=", 1)
        field_key = field_aliases.get(field_raw.strip().lower())
        if not field_key:
            warning(f"Ignoring unknown --contains field '{field_raw}'.")
            continue
        value = value_raw.strip().lower()
        if not value:
            warning(f"Ignoring empty --contains value for field '{field_raw}'.")
            continue
        contains_filters.append((field_key, value))
        contains_values_by_field.setdefault(field_key, []).append(value)

    if all_pages and per_page < 200:
        per_page = 200
        info("Using larger page size (200) for faster retrieval with --all.")

    variables = {
        "companyId": str(company_id),
        "pagination": {"page": page, "perPage": per_page},
        "filters": filters or None,
    }

    include_detail_raw = bool(grep_filter)
    search_trace_enabled = bool(grep_filter or contains_filters)
    trace_fields = [
        "id",
        "title",
        "type",
        "status",
        "severity_raw",
        "asset",
        "tags",
        "author",
        "assignee",
        "company",
        "description",
        "solution",
        "reference",
        "impactLevel",
        "fileName",
        "vulnerableLine",
        "codeSnippet",
        "package",
        "affectedVersion",
        "patchedVersion",
        "cve",
        "url",
        "method",
        "request",
        "response",
        "parameters",
        "snippetContent",
    ]

    def _matches_local_filters(row: dict) -> bool:
        if grep_filter:
            haystack = str(row.get("_grep_blob") or "").lower()
            if grep_filter not in haystack:
                return False
        for field_key, value in contains_filters:
            current = str(row.get(field_key) or "").lower()
            if field_key == "codeSnippet":
                # Fast-path: avoid expensive row-wide joins on huge datasets.
                fallback = " ".join([current, str(row.get("package") or ""), str(row.get("snippetContent") or "")]).lower()
                if value not in current and value not in fallback:
                    return False
                continue
            if value not in current:
                return False
        return True

    def _matched_fields(row: dict) -> list[str]:
        matched: list[str] = []
        if grep_filter:
            for key in trace_fields:
                if grep_filter in str(row.get(key) or "").lower():
                    matched.append(key)
        for field_key, value in contains_filters:
            current = str(row.get(field_key) or "").lower()
            if field_key == "codeSnippet":
                fallback = " ".join([current, str(row.get("package") or ""), str(row.get("snippetContent") or "")]).lower()
                if value in current or value in fallback:
                    matched.append(field_key)
                continue
            if value in current:
                matched.append(field_key)
        # Deduplicate while preserving order
        seen = set()
        ordered = []
        for item in matched:
            if item in seen:
                continue
            seen.add(item)
            ordered.append(item)
        return ordered

    auto_deep_fields = {"codeSnippet", "fileName", "vulnerableLine", "request", "response", "url", "method", "parameters"}
    auto_deep_requested = sorted(set(contains_values_by_field.keys()) & auto_deep_fields)
    effective_deep_search = bool(deep_search or auto_deep_requested)
    if auto_deep_requested and not deep_search:
        info(f"Auto deep-search enabled for --contains fields: {', '.join(auto_deep_requested)}.")

    code_terms = contains_values_by_field.get("codeSnippet", [])
    deep_contains_filters = {
        key: values
        for key, values in contains_values_by_field.items()
        if key in auto_deep_fields
    }
    requires_deep_for_fields = bool(effective_deep_search and deep_contains_filters)
    requires_deep_for_codesnippet = bool(code_terms and effective_deep_search)
    use_blob_snippet_query = requires_deep_for_codesnippet
    if use_blob_snippet_query:
        info("Deep search for codeSnippet enabled: requesting snippet blob inline in paginated query for better performance.")
    snippet_content_cache: dict[str, str] = {}

    def _fetch_deep_issue_detail(issue: dict) -> dict:
        issue_id = str(issue.get("id") or "")
        issue_type = str(issue.get("type") or "").upper()
        if not issue_id:
            return {}
        is_web_dast = issue_type in {"WEB_VULNERABILITY", "DAST_FINDING"}
        try:
            if is_web_dast:
                data = None
                for q in (deep_web_dast_query, deep_web_dast_query_top_level, deep_web_dast_query_fallback):
                    try:
                        data = graphql_request(q, {"id": issue_id}, log_request=True, verbose_only=True)
                        break
                    except Exception:
                        continue
                if not data:
                    return {}
                web_issue = data.get("issue") or {}
                detail = web_issue.get("detail") or {}
                return {
                    "url": web_issue.get("url") or detail.get("url"),
                    "method": web_issue.get("method") or detail.get("method"),
                    "request": web_issue.get("request") or detail.get("request"),
                    "response": web_issue.get("response") or detail.get("response"),
                    "parameters": web_issue.get("parameters") or detail.get("parameters"),
                }

            data = graphql_request(deep_issue_query, {"id": issue_id}, log_request=True, verbose_only=True)
            issue_data = data.get("issue") or {}
            return issue_data.get("detail") or {}
        except Exception:
            return {}

    def _looks_like_url(value: str) -> bool:
        v = (value or "").strip().lower()
        return v.startswith("http://") or v.startswith("https://")

    def _fetch_snippet_from_url(url: str) -> str:
        if not url:
            return ""
        cached = snippet_content_cache.get(url)
        if cached is not None:
            return cached
        try:
            resp = requests.get(url, timeout=8)
            resp.raise_for_status()
            text = (resp.text or "")[:300000]
            snippet_content_cache[url] = text
            return text
        except Exception:
            snippet_content_cache[url] = ""
            return ""

    try:
        fetch_all = all_pages  # Respect user pagination choices for all formats
        current_page = page
        rows = []
        total_count = 0
        total_pages = None
        max_pages = 200

        def _fetch_issues_page(page_num: int):
            vars_page = {
                "companyId": variables["companyId"],
                "pagination": {"page": page_num, "perPage": per_page},
                "filters": variables.get("filters"),
            }
            issues_query = query_with_blob if use_blob_snippet_query else query
            data = graphql_request(issues_query, vars_page, log_request=True, verbose_only=True)
            issues = data["issues"]
            return page_num, (issues.get("collection") or []), (issues.get("metadata") or {})

        def _build_page_rows(collection: list) -> list:
            page_rows = []
            for vuln in collection:
                asset = vuln.get("asset") or {}
                tags = ", ".join(asset.get("assetsTagList") or [])
                author_name = (vuln.get("author") or {}).get("name", "")
                if author_filter and author_filter not in author_name.lower():
                    continue
                severity_value = vuln.get("severity") or ""
                severity_raw = severity_value
                sev_color_map = {
                    "CRITICAL": "bold white on red",
                    "HIGH": "bold red",
                    "MEDIUM": "yellow",
                    "LOW": "green",
                    "NOTIFICATION": "cyan",
                }
                sev_display = severity_value
                sev_style = sev_color_map.get(severity_value.upper(), None)
                if fmt_lower == "table" and sev_style:
                    sev_display = f"[{sev_style}]{severity_value}[/{sev_style}]"
                assignee = ""
                assigned = vuln.get("assignedUsers") or []
                if assigned:
                    assignee = assigned[0].get("email") or assigned[0].get("name") or ""

                row = {
                    "id": vuln.get("id"),
                    "title": vuln.get("title"),
                    "type": vuln.get("type"),
                    "status": vuln.get("status"),
                    "severity": sev_display,
                    "severity_raw": severity_raw,
                    "asset": asset.get("name") or "",
                    "tags": tags,
                    "author": author_name,
                    "assignee": assignee,
                    "company": ((asset.get("company") or {}).get("label")) or "",
                    "description": vuln.get("description"),
                    "solution": vuln.get("solution"),
                    "reference": vuln.get("reference"),
                    "impactLevel": vuln.get("impactLevel"),
                    # SAST detail
                    "fileName": (vuln.get("detail") or {}).get("fileName"),
                    "vulnerableLine": (vuln.get("detail") or {}).get("vulnerableLine"),
                    "codeSnippet": (vuln.get("detail") or {}).get("codeSnippetBlob") or (vuln.get("detail") or {}).get("codeSnippet"),
                    "package": (vuln.get("detail") or {}).get("package"),
                    "affectedVersion": (vuln.get("detail") or {}).get("affectedVersion"),
                    "patchedVersion": (vuln.get("detail") or {}).get("patchedVersion"),
                    "cve": (vuln.get("detail") or {}).get("cve"),
                    "url": (vuln.get("detail") or {}).get("url"),
                    "method": (vuln.get("detail") or {}).get("method"),
                    "request": (vuln.get("detail") or {}).get("request"),
                    "response": (vuln.get("detail") or {}).get("response"),
                    "parameters": (vuln.get("detail") or {}).get("parameters"),
                    "detailRaw": json.dumps(vuln.get("detail") or {}, ensure_ascii=False) if include_detail_raw else "",
                    "matchedIn": "",
                }
                if grep_filter:
                    row["_grep_blob"] = " ".join(
                        [
                            str(row.get("id") or ""),
                            str(row.get("title") or ""),
                            str(row.get("type") or ""),
                            str(row.get("status") or ""),
                            str(row.get("severity_raw") or ""),
                            str(row.get("asset") or ""),
                            str(row.get("tags") or ""),
                            str(row.get("author") or ""),
                            str(row.get("assignee") or ""),
                            str(row.get("company") or ""),
                            str(row.get("description") or ""),
                            str(row.get("solution") or ""),
                            str(row.get("reference") or ""),
                            str(row.get("impactLevel") or ""),
                            str(row.get("fileName") or ""),
                            str(row.get("vulnerableLine") or ""),
                            str(row.get("codeSnippet") or ""),
                            str(row.get("package") or ""),
                            str(row.get("url") or ""),
                            str(row.get("method") or ""),
                            str(row.get("request") or ""),
                            str(row.get("response") or ""),
                            str(row.get("parameters") or ""),
                            str(row.get("affectedVersion") or ""),
                            str(row.get("patchedVersion") or ""),
                            str(row.get("cve") or ""),
                            str(row.get("detailRaw") or ""),
                        ]
                    )
                page_rows.append(row)
            return page_rows

        def _field_needs_deep_lookup(row: dict, field_key: str, values: list[str]) -> bool:
            current = str(row.get(field_key) or "").lower()
            if field_key == "codeSnippet":
                # URL means we still need detail/blob or fallback download.
                if _looks_like_url(current):
                    return True
                fallback = " ".join([current, str(row.get("package") or ""), str(row.get("snippetContent") or "")]).lower()
                return any(term not in fallback for term in values)
            return any(term not in current for term in values)

        def _enrich_page_rows(page_rows: list):
            if requires_deep_for_fields and page_rows:
                missing_rows = []
                for row in page_rows:
                    if any(_field_needs_deep_lookup(row, field_key, values) for field_key, values in deep_contains_filters.items()):
                        missing_rows.append(row)
                if missing_rows:
                    max_workers = resolve_workers(workers)
                    detail_list = parallel_map(
                        _fetch_deep_issue_detail,
                        missing_rows,
                        workers=max_workers,
                    )
                    for row, deep_detail in zip(missing_rows, detail_list):
                        if not deep_detail:
                            continue
                        snippet_blob = deep_detail.get("codeSnippetBlob")
                        snippet_default = deep_detail.get("codeSnippet")
                        row["fileName"] = deep_detail.get("fileName") or row.get("fileName")
                        row["vulnerableLine"] = deep_detail.get("vulnerableLine") or row.get("vulnerableLine")
                        row["codeSnippet"] = snippet_blob or snippet_default or row.get("codeSnippet")
                        row["package"] = deep_detail.get("package") or row.get("package")
                        row["affectedVersion"] = deep_detail.get("affectedVersion") or row.get("affectedVersion")
                        row["patchedVersion"] = deep_detail.get("patchedVersion") or row.get("patchedVersion")
                        row["cve"] = deep_detail.get("cve") or row.get("cve")
                        row["url"] = deep_detail.get("url") or row.get("url")
                        row["method"] = deep_detail.get("method") or row.get("method")
                        row["request"] = deep_detail.get("request") or row.get("request")
                        row["response"] = deep_detail.get("response") or row.get("response")
                        row["parameters"] = deep_detail.get("parameters") or row.get("parameters")
                        if include_detail_raw:
                            row["detailRaw"] = json.dumps(deep_detail, ensure_ascii=False)
                        if grep_filter:
                            row["_grep_blob"] = f"{row.get('_grep_blob') or ''} {row.get('codeSnippet') or ''} {row.get('fileName') or ''} {row.get('vulnerableLine') or ''} {row.get('package') or ''} {row.get('url') or ''} {row.get('method') or ''} {row.get('request') or ''} {row.get('response') or ''} {row.get('parameters') or ''}"

                if resolve_snippet_urls and missing_rows:
                    url_rows = []
                    for row in missing_rows:
                        cs = str(row.get("codeSnippet") or "")
                        if _looks_like_url(cs):
                            fallback = f"{cs} {row.get('package') or ''}".lower()
                            if any(term not in fallback for term in code_terms):
                                url_rows.append(row)
                    if url_rows:
                        max_workers = resolve_workers(workers)
                        contents = parallel_map(
                            lambda r: _fetch_snippet_from_url(str(r.get("codeSnippet") or "")),
                            url_rows,
                            workers=max_workers,
                        )
                        for row, content in zip(url_rows, contents):
                            if not content:
                                continue
                            row["snippetContent"] = content
                            if include_detail_raw:
                                row["detailRaw"] = f"{row.get('detailRaw') or ''}\n{content[:120000]}"
                            if grep_filter:
                                row["_grep_blob"] = f"{row.get('_grep_blob') or ''} {content[:120000]}"

        def _append_filtered_rows(page_rows: list):
            for row in page_rows:
                if _matches_local_filters(row):
                    if search_trace_enabled:
                        matches = _matched_fields(row)
                        row["matchedIn"] = ", ".join(matches[:6]) if matches else "unknown"
                    rows.append(row)

        page_num, collection, metadata = _fetch_issues_page(current_page)
        total_pages = metadata.get("totalPages")
        total_count = metadata.get("totalCount", total_count)
        if not total_pages and total_count and per_page:
            total_pages = (total_count + per_page - 1) // per_page

        if not collection:
            typer.echo("⚠️  No vulnerabilities found.")
            raise typer.Exit()

        page_rows = _build_page_rows(collection)
        _enrich_page_rows(page_rows)
        _append_filtered_rows(page_rows)

        if fetch_all:
            can_parallel_pages = bool(total_pages is not None and current_page < total_pages)
            if can_parallel_pages:
                page_numbers = list(range(current_page + 1, total_pages + 1))
                max_workers = resolve_workers(workers)
                page_results = parallel_map(_fetch_issues_page, page_numbers, workers=max_workers)
                for _, next_collection, _ in sorted(page_results, key=lambda x: x[0]):
                    if not next_collection:
                        continue
                    next_rows = _build_page_rows(next_collection)
                    _enrich_page_rows(next_rows)
                    _append_filtered_rows(next_rows)
            else:
                last_signature = (collection[0].get("id"), collection[-1].get("id"))
                while True:
                    current_page += 1
                    if total_pages is not None and current_page > total_pages:
                        break
                    if total_pages is None and current_page > max_pages:
                        error("Stopping pagination early to avoid infinite loop (missing metadata).")
                        break

                    _, next_collection, next_metadata = _fetch_issues_page(current_page)
                    if not next_collection:
                        break

                    signature = (next_collection[0].get("id"), next_collection[-1].get("id"))
                    if last_signature == signature:
                        error("Pagination appears to be repeating the same results; stopping early to avoid a loop.")
                        break
                    last_signature = signature

                    if total_pages is None:
                        maybe_total_pages = next_metadata.get("totalPages")
                        maybe_total_count = next_metadata.get("totalCount")
                        if maybe_total_count:
                            total_count = maybe_total_count
                        if maybe_total_pages:
                            total_pages = maybe_total_pages

                    next_rows = _build_page_rows(next_collection)
                    _enrich_page_rows(next_rows)
                    _append_filtered_rows(next_rows)

                    if total_pages is None and len(next_collection) < per_page:
                        break
        if fmt_lower == "sarif":
            export_rows = [{k: v for k, v in r.items() if not str(k).startswith("_")} for r in rows]
            sarif = _to_sarif(export_rows)
            sarif_json = json.dumps(sarif, indent=2)
            if output:
                with open(output, "w", encoding="utf-8") as f:
                    f.write(sarif_json)
                summary(f"SARIF exported to {output}")
            else:
                print(sarif_json)
            elapsed = time.perf_counter() - started_at
            timed_summary(f"{len(rows)} vulnerability(ies) listed out of {total_count or len(rows)}", elapsed)
        else:
            # Keep full payload for JSON; constrain fields for table/csv to schema columns.
            output_rows = [{k: v for k, v in r.items() if not str(k).startswith("_")} for r in rows]
            if fmt_lower in {"table", "csv"} and schema and hasattr(schema, "display_headers"):
                display_keys = list(schema.display_headers.keys())
                output_rows = [{k: r.get(k, "") for k in display_keys} for r in rows]
            export_data(
                output_rows,
                schema=schema,
                fmt=fmt,
                output=output,
                title=f"Vulnerabilities (Company {company_id}) - Page {page}/{total_pages or '?'}",
            )
            elapsed = time.perf_counter() - started_at
            timed_summary(f"{len(rows)} vulnerability(ies) listed out of {total_count or len(rows)}", elapsed)
    except Exception as e:
        error(f"Error listing vulnerabilities: {e}")
        raise typer.Exit(code=1)


def _to_sarif(rows):
    import re

    def strip_rich(text: str) -> str:
        return re.sub(r"\[/?[^\]]+\]", "", text or "")

    def sev_to_level(sev: str):
        sev_up = str(sev).upper()
        if sev_up in {"CRITICAL", "HIGH"}:
            return "error"
        if sev_up == "MEDIUM":
            return "warning"
        return "note"

    results = []
    for r in rows:
        raw_sev = r.get("severity_raw") or r.get("severity") or ""
        raw_sev = strip_rich(raw_sev)
        level = sev_to_level(raw_sev)
        message = r.get("title") or "Vulnerability"
        # Use asset name as URI placeholder
        uri = r.get("asset") or "N/A"
        results.append({
            "ruleId": (r.get("type") or "vulnerability").upper(),
            "level": level,
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": 1},
                    }
                }
            ],
            "properties": {
                "severity": raw_sev,
                "status": r.get("status"),
                "asset": r.get("asset"),
                "author": r.get("author"),
                "company": r.get("company"),
                "description": r.get("description"),
                "solution": r.get("solution"),
                "reference": r.get("reference"),
                "impactLevel": r.get("impactLevel"),
                "fileName": r.get("fileName"),
                "vulnerableLine": r.get("vulnerableLine"),
                "codeSnippet": r.get("codeSnippet"),
                "url": r.get("url"),
                "method": r.get("method"),
                "request": r.get("request"),
                "response": r.get("response"),
                "parameters": r.get("parameters"),
            },
        })

    return {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "runs": [
            {
                "tool": {"driver": {"name": "Conviso CLI", "informationUri": "https://github.com/convisolabs/conviso-cli"}},
                "results": results,
            }
        ],
    }


def _parse_dt_filter(value: Optional[str], end_of_day: bool = False) -> Optional[datetime]:
    if not value:
        return None
    raw = value.strip()
    try:
        if len(raw) == 10 and raw[4] == "-" and raw[7] == "-":
            date_obj = datetime.strptime(raw, "%Y-%m-%d")
            if end_of_day:
                return date_obj.replace(hour=23, minute=59, second=59, microsecond=999999, tzinfo=timezone.utc)
            return date_obj.replace(tzinfo=timezone.utc)
        raw = raw.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(raw)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        warning(f"Ignoring invalid date/datetime filter: {value}")
        return None


def _safe_parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def _extract_status_change_fields(history_item: dict) -> tuple[str, str, str]:
    from_status = ""
    to_status = ""
    event_status = ""

    candidates = [
        ("fromStatus", "toStatus"),
        ("oldStatus", "newStatus"),
        ("previousStatus", "status"),
    ]
    for left_key, right_key in candidates:
        left = history_item.get(left_key)
        right = history_item.get(right_key)
        if left and not from_status:
            from_status = str(left).upper()
        if right and not to_status:
            to_status = str(right).upper()

    status_value = history_item.get("status")
    if status_value:
        event_status = str(status_value).upper()
        if not to_status:
            to_status = event_status

    if not to_status:
        action_type = (history_item.get("actionType") or "").upper()
        if "STATUS" in action_type:
            tokens = [t for t in re.split(r"[^A-Z0-9_]+", action_type) if t]
            for idx, token in enumerate(tokens):
                if token == "STATUS" and idx + 1 < len(tokens):
                    to_status = tokens[idx + 1]
                    break
            if not to_status:
                for token in reversed(tokens):
                    if token != "STATUS":
                        to_status = token
                        break

    return from_status, to_status, event_status


@app.command("timeline", help="Show vulnerability timeline/history and filter by actor/status.")
def vulnerability_timeline(
    issue_id: Optional[int] = typer.Option(None, "--id", "-i", help="Vulnerability/issue ID."),
    company_id: Optional[int] = typer.Option(None, "--company-id", "-c", help="Company ID (required with --project-id)."),
    project_id: Optional[int] = typer.Option(None, "--project-id", "-P", help="Project ID to aggregate timelines from related vulnerabilities."),
    user_email: Optional[str] = typer.Option(None, "--user-email", help="Filter by actor email or name (contains, case-insensitive)."),
    status: Optional[str] = typer.Option(None, "--status", help="Filter status-change events by target status (IssueStatusLabel)."),
    history_start: Optional[str] = typer.Option(None, "--history-start", help="History created_at >= this value (YYYY-MM-DD or ISO-8601)."),
    history_end: Optional[str] = typer.Option(None, "--history-end", help="History created_at <= this value (YYYY-MM-DD or ISO-8601)."),
    last_status_change_only: bool = typer.Option(False, "--last-status-change-only", help="Show only the latest status-change event after filters."),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table, json, csv."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file for json/csv."),
):
    if issue_id is not None and project_id is not None:
        error("Use either --id or --project-id, not both.")
        raise typer.Exit(code=1)
    if issue_id is None and project_id is None:
        error("Provide --id or --project-id (with --company-id).")
        raise typer.Exit(code=1)
    if project_id is not None and company_id is None:
        error("--company-id is required when using --project-id.")
        raise typer.Exit(code=1)
    if company_id is not None and project_id is None and issue_id is None:
        error("--company-id alone is not enough; use with --project-id or provide --id.")
        raise typer.Exit(code=1)

    if issue_id is not None:
        info(f"Listing timeline for vulnerability {issue_id}...")
    else:
        info(f"Listing timeline for vulnerabilities in project {project_id} (company {company_id})...")
    started_at = time.perf_counter()

    status_filter = status.strip().upper() if status else None
    email_filter = (user_email or "").strip().lower() or None
    history_start_dt = _parse_dt_filter(history_start, end_of_day=False)
    history_end_dt = _parse_dt_filter(history_end, end_of_day=True)

    issue_timeline_query = """
    query IssueTimeline($id: ID!) {
      issue(id: $id) {
        id
        title
        status
        history {
          eventId
          at
          action
          authorEmail
          assigneeEmail
          previousStatus
          status
          kind
          reason
        }
      }
    }
    """

    project_issues_query = """
    query IssuesByProject($companyId: ID!, $pagination: PaginationInput!, $filters: IssuesFiltersInput) {
      issues(companyId: $companyId, pagination: $pagination, filters: $filters) {
        collection {
          id
          title
          status
        }
        metadata {
          currentPage
          totalPages
          totalCount
        }
      }
    }
    """

    def _fetch_project_issues(cid: int, pid: int) -> list[dict]:
        current_page = 1
        per_page = 100
        out = []
        while True:
            data = graphql_request(
                project_issues_query,
                {
                    "companyId": str(cid),
                    "pagination": {"page": current_page, "perPage": per_page},
                    "filters": {"projectIds": [pid]},
                },
                log_request=True,
                verbose_only=True,
            )
            issues = (data.get("issues") or {})
            collection = issues.get("collection") or []
            metadata = issues.get("metadata") or {}
            total_pages = metadata.get("totalPages")
            out.extend(collection)
            if not collection:
                break
            if total_pages is not None and current_page >= total_pages:
                break
            if len(collection) < per_page:
                break
            current_page += 1
        return out

    def _fetch_issue_timeline(issue_stub: dict) -> tuple[dict, list[dict]]:
        current_issue_id = issue_stub.get("id")
        if not current_issue_id:
            return {}, []
        try:
            data = graphql_request(
                issue_timeline_query,
                {"id": str(current_issue_id)},
                log_request=True,
                verbose_only=True,
            )
        except Exception:
            return issue_stub, []
        issue = data.get("issue") or {}
        if not issue:
            return issue_stub, []
        return issue, issue.get("history") or []

    try:
        rows = []
        target_issues = []
        if issue_id is not None:
            target_issues = [{"id": str(issue_id)}]
        else:
            target_issues = _fetch_project_issues(company_id, project_id)
            if not target_issues:
                warning("No vulnerabilities found for the given project.")
                raise typer.Exit()

        issue_histories = parallel_map(_fetch_issue_timeline, target_issues)
        for issue, history_rows in issue_histories:
            if not issue:
                continue
            current_issue_id = issue.get("id")

            for h in history_rows:
                action_type = (h.get("action") or "").upper()
                actor_email = (h.get("authorEmail") or "").strip()
                actor_name = actor_email.split("@", 1)[0] if actor_email else ""
                created_at = h.get("at") or ""
                created_at_dt = _safe_parse_iso(created_at)
                from_status = (h.get("previousStatus") or "").upper()
                to_status = (h.get("status") or "").upper()
                event_status = to_status
                kind = (h.get("kind") or "").lower()
                is_status_change = bool(kind == "status" or from_status or to_status)

                if email_filter:
                    haystack = f"{actor_email.lower()} {actor_name.lower()}".strip()
                    if email_filter not in haystack:
                        continue
                if history_start_dt and (created_at_dt is None or created_at_dt < history_start_dt):
                    continue
                if history_end_dt and (created_at_dt is None or created_at_dt > history_end_dt):
                    continue
                if status_filter:
                    if not is_status_change:
                        continue
                    if (to_status or event_status) != status_filter:
                        continue

                rows.append({
                    "projectId": str(project_id) if project_id is not None else "",
                    "issueId": issue.get("id") or current_issue_id,
                    "issueTitle": issue.get("title") or "",
                    "currentIssueStatus": issue.get("status") or "",
                    "eventId": h.get("eventId") or "",
                    "createdAt": created_at,
                    "actorName": actor_name,
                    "actorEmail": actor_email,
                    "actionType": action_type,
                    "fromStatus": from_status,
                    "toStatus": to_status or event_status,
                    "statusChange": "true" if is_status_change else "false",
                })

        if not rows:
            warning("No timeline events found for the given filters.")
            raise typer.Exit()

        if last_status_change_only:
            status_rows = [r for r in rows if r.get("statusChange") == "true"]
            if not status_rows:
                warning("No status-change events found for the given filters.")
                raise typer.Exit()
            status_rows.sort(
                key=lambda r: (
                    _safe_parse_iso(r.get("createdAt") or "") or datetime.min.replace(tzinfo=timezone.utc),
                    str(r.get("eventId") or ""),
                )
            )
            latest = status_rows[-1]
            latest = {
                "projectId": latest.get("projectId"),
                "issueId": latest.get("issueId"),
                "issueTitle": latest.get("issueTitle"),
                "currentIssueStatus": latest.get("currentIssueStatus"),
                "lastChangedAt": latest.get("createdAt"),
                "lastChangedBy": latest.get("actorName"),
                "lastChangedByEmail": latest.get("actorEmail"),
                "fromStatus": latest.get("fromStatus"),
                "toStatus": latest.get("toStatus"),
                "actionType": latest.get("actionType"),
            }
            if project_id is not None:
                grouped_latest = {}
                for r in status_rows:
                    key = str(r.get("issueId") or "")
                    curr = grouped_latest.get(key)
                    if curr is None:
                        grouped_latest[key] = r
                        continue
                    curr_dt = _safe_parse_iso(curr.get("createdAt") or "") or datetime.min.replace(tzinfo=timezone.utc)
                    r_dt = _safe_parse_iso(r.get("createdAt") or "") or datetime.min.replace(tzinfo=timezone.utc)
                    if r_dt > curr_dt or (r_dt == curr_dt and str(r.get("eventId") or "") > str(curr.get("eventId") or "")):
                        grouped_latest[key] = r
                latest_rows = []
                for r in grouped_latest.values():
                    latest_rows.append({
                        "projectId": r.get("projectId"),
                        "issueId": r.get("issueId"),
                        "issueTitle": r.get("issueTitle"),
                        "currentIssueStatus": r.get("currentIssueStatus"),
                        "lastChangedAt": r.get("createdAt"),
                        "lastChangedBy": r.get("actorName"),
                        "lastChangedByEmail": r.get("actorEmail"),
                        "fromStatus": r.get("fromStatus"),
                        "toStatus": r.get("toStatus"),
                        "actionType": r.get("actionType"),
                    })
                latest_rows.sort(
                    key=lambda r: (
                        _safe_parse_iso(r.get("lastChangedAt") or "") or datetime.min.replace(tzinfo=timezone.utc),
                        str(r.get("issueId") or ""),
                    )
                )
                export_data(
                    latest_rows,
                    schema=timeline_last_schema,
                    fmt=fmt,
                    output=output,
                    title=f"Project {project_id} - Last Status Change Per Vulnerability",
                )
                elapsed = time.perf_counter() - started_at
                timed_summary(f"{len(latest_rows)} vulnerability(ies) with last status-change listed", elapsed)
                return

            export_data(
                [latest],
                schema=timeline_last_schema,
                fmt=fmt,
                output=output,
                title=f"Vulnerability {issue_id} - Last Status Change",
            )
            elapsed = time.perf_counter() - started_at
            timed_summary("1 last status-change event listed", elapsed)
            return

        if project_id is not None:
            export_data(
                rows,
                schema=timeline_schema,
                fmt=fmt,
                output=output,
                title=f"Project {project_id} - Vulnerabilities Timeline",
            )
        else:
            export_data(
                rows,
                schema=timeline_schema,
                fmt=fmt,
                output=output,
                title=f"Vulnerability {issue_id} - Timeline",
            )
        elapsed = time.perf_counter() - started_at
        timed_summary(f"{len(rows)} timeline event(s) listed", elapsed)

    except typer.Exit:
        raise
    except Exception as exc:
        if "RECORD_NOT_FOUND" in str(exc) and issue_id is not None:
            error(f"Issue {issue_id} not found. Use the vulnerability ID (not project ID).")
            raise typer.Exit(code=1)
        error(f"Error listing vulnerability timeline: {exc}")
        raise typer.Exit(code=1)


# ---------------------- CREATE COMMAND ---------------------- #
@app.command("create")
def create_vulnerability(
    company_id: Optional[int] = typer.Option(None, "--company-id", "-c", help="Company ID (optional)."),
    vtype: str = typer.Option(
        ...,
        "--type",
        "-t",
        help="Vuln type: WEB|NETWORK|SOURCE|DAST|SAST|SCA|IAC|CONTAINER|SECRET (required)",
    ),
    asset_id: int = typer.Option(..., "--asset-id", "-a", help="Asset ID"),
    title: str = typer.Option(..., "--title", help="Title"),
    description: str = typer.Option(..., "--description", help="Description"),
    solution: str = typer.Option(..., "--solution", help="Solution"),
    impact_level: str = typer.Option(..., "--impact-level", help="ImpactLevelCategory (e.g., HIGH) (required)"),
    probability_level: str = typer.Option(..., "--probability-level", help="ProbabilityLevelCategory (e.g., MEDIUM) (required)"),
    severity: str = typer.Option(..., "--severity", help="Severity (NOTIFICATION|LOW|MEDIUM|HIGH|CRITICAL) (required)"),
    summary_text: Optional[str] = typer.Option(None, "--summary", help="Summary (required for WEB/NETWORK/SOURCE)."),
    impact_description: Optional[str] = typer.Option(None, "--impact-description", help="Impact description (required for WEB/NETWORK/SOURCE)."),
    steps_to_reproduce: Optional[str] = typer.Option(None, "--steps", help="Steps to reproduce (required for WEB/NETWORK/SOURCE)."),
    reference: Optional[str] = typer.Option(None, "--reference", help="Reference/CWE/URL"),
    category: Optional[str] = typer.Option(None, "--category", help="Category"),
    project_id: Optional[int] = typer.Option(None, "--project-id", help="Project ID"),
    status: Optional[str] = typer.Option(None, "--status", help="IssueStatusLabel (e.g., ANALYSIS, REMEDIATION)"),
    compromised_env: Optional[bool] = typer.Option(None, "--compromised-env", help="Compromised environment (true/false)"),
    # WEB
    method: Optional[str] = typer.Option(None, "--method", help="HTTP method (WEB)"),
    scheme: Optional[str] = typer.Option(None, "--scheme", help="Scheme (WEB)"),
    url: Optional[str] = typer.Option(None, "--url", help="URL (WEB)"),
    web_port: Optional[int] = typer.Option(None, "--port", help="Port (WEB/NETWORK)"),
    request: Optional[str] = typer.Option(None, "--request", help="Request (WEB)"),
    response: Optional[str] = typer.Option(None, "--response", help="Response (WEB)"),
    parameters: Optional[str] = typer.Option(None, "--parameters", help="Parameters (WEB)"),
    # NETWORK
    address: Optional[str] = typer.Option(None, "--address", help="Address/host/IP (NETWORK)"),
    protocol: Optional[str] = typer.Option(None, "--protocol", help="Protocol (NETWORK)"),
    attack_vector: Optional[str] = typer.Option(None, "--attack-vector", help="Attack vector (NETWORK)"),
    # SOURCE
    file_name: Optional[str] = typer.Option(None, "--file-name", help="File name (SOURCE)"),
    vulnerable_line: Optional[int] = typer.Option(None, "--vulnerable-line", help="Vulnerable line (SOURCE)"),
    first_line: Optional[int] = typer.Option(None, "--first-line", help="First line (SOURCE)"),
    code_snippet: Optional[str] = typer.Option(None, "--code-snippet", help="Code snippet (SOURCE)"),
    source: Optional[str] = typer.Option(None, "--source", help="Source (SOURCE optional)"),
    sink: Optional[str] = typer.Option(None, "--sink", help="Sink (SOURCE optional)"),
    commit_ref: Optional[str] = typer.Option(None, "--commit-ref", help="Commit ref (SOURCE optional)"),
    deploy_id: Optional[str] = typer.Option(None, "--deploy-id", help="Deploy ID (SOURCE optional)"),
):
    """Create a vulnerability (WEB, NETWORK, SOURCE, DAST, SAST, SCA, IAC, CONTAINER, SECRET)."""
    vtype_up = vtype.strip().upper()
    supported_create = {"WEB", "NETWORK", "SOURCE", "DAST", "SAST", "SCA", "IAC", "CONTAINER", "SECRET"}
    if vtype_up not in supported_create:
        error(f"Invalid --type. Use one of: {', '.join(sorted(supported_create))}.")
        raise typer.Exit(code=1)

    SEVERITY_ALLOWED = {"NOTIFICATION", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    severity_up = severity.strip().upper()
    if severity_up not in SEVERITY_ALLOWED:
        error(f"Invalid severity '{severity}'. Use one of {', '.join(SEVERITY_ALLOWED)}.")
        raise typer.Exit(code=1)

    common = {
        "assetId": asset_id,
        "title": title,
        "description": description,
        "solution": solution,
        "impactLevel": impact_level.strip().upper(),
        "probabilityLevel": probability_level.strip().upper(),
        "severity": severity_up,
        "summary": summary_text,
        "impactDescription": impact_description,
        "stepsToReproduce": steps_to_reproduce,
        "reference": reference,
        "category": category,
        "projectId": project_id,
        "status": status.strip().upper() if status else None,
        "compromisedEnvironment": compromised_env,
    }
    if company_id is not None:
        common["companyId"] = company_id
    common = {k: v for k, v in common.items() if v is not None}

    try:
        if vtype_up == "WEB":
            required = [method, scheme, url, web_port, request, response]
            if any(x is None for x in required):
                error("WEB requires --method --scheme --url --port --request --response")
                raise typer.Exit(code=1)
            payload = dict(common)
            payload.update({
                "method": method.strip().upper(),
                "scheme": scheme.strip().upper(),
                "url": url,
                "port": int(web_port),
                "request": request,
                "response": response,
            })
            if parameters:
                payload["parameters"] = parameters
            payload["summary"] = summary_text or title
            payload["impactDescription"] = impact_description or description
            payload["stepsToReproduce"] = steps_to_reproduce or description
            mutation = """
            mutation CreateWeb($input: CreateWebVulnerabilityInput!) {
              createWebVulnerability(input: $input) { issue { id title } }
            }
            """
            data = graphql_request(mutation, {"input": payload})
            issue = ((data.get("createWebVulnerability") or {}).get("issue") or {})
            success(f"Created WEB vulnerability '{title}' (ID {issue.get('id')})")

        elif vtype_up == "NETWORK":
            required = [address, protocol, web_port, attack_vector]
            if any(x is None for x in required):
                error("NETWORK requires --address --protocol --port --attack-vector")
                raise typer.Exit(code=1)
            payload = dict(common)
            payload.update({
                "address": address,
                "protocol": protocol,
                "port": int(web_port),
                "attackVector": attack_vector,
            })
            payload["summary"] = summary_text or title
            payload["impactDescription"] = impact_description or description
            payload["stepsToReproduce"] = steps_to_reproduce or description
            mutation = """
            mutation CreateNetwork($input: CreateNetworkVulnerabilityInput!) {
              createNetworkVulnerability(input: $input) { issue { id title } }
            }
            """
            data = graphql_request(mutation, {"input": payload})
            issue = ((data.get("createNetworkVulnerability") or {}).get("issue") or {})
            success(f"Created NETWORK vulnerability '{title}' (ID {issue.get('id')})")

        elif vtype_up == "SOURCE":
            required = [file_name, vulnerable_line, first_line, code_snippet]
            if any(x is None for x in required):
                error("SOURCE requires --file-name --vulnerable-line --first-line --code-snippet")
                raise typer.Exit(code=1)
            payload = dict(common)
            payload.update({
                "fileName": file_name,
                "vulnerableLine": int(vulnerable_line),
                "firstLine": int(first_line),
                "codeSnippet": code_snippet,
            })
            if source:
                payload["source"] = source
            if sink:
                payload["sink"] = sink
            if commit_ref:
                payload["commitRef"] = commit_ref
            if deploy_id:
                payload["deployId"] = deploy_id
            payload["summary"] = summary_text or title
            payload["impactDescription"] = impact_description or description
            payload["stepsToReproduce"] = steps_to_reproduce or description
            mutation = """
            mutation CreateSource($input: CreateSourceCodeVulnerabilityInput!) {
              createSourceCodeVulnerability(input: $input) { issue { id title } }
            }
            """
            data = graphql_request(mutation, {"input": payload})
            issue = ((data.get("createSourceCodeVulnerability") or {}).get("issue") or {})
            success(f"Created SOURCE vulnerability '{title}' (ID {issue.get('id')})")
        elif vtype_up == "DAST":
            required = [method, scheme, url, web_port, request, response]
            if any(x is None for x in required):
                error("DAST requires --method --scheme --url --port --request --response")
                raise typer.Exit(code=1)
            payload = {
                "assetId": asset_id,
                "title": title,
                "description": description,
                "solution": solution,
                "impactLevel": impact_level.strip().upper(),
                "probabilityLevel": probability_level.strip().upper(),
                "severity": severity_up,
                "method": method.strip().upper(),
                "scheme": scheme.strip().upper(),
                "url": url,
                "port": int(web_port),
                "request": request,
                "response": response,
            }
            if parameters is not None:
                payload["parameters"] = parameters
            if reference is not None:
                payload["reference"] = reference
            if status is not None:
                payload["status"] = status.strip().upper()
            if category is not None:
                payload["category"] = category
            if project_id is not None:
                payload["projectId"] = project_id
            if company_id is not None:
                payload["companyId"] = company_id
            # Use the pure create mutation because some backends reject CreateOrUpdate for new DAST findings.
            mutation = """
            mutation CreateDast($input: CreateDastFindingInput!) {
              createDastFinding(input: $input) { issue { id title } }
            }
            """
            data = graphql_request(mutation, {"input": payload})
            issue = ((data.get("createDastFinding") or {}).get("issue") or {})
            success(f"Created DAST vulnerability '{title}' (ID {issue.get('id')})")
        elif vtype_up == "SAST":
            if file_name is None or vulnerable_line is None:
                error("SAST requires --file-name and --vulnerable-line")
                raise typer.Exit(code=1)
            if code_snippet is None:
                error("SAST requires --code-snippet")
                raise typer.Exit(code=1)
            payload = dict(common)
            allowed = {
                "assetId",
                "impactLevel",
                "probabilityLevel",
                "title",
                "description",
                "solution",
                "severity",
                "status",
                "category",
                "projectId",
                "fileName",
                "vulnerableLine",
                "firstLine",
                "codeSnippet",
                "reference",
                "source",
                "sink",
                "commitRef",
                "deployId",
            }
            for extra in ("summary", "impactDescription", "stepsToReproduce", "compromisedEnvironment"):
                payload.pop(extra, None)
            payload["fileName"] = file_name
            payload["vulnerableLine"] = int(vulnerable_line)
            payload["firstLine"] = int(first_line) if first_line is not None else int(vulnerable_line or 1)
            payload["codeSnippet"] = code_snippet
            if source:
                payload["source"] = source
            if sink:
                payload["sink"] = sink
            if commit_ref:
                payload["commitRef"] = commit_ref
            if deploy_id:
                payload["deployId"] = deploy_id
            payload = {k: v for k, v in payload.items() if k in allowed and v is not None}
            mutation = """
            mutation CreateOrUpdateSast($input: CreateOrUpdateSastFindingInput!) {
              createOrUpdateSastFinding(input: $input) { issue { id title } }
            }
            """
            data = graphql_request(mutation, {"input": payload})
            issue = ((data.get("createOrUpdateSastFinding") or {}).get("issue") or {})
            success(f"Created SAST finding '{title}' (ID {issue.get('id')})")
        elif vtype_up == "SCA":
            payload = dict(common)
            # Optional package info
            if category:
                payload["package"] = category
            if parameters:
                payload["affectedVersion"] = parameters
            if reference:
                payload["patchedVersion"] = reference
            mutation = """
            mutation CreateOrUpdateSca($input: CreateOrUpdateScaFindingInput!) {
              createOrUpdateScaFinding(input: $input) { issue { id title } }
            }
            """
            data = graphql_request(mutation, {"input": payload})
            issue = ((data.get("createOrUpdateScaFinding") or {}).get("issue") or {})
            success(f"Created SCA finding '{title}' (ID {issue.get('id')})")
        elif vtype_up == "IAC":
            payload = dict(common)
            if file_name:
                payload["fileName"] = file_name
            if vulnerable_line is not None:
                payload["vulnerableLine"] = int(vulnerable_line)
            payload["firstLine"] = int(first_line) if first_line is not None else int(vulnerable_line or 1)
            if code_snippet:
                payload["codeSnippet"] = code_snippet
            mutation = """
            mutation CreateOrUpdateIac($input: CreateOrUpdateIacFindingInput!) {
              createOrUpdateIacFinding(input: $input) { issue { id title } }
            }
            """
            data = graphql_request(mutation, {"input": payload})
            issue = ((data.get("createOrUpdateIacFinding") or {}).get("issue") or {})
            success(f"Created IAC finding '{title}' (ID {issue.get('id')})")
        elif vtype_up == "CONTAINER":
            payload = dict(common)
            if category:
                payload["package"] = category
            if parameters:
                payload["affectedVersion"] = parameters
            if reference:
                payload["patchedVersion"] = reference
            mutation = """
            mutation CreateOrUpdateContainer($input: CreateOrUpdateContainerFindingInput!) {
              createOrUpdateContainerFinding(input: $input) { issue { id title } }
            }
            """
            data = graphql_request(mutation, {"input": payload})
            issue = ((data.get("createOrUpdateContainerFinding") or {}).get("issue") or {})
            success(f"Created CONTAINER finding '{title}' (ID {issue.get('id')})")
        else:  # SECRET
            payload = dict(common)
            if file_name:
                payload["fileName"] = file_name
            if vulnerable_line is not None:
                payload["vulnerableLine"] = int(vulnerable_line)
            payload["firstLine"] = int(first_line) if first_line is not None else int(vulnerable_line or 1)
            if code_snippet:
                payload["codeSnippet"] = code_snippet
            mutation = """
            mutation CreateOrUpdateSecret($input: CreateOrUpdateSecretFindingInput!) {
              createOrUpdateSecretFinding(input: $input) { issue { id title } }
            }
            """
            data = graphql_request(mutation, {"input": payload})
            issue = ((data.get("createOrUpdateSecretFinding") or {}).get("issue") or {})
            success(f"Created SECRET finding '{title}' (ID {issue.get('id')})")

    except Exception as exc:
        error(f"Error creating vulnerability: {exc}")
        raise typer.Exit(code=1)


# ---------------------- UPDATE COMMAND ---------------------- #
@app.command("update", help="Update a vulnerability by type, including assignees.")
def update_vulnerability(
    issue_id: int = typer.Option(..., "--id", "-i", help="Vulnerability/issue ID to update."),
    vtype: str = typer.Option(..., "--type", "-t", help="Type: WEB|NETWORK|SOURCE|DAST|SAST|SCA|IAC|CONTAINER|SECRET"),
    assignees: Optional[str] = typer.Option(None, "--assignees", "-A", help="Comma-separated assignee emails."),
    asset_id: Optional[int] = typer.Option(None, "--asset-id", "-a", help="Asset ID"),
    title: Optional[str] = typer.Option(None, "--title", help="Title"),
    description: Optional[str] = typer.Option(None, "--description", help="Description"),
    solution: Optional[str] = typer.Option(None, "--solution", help="Solution"),
    impact_level: Optional[str] = typer.Option(None, "--impact-level", help="ImpactLevelCategory"),
    probability_level: Optional[str] = typer.Option(None, "--probability-level", help="ProbabilityLevelCategory"),
    severity: Optional[str] = typer.Option(None, "--severity", help="Severity (NOTIFICATION|LOW|MEDIUM|HIGH|CRITICAL)"),
    summary_text: Optional[str] = typer.Option(None, "--summary", help="Summary"),
    impact_description: Optional[str] = typer.Option(None, "--impact-description", help="Impact description"),
    steps_to_reproduce: Optional[str] = typer.Option(None, "--steps", help="Steps to reproduce"),
    reference: Optional[str] = typer.Option(None, "--reference", help="Reference/CWE/URL"),
    category: Optional[str] = typer.Option(None, "--category", help="Category"),
    project_id: Optional[int] = typer.Option(None, "--project-id", help="Project ID"),
    status: Optional[str] = typer.Option(None, "--status", help="IssueStatusLabel"),
    compromised_env: Optional[bool] = typer.Option(None, "--compromised-env", help="Compromised environment (true/false)"),
    # WEB/DAST
    method: Optional[str] = typer.Option(None, "--method", help="HTTP method (WEB/DAST)"),
    scheme: Optional[str] = typer.Option(None, "--scheme", help="Scheme (WEB/DAST)"),
    url: Optional[str] = typer.Option(None, "--url", help="URL (WEB/DAST)"),
    web_port: Optional[int] = typer.Option(None, "--port", help="Port (WEB/DAST/NETWORK)"),
    request: Optional[str] = typer.Option(None, "--request", help="Request (WEB/DAST)"),
    response: Optional[str] = typer.Option(None, "--response", help="Response (WEB/DAST)"),
    parameters: Optional[str] = typer.Option(None, "--parameters", help="Parameters (WEB/DAST)"),
    # NETWORK
    address: Optional[str] = typer.Option(None, "--address", help="Address/host/IP (NETWORK)"),
    protocol: Optional[str] = typer.Option(None, "--protocol", help="Protocol (NETWORK)"),
    attack_vector: Optional[str] = typer.Option(None, "--attack-vector", help="Attack vector (NETWORK)"),
    # SOURCE
    file_name: Optional[str] = typer.Option(None, "--file-name", help="File name (SOURCE)"),
    vulnerable_line: Optional[int] = typer.Option(None, "--vulnerable-line", help="Vulnerable line (SOURCE)"),
    first_line: Optional[int] = typer.Option(None, "--first-line", help="First line (SOURCE)"),
    code_snippet: Optional[str] = typer.Option(None, "--code-snippet", help="Code snippet (SOURCE)"),
    source: Optional[str] = typer.Option(None, "--source", help="Source (SOURCE)"),
    sink: Optional[str] = typer.Option(None, "--sink", help="Sink (SOURCE)"),
    commit_ref: Optional[str] = typer.Option(None, "--commit-ref", help="Commit ref (SOURCE)"),
    deploy_id: Optional[str] = typer.Option(None, "--deploy-id", help="Deploy ID (SOURCE)"),
):
    vtype_up = vtype.strip().upper()
    supported = {"WEB", "NETWORK", "SOURCE", "DAST", "SAST", "SCA", "IAC", "CONTAINER", "SECRET"}
    if vtype_up not in supported:
        error(f"Unsupported type '{vtype}'. Use one of: {', '.join(sorted(supported))}")
        raise typer.Exit(code=1)

    SEVERITY_ALLOWED = {"NOTIFICATION", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    common = {
        "id": issue_id,
        "assetId": asset_id,
        "title": title,
        "description": description,
        "solution": solution,
        "impactLevel": impact_level.upper() if impact_level else None,
        "probabilityLevel": probability_level.upper() if probability_level else None,
        "severity": severity.upper() if severity else None,
        "summary": summary_text,
        "impactDescription": impact_description,
        "stepsToReproduce": steps_to_reproduce,
        "reference": reference,
        "category": category,
        "projectId": project_id,
        "status": status.upper() if status else None,
        "compromisedEnvironment": compromised_env,
    }
    if common.get("severity") and common["severity"] not in SEVERITY_ALLOWED:
        error(f"Invalid severity '{severity}'. Use {', '.join(SEVERITY_ALLOWED)}")
        raise typer.Exit(code=1)
    common = {k: v for k, v in common.items() if v is not None}

    def clean_web_payload(base):
        for extra in ("fileName", "vulnerableLine", "firstLine", "codeSnippet", "source", "sink", "commitRef", "deployId", "address", "protocol", "attackVector"):
            base.pop(extra, None)
        return base

    def clean_network_payload(base):
        for extra in ("fileName", "vulnerableLine", "firstLine", "codeSnippet", "source", "sink", "commitRef", "deployId", "url", "method", "scheme", "request", "response", "parameters"):
            base.pop(extra, None)
        return base

    def clean_source_payload(base):
        for extra in ("url", "method", "scheme", "request", "response", "parameters", "address", "protocol", "attackVector"):
            base.pop(extra, None)
        return base

    try:
        if assignees:
            assignee_list = [a.strip() for a in assignees.split(",") if a.strip()]
            mutation_assign = """
            mutation UpdateIssueAssignee($input: UpdateIssueAssigneeInput!) {
              updateIssueAssignee(input: $input) { issue { id assignedUsers { email name } } }
            }
            """
            graphql_request(mutation_assign, {"input": {"issueId": issue_id, "assigneeEmails": assignee_list}})

        if vtype_up == "WEB":
            payload = dict(common)
            if method:
                payload["method"] = method.upper()
            if scheme:
                payload["scheme"] = scheme.upper()
            if url:
                payload["url"] = url
            if web_port is not None:
                payload["port"] = int(web_port)
            if request:
                payload["request"] = request
            if response:
                payload["response"] = response
            if parameters:
                payload["parameters"] = parameters
            payload = clean_web_payload(payload)
            mutation = """
            mutation UpdateWeb($input: UpdateWebVulnerabilityInput!) {
              updateWebVulnerability(input: $input) { issue { id title } }
            }
            """
            data = graphql_request(mutation, {"input": payload})
            issue = ((data.get("updateWebVulnerability") or {}).get("issue")) or {}
            success(f"Updated WEB vulnerability {issue.get('id')} - {issue.get('title')}")

        elif vtype_up == "NETWORK":
            payload = dict(common)
            if address:
                payload["address"] = address
            if protocol:
                payload["protocol"] = protocol
            if attack_vector:
                payload["attackVector"] = attack_vector
            if web_port is not None:
                payload["port"] = int(web_port)
            payload = clean_network_payload(payload)
            mutation = """
            mutation UpdateNetwork($input: UpdateNetworkVulnerabilityInput!) {
              updateNetworkVulnerability(input: $input) { issue { id title } }
            }
            """
            data = graphql_request(mutation, {"input": payload})
            issue = ((data.get("updateNetworkVulnerability") or {}).get("issue")) or {}
            success(f"Updated NETWORK vulnerability {issue.get('id')} - {issue.get('title')}")

        elif vtype_up == "SOURCE":
            payload = dict(common)
            if file_name:
                payload["fileName"] = file_name
            if vulnerable_line is not None:
                payload["vulnerableLine"] = int(vulnerable_line)
            payload["firstLine"] = int(first_line) if first_line is not None else int(vulnerable_line or 1)
            if code_snippet:
                payload["codeSnippet"] = code_snippet
            if source:
                payload["source"] = source
            if sink:
                payload["sink"] = sink
            if commit_ref:
                payload["commitRef"] = commit_ref
            if deploy_id:
                payload["deployId"] = deploy_id
            payload = clean_source_payload(payload)
            mutation = """
            mutation UpdateSource($input: UpdateSourceCodeVulnerabilityInput!) {
              updateSourceCodeVulnerability(input: $input) { issue { id title } }
            }
            """
            data = graphql_request(mutation, {"input": payload})
            issue = ((data.get("updateSourceCodeVulnerability") or {}).get("issue")) or {}
            success(f"Updated SOURCE vulnerability {issue.get('id')} - {issue.get('title')}")

        elif vtype_up == "DAST":
            payload = dict(common)
            payload["id"] = issue_id
            if method:
                payload["method"] = method.upper()
            if scheme:
                payload["scheme"] = scheme.upper()
            if url:
                payload["url"] = url
            if web_port is not None:
                payload["port"] = int(web_port)
            if request:
                payload["request"] = request
            if response:
                payload["response"] = response
            if parameters:
                payload["parameters"] = parameters
            mutation = """
            mutation CreateOrUpdateDast($input: CreateOrUpdateDastFindingInput!) {
              createOrUpdateDastFinding(input: $input) { issue { id title } }
            }
            """
            data = graphql_request(mutation, {"input": payload})
            issue = ((data.get("createOrUpdateDastFinding") or {}).get("issue")) or {}
            success(f"Updated DAST vulnerability {issue.get('id')} - {issue.get('title')}")
        elif vtype_up == "SAST":
            if file_name is None and vulnerable_line is None and code_snippet is None:
                error("SAST update: provide at least one of --file-name/--vulnerable-line/--code-snippet.")
                raise typer.Exit(code=1)
            payload = dict(common)
            payload["id"] = issue_id
            allowed = {
                "id",
                "assetId",
                "impactLevel",
                "probabilityLevel",
                "title",
                "description",
                "solution",
                "severity",
                "reference",
                "status",
                "category",
                "projectId",
                "fileName",
                "vulnerableLine",
                "firstLine",
                "codeSnippet",
                "source",
                "sink",
                "commitRef",
                "deployId",
            }
            for extra in ("summary", "impactDescription", "stepsToReproduce", "compromisedEnvironment"):
                payload.pop(extra, None)
            if file_name:
                payload["fileName"] = file_name
            if vulnerable_line is not None:
                payload["vulnerableLine"] = int(vulnerable_line)
            if first_line is not None or vulnerable_line is not None:
                payload["firstLine"] = int(first_line) if first_line is not None else int(vulnerable_line or 1)
            if code_snippet:
                payload["codeSnippet"] = code_snippet
            if source:
                payload["source"] = source
            if sink:
                payload["sink"] = sink
            if commit_ref:
                payload["commitRef"] = commit_ref
            if deploy_id:
                payload["deployId"] = deploy_id
            payload = {k: v for k, v in payload.items() if k in allowed and v is not None}
            mutation = """
            mutation CreateOrUpdateSast($input: CreateOrUpdateSastFindingInput!) {
              createOrUpdateSastFinding(input: $input) { issue { id title } }
            }
            """
            data = graphql_request(mutation, {"input": payload})
            issue = ((data.get("createOrUpdateSastFinding") or {}).get("issue")) or {}
            success(f"Updated SAST finding {issue.get('id')} - {issue.get('title')}")
        elif vtype_up == "SCA":
            payload = dict(common)
            payload["id"] = issue_id
            if category:
                payload["package"] = category
            if parameters:
                payload["affectedVersion"] = parameters
            if reference:
                payload["patchedVersion"] = reference
            mutation = """
            mutation CreateOrUpdateSca($input: CreateOrUpdateScaFindingInput!) {
              createOrUpdateScaFinding(input: $input) { issue { id title } }
            }
            """
            data = graphql_request(mutation, {"input": payload})
            issue = ((data.get("createOrUpdateScaFinding") or {}).get("issue")) or {}
            success(f"Updated SCA finding {issue.get('id')} - {issue.get('title')}")
        elif vtype_up == "IAC":
            payload = dict(common)
            payload["id"] = issue_id
            if file_name:
                payload["fileName"] = file_name
            if vulnerable_line is not None:
                payload["vulnerableLine"] = int(vulnerable_line)
            if first_line is not None:
                payload["firstLine"] = int(first_line)
            if code_snippet:
                payload["codeSnippet"] = code_snippet
            mutation = """
            mutation CreateOrUpdateIac($input: CreateOrUpdateIacFindingInput!) {
              createOrUpdateIacFinding(input: $input) { issue { id title } }
            }
            """
            data = graphql_request(mutation, {"input": payload})
            issue = ((data.get("createOrUpdateIacFinding") or {}).get("issue")) or {}
            success(f"Updated IAC finding {issue.get('id')} - {issue.get('title')}")
        elif vtype_up == "CONTAINER":
            payload = dict(common)
            payload["id"] = issue_id
            if category:
                payload["package"] = category
            if parameters:
                payload["affectedVersion"] = parameters
            if reference:
                payload["patchedVersion"] = reference
            mutation = """
            mutation CreateOrUpdateContainer($input: CreateOrUpdateContainerFindingInput!) {
              createOrUpdateContainerFinding(input: $input) { issue { id title } }
            }
            """
            data = graphql_request(mutation, {"input": payload})
            issue = ((data.get("createOrUpdateContainerFinding") or {}).get("issue")) or {}
            success(f"Updated CONTAINER finding {issue.get('id')} - {issue.get('title')}")
        else:  # SECRET
            payload = dict(common)
            payload["id"] = issue_id
            if file_name:
                payload["fileName"] = file_name
            if vulnerable_line is not None:
                payload["vulnerableLine"] = int(vulnerable_line)
            if first_line is not None:
                payload["firstLine"] = int(first_line)
            if code_snippet:
                payload["codeSnippet"] = code_snippet
            mutation = """
            mutation CreateOrUpdateSecret($input: CreateOrUpdateSecretFindingInput!) {
              createOrUpdateSecretFinding(input: $input) { issue { id title } }
            }
            """
            data = graphql_request(mutation, {"input": payload})
            issue = ((data.get("createOrUpdateSecretFinding") or {}).get("issue")) or {}
            success(f"Updated SECRET finding {issue.get('id')} - {issue.get('title')}")

    except Exception as exc:
        error(f"Error updating vulnerability: {exc}")
        raise typer.Exit(code=1)
