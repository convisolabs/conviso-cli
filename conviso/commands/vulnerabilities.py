# conviso/commands/vulnerabilities.py
"""
Vulnerabilities Command Module
-----------------------------
Lists vulnerabilities (issues) with optional filters (asset IDs, pagination).
"""

import typer
from typing import Optional
from conviso.core.notifier import info, error, summary, success
from conviso.clients.client_graphql import graphql_request
from conviso.core.output_manager import export_data
from conviso.schemas.vulnerabilities_schema import schema

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
    categories: Optional[str] = typer.Option(None, "--categories", help="Comma-separated categories."),
    created_start: Optional[str] = typer.Option(None, "--created-start", help="Created at >= (YYYY-MM-DD)."),
    created_end: Optional[str] = typer.Option(None, "--created-end", help="Created at <= (YYYY-MM-DD)."),
    risk_until_start: Optional[str] = typer.Option(None, "--risk-until-start", help="Risk accepted until >= (YYYY-MM-DD)."),
    risk_until_end: Optional[str] = typer.Option(None, "--risk-until-end", help="Risk accepted until <= (YYYY-MM-DD)."),
    compromised_env: bool = typer.Option(False, "--compromised-env", help="Filter compromised environment = true."),
    data_classification: Optional[str] = typer.Option(None, "--data-classification", help="Comma-separated data classifications (PII,PAYMENT_CARD_INDUSTRY,NON_SENSITIVE,NOT_DEFINED)."),
    business_impact: Optional[str] = typer.Option(None, "--business-impact", help="Comma-separated business impact levels (LOW,MEDIUM,HIGH,NOT_DEFINED)."),
    exploitability: Optional[str] = typer.Option(None, "--attack-surface", "-A", help="Attack surface (INTERNET_FACING,INTERNAL,NOT_DEFINED)."),
    page: int = typer.Option(1, "--page", "-p", help="Page number."),
    per_page: int = typer.Option(50, "--per-page", "-l", help="Items per page."),
    all_pages: bool = typer.Option(False, "--all", help="Fetch all pages."),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table, json, csv."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file for json/csv."),
):
    """List vulnerabilities (issues) for a company, optionally filtered by asset IDs."""
    info(f"Listing vulnerabilities for company {company_id} (page {page}, per_page {per_page})...")

    SEVERITY_ALLOWED = {"NOTIFICATION", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    ATTACK_SURFACE_ALLOWED = {"INTERNET_FACING", "INTERNAL", "NOT_DEFINED"}

    query = """
    query Issues($companyId: ID!, $pagination: PaginationInput!, $filters: IssuesFiltersInput) {
      issues(companyId: $companyId, pagination: $pagination, filters: $filters) {
        collection {
          id
          title
          status
          type
          description
          asset {
            name
            assetsTagList
            company { label }
          }
          author { name }
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
          }
          ... on WebVulnerability {
            severity
            solution
            reference
            impactLevel
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
    categories_list = _split_strs(categories)
    data_class_list = _split_strs(data_classification)
    business_impact_list = _split_strs(business_impact)
    if business_impact_list:
        business_impact_list = [b.upper() for b in business_impact_list]

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
    if categories_list:
        filters["categories"] = categories_list
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

    variables = {
        "companyId": str(company_id),
        "pagination": {"page": page, "perPage": per_page},
        "filters": filters or None,
    }

    try:
        current_page = page
        rows = []
        total_count = 0
        total_pages = None

        while True:
            variables["pagination"]["page"] = current_page
            data = graphql_request(query, variables, log_request=True, verbose_only=all_pages)
            issues = data["issues"]
            collection = issues.get("collection") or []
            metadata = issues.get("metadata") or {}
            total_pages = metadata.get("totalPages")
            total_count = metadata.get("totalCount", total_count)

            if not collection:
                if current_page == page:
                    typer.echo("⚠️  No vulnerabilities found.")
                    raise typer.Exit()
                break

            for vuln in collection:
                asset = vuln.get("asset") or {}
                tags = ", ".join(asset.get("assetsTagList") or [])
                severity_value = vuln.get("severity") or ""
                sev_color_map = {
                    "CRITICAL": "bold white on red",
                    "HIGH": "bold red",
                    "MEDIUM": "yellow",
                    "LOW": "green",
                    "NOTIFICATION": "cyan",
                }
                sev_display = severity_value
                sev_style = sev_color_map.get(severity_value.upper(), None)
                if sev_style:
                    sev_display = f"[{sev_style}]{severity_value}[/{sev_style}]"
                rows.append({
                    "id": vuln.get("id"),
                    "title": vuln.get("title"),
                    "type": vuln.get("type"),
                    "status": vuln.get("status"),
                    "severity": sev_display,
                    "asset": asset.get("name") or "",
                    "tags": tags,
                    "author": (vuln.get("author") or {}).get("name", ""),
                    "company": ((asset.get("company") or {}).get("label")) or "",
                    "attackSurface": vuln.get("exploitability") or "",
                })

            if not all_pages or (total_pages is not None and current_page >= total_pages):
                break
            current_page += 1

        export_data(
            rows,
            schema=schema,
            fmt=fmt,
            output=output,
            title=f"Vulnerabilities (Company {company_id}) - Page {page}/{total_pages or '?'}",
        )
        summary(f"{len(rows)} vulnerability(ies) listed out of {total_count or len(rows)}.")
    except Exception as e:
        error(f"Error listing vulnerabilities: {e}")
        raise typer.Exit(code=1)


# ---------------------- CREATE COMMAND ---------------------- #
@app.command("create")
def create_vulnerability(
    vtype: str = typer.Option(..., "--type", "-t", help="Vuln type: WEB|NETWORK|SOURCE (required)"),
    asset_id: int = typer.Option(..., "--asset-id", "-a", help="Asset ID"),
    title: str = typer.Option(..., "--title", help="Title"),
    description: str = typer.Option(..., "--description", help="Description"),
    solution: str = typer.Option(..., "--solution", help="Solution"),
    impact_level: str = typer.Option(..., "--impact-level", help="ImpactLevelCategory (e.g., HIGH) (required)"),
    probability_level: str = typer.Option(..., "--probability-level", help="ProbabilityLevelCategory (e.g., MEDIUM) (required)"),
    severity: str = typer.Option(..., "--severity", help="Severity (NOTIFICATION|LOW|MEDIUM|HIGH|CRITICAL) (required)"),
    summary_text: str = typer.Option(..., "--summary", help="Summary (required)"),
    impact_description: str = typer.Option(..., "--impact-description", help="Impact description (required)"),
    steps_to_reproduce: str = typer.Option(..., "--steps", help="Steps to reproduce (required)"),
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
    """Create a vulnerability (WEB, NETWORK, SOURCE)."""
    vtype_up = vtype.strip().upper()
    if vtype_up not in {"WEB", "NETWORK", "SOURCE"}:
        error("Invalid --type. Use WEB|NETWORK|SOURCE.")
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
            mutation = """
            mutation CreateNetwork($input: CreateNetworkVulnerabilityInput!) {
              createNetworkVulnerability(input: $input) { issue { id title } }
            }
            """
            data = graphql_request(mutation, {"input": payload})
            issue = ((data.get("createNetworkVulnerability") or {}).get("issue") or {})
            success(f"Created NETWORK vulnerability '{title}' (ID {issue.get('id')})")

        else:  # SOURCE
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
            mutation = """
            mutation CreateSource($input: CreateSourceCodeVulnerabilityInput!) {
              createSourceCodeVulnerability(input: $input) { issue { id title } }
            }
            """
            data = graphql_request(mutation, {"input": payload})
            issue = ((data.get("createSourceCodeVulnerability") or {}).get("issue") or {})
            success(f"Created SOURCE vulnerability '{title}' (ID {issue.get('id')})")

    except Exception as exc:
        error(f"Error creating vulnerability: {exc}")
        raise typer.Exit(code=1)


# ---------------------- UPDATE COMMAND (Not implemented) ---------------------- #
@app.command("update", help="Update vulnerability (not implemented).", hidden=True)
def update_vulnerability():
    error("Update vulnerability via CLI is not implemented. Use bulk or API directly.")
    raise typer.Exit(code=1)
