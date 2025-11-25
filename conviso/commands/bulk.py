# conviso/commands/bulk.py
"""
Bulk import/update/delete commands.
Initial scope: assets (create/update/delete) via CSV.
"""

import typer
from typing import Optional
from rich.table import Table
from conviso.core.notifier import info, success, error, warning
from conviso.core.bulk_loader import load_csv, bulk_process
from conviso.clients.client_graphql import graphql_request
from conviso.core.output_manager import console

app = typer.Typer(help="Bulk import/update/delete via CSV.")


def _parse_int(value: str):
    try:
        return int(value)
    except Exception:
        return value


@app.command("assets")
def bulk_assets(
    company_id: int = typer.Option(None, "--company-id", "-c", help="Company ID."),
    file: str = typer.Option(None, "--file", "-f", help="Path to CSV file."),
    operation: str = typer.Option(None, "--op", "-o", help="Operation: create|update|delete", case_sensitive=False),
    id_column: str = typer.Option("id", "--id-column", help="CSV column name for asset ID (update/delete)."),
    force: bool = typer.Option(False, "--force", help="Apply changes after dry-run without confirmation."),
    preview_only: bool = typer.Option(False, "--preview-only", help="Run dry-run only and exit without applying."),
    show_template: bool = typer.Option(False, "--show-template", help="Display expected CSV columns and examples, then exit."),
):
    """
    Bulk operations for assets using CSV.

    See README bulk section for a table of columns and examples.
    """
    if show_template:
        _show_asset_template()
        raise typer.Exit()
    if file is None or operation is None or company_id is None:
        error("Missing required options. Use --company-id, --file, --op. For column layout, run --show-template.")
        raise typer.Exit(code=1)

    op = operation.lower()
    if op not in {"create", "update", "delete"}:
        error("Invalid --op. Use create|update|delete.")
        raise typer.Exit(code=1)

    rows = load_csv(file)
    if not rows:
        warning("No rows found in CSV.")
        raise typer.Exit()

    info(f"Loaded {len(rows)} row(s) from {file}. Operation={op}.")

    def handle_create(payload, rownum):
        mutation = """
        mutation CreateAsset($input: CreateAssetInput!) {
          createAsset(input: $input) { asset { id name } }
        }
        """
        tags = payload.get("tags")
        if tags:
            payload["assetsTagList"] = [t.strip() for t in tags.split(",") if t.strip()]
        payload["companyId"] = company_id
        payload.pop("tags", None)
        # Normalize enums to upper
        for key in ("businessImpact", "dataClassification", "exploitability"):
            if key in payload and payload[key]:
                if key == "dataClassification":
                    payload[key] = [v.strip().upper() for v in payload[key].split(",") if v.strip()]
                else:
                    payload[key] = payload[key].strip().upper()
        graphql_request(mutation, {"input": payload})

    def handle_update(payload, rownum):
        mutation = """
        mutation UpdateAsset($input: UpdateAssetInput!) {
          updateAsset(input: $input) { asset { id name } }
        }
        """
        if id_column not in payload:
            raise Exception(f"Missing ID column '{id_column}' on row {rownum}")
        payload["id"] = _parse_int(payload[id_column])
        payload["companyId"] = company_id
        payload.pop(id_column, None)
        tags = payload.get("tags")
        if tags:
            payload["assetsTagList"] = [t.strip() for t in tags.split(",") if t.strip()]
        payload.pop("tags", None)
        for key in ("businessImpact", "dataClassification", "exploitability"):
            if key in payload and payload[key]:
                if key == "dataClassification":
                    payload[key] = [v.strip().upper() for v in payload[key].split(",") if v.strip()]
                else:
                    payload[key] = payload[key].strip().upper()
        graphql_request(mutation, {"input": payload})

    def handle_delete(payload, rownum):
        mutation = """
        mutation DeleteAsset($input: DeleteAssetInput!) {
          deleteAsset(input: $input) { asset { collection { id } } }
        }
        """
        if id_column not in payload:
            raise Exception(f"Missing ID column '{id_column}' on row {rownum}")
        asset_id = _parse_int(payload[id_column])
        graphql_request(mutation, {"input": {"companyId": company_id, "id": asset_id}})

    column_map = {
        "id": id_column,  # alias for clarity; used only when present
        "name": "name",
        "businessImpact": "businessImpact",
        "dataClassification": "dataClassification",
        "tags": "tags",
        "attackSurface": "exploitability",
        # threat/environmentCompromised not supported by CreateAssetInput
    }

    handler = {"create": handle_create, "update": handle_update, "delete": handle_delete}[op]
    # Always run dry-run first
    info("Running dry-run (no changes will be applied)...")
    preview = bulk_process(rows, column_map, handler, dry_run=True)
    preview.report()

    if preview_only:
        info("Preview-only mode: no changes applied.")
        raise typer.Exit()

    if not force:
        confirm = typer.confirm("Apply changes now (run without dry-run)?")
        if not confirm:
            info("Aborted. No changes applied.")
            raise typer.Exit()

    info("Applying changes...")
    result = bulk_process(rows, column_map, handler, dry_run=False)
    result.report()


@app.command("requirements")
def bulk_requirements(
    company_id: int = typer.Option(None, "--company-id", "-c", help="Company ID."),
    file: str = typer.Option(None, "--file", "-f", help="Path to CSV file."),
    operation: str = typer.Option(None, "--op", "-o", help="Operation: create|update|delete", case_sensitive=False),
    id_column: str = typer.Option("id", "--id-column", help="CSV column name for requirement ID (update/delete)."),
    force: bool = typer.Option(False, "--force", help="Apply changes after dry-run without confirmation."),
    preview_only: bool = typer.Option(False, "--preview-only", help="Run dry-run only and exit without applying."),
    show_template: bool = typer.Option(False, "--show-template", help="Display expected CSV columns and examples, then exit."),
):
    """
    Bulk operations for requirements using CSV.

    Use --show-template to see expected columns and examples.
    """
    if show_template:
        _show_requirement_template()
        raise typer.Exit()
    if file is None or operation is None or company_id is None:
        error("Missing required options. Use --company-id, --file, --op. For column layout, run --show-template.")
        raise typer.Exit(code=1)

    op = operation.lower()
    if op not in {"create", "update", "delete"}:
        error("Invalid --op. Use create|update|delete.")
        raise typer.Exit(code=1)

    rows = load_csv(file)
    if not rows:
        warning("No rows found in CSV.")
        raise typer.Exit()

    info(f"Loaded {len(rows)} row(s) from {file}. Operation={op}.")

    def _parse_bool(val: str):
        if val is None:
            return None
        return str(val).strip().lower() in {"true", "1", "yes", "y"}

    def _parse_activities(val: str):
        if not val:
            return []
        activities = []
        for raw in val.split(";"):
            raw = raw.strip()
            if not raw:
                continue
            parts = [p.strip() for p in raw.split("|")]
            if len(parts) < 2:
                warning(f"Ignoring activity (expected at least label|description): {raw}")
                continue
            act = {"label": parts[0], "description": parts[1]}
            if len(parts) > 2 and parts[2]:
                try:
                    act["typeId"] = int(parts[2])
                except Exception:
                    warning(f"Ignoring invalid typeId in activity: {parts[2]}")
            if len(parts) > 3 and parts[3]:
                act["reference"] = parts[3]
            if len(parts) > 4 and parts[4]:
                act["item"] = parts[4]
            if len(parts) > 5 and parts[5]:
                act["category"] = parts[5]
            if len(parts) > 6 and parts[6]:
                act["actionPlan"] = parts[6]
            if len(parts) > 7 and parts[7]:
                try:
                    act["vulnerabilityTemplateId"] = int(parts[7])
                except Exception:
                    warning(f"Ignoring invalid vulnerabilityTemplateId in activity: {parts[7]}")
            if len(parts) > 8 and parts[8]:
                act["sort"] = parts[8]
            activities.append(act)
        return activities

    def handle_create(payload, rownum):
        mutation = """
        mutation CreateOrUpdateRequirement($input: RequirementInput!) {
          createOrUpdateRequirement(input: $input) { requirement { id label } }
        }
        """
        payload["companyId"] = company_id
        payload["type"] = "Procedures"
        payload["global"] = _parse_bool(payload.get("global"))
        payload["activities"] = _parse_activities(payload.get("activities"))  # avoid nil
        try:
            graphql_request(mutation, {"input": payload})
        except Exception as exc:
            msg = str(exc)
            if "Label has already been taken" in msg:
                raise Exception(f"Duplicate label '{payload.get('label')}' for company {company_id}")
            raise

    def handle_update(payload, rownum):
        mutation = """
        mutation CreateOrUpdateRequirement($input: RequirementInput!) {
          createOrUpdateRequirement(input: $input) { requirement { id label } }
        }
        """
        if id_column not in payload:
            raise Exception(f"Missing ID column '{id_column}' on row {rownum}")
        payload["id"] = _parse_int(payload[id_column])
        payload["companyId"] = company_id
        payload.pop(id_column, None)
        payload["type"] = "Procedures"
        payload["global"] = _parse_bool(payload.get("global"))
        payload["activities"] = _parse_activities(payload.get("activities"))  # avoid nil
        try:
            graphql_request(mutation, {"input": payload})
        except Exception as exc:
            msg = str(exc)
            if "Label has already been taken" in msg:
                raise Exception(f"Duplicate label '{payload.get('label')}' for company {company_id}")
            raise

    def handle_delete(payload, rownum):
        mutation = """
        mutation DeleteRequirement($input: DeleteRequirementInput!) {
          deleteRequirement(input: $input) { requirement { id } }
        }
        """
        if id_column not in payload:
            raise Exception(f"Missing ID column '{id_column}' on row {rownum}")
        req_id = _parse_int(payload[id_column])
        graphql_request(mutation, {"input": {"requirementId": req_id}})

    column_map = {
        "id": id_column,
        "label": "label",
        "description": "description",
        "global": "global",
        "activities": "activities",
    }

    handler = {"create": handle_create, "update": handle_update, "delete": handle_delete}[op]
    info("Running dry-run (no changes will be applied)...")
    preview = bulk_process(rows, column_map, handler, dry_run=True)
    preview.report()

    if preview_only:
        info("Preview-only mode: no changes applied.")
        raise typer.Exit()

    if not force:
        confirm = typer.confirm("Apply changes now (run without dry-run)?")
        if not confirm:
            info("Aborted. No changes applied.")
            raise typer.Exit()

    info("Applying changes...")
    result = bulk_process(rows, column_map, handler, dry_run=False)
    result.report()


@app.command("vulns")
def bulk_vulns(
    company_id: int = typer.Option(None, "--company-id", "-c", help="Company ID."),
    file: str = typer.Option(None, "--file", "-f", help="Path to CSV file."),
    operation: str = typer.Option(None, "--op", "-o", help="Operation: create (WEB|NETWORK|SOURCE)", case_sensitive=False),
    force: bool = typer.Option(False, "--force", help="Apply changes after dry-run without confirmation."),
    preview_only: bool = typer.Option(False, "--preview-only", help="Run dry-run only and exit without applying."),
    show_template: bool = typer.Option(False, "--show-template", help="Display expected CSV columns and examples, then exit."),
):
    """
    Bulk create vulnerabilities (WEB, NETWORK, SOURCE) using CSV.
    Always runs dry-run first; requires --force or confirmation to apply.
    """
    if show_template:
        _show_vuln_template()
        raise typer.Exit()
    if file is None or operation is None or company_id is None:
        error("Missing required options. Use --company-id, --file, --op. For columns, run --show-template.")
        raise typer.Exit(code=1)

    op = operation.lower()
    if op != "create":
        error("Only create is supported for bulk vulns.")
        raise typer.Exit(code=1)

    rows = load_csv(file)
    if not rows:
        warning("No rows found in CSV.")
        raise typer.Exit()

    info(f"Loaded {len(rows)} row(s) from {file}. Operation={op}.")

    SEVERITY_ALLOWED = {"NOTIFICATION", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def _require_fields(payload: dict, fields: list, rownum: int):
        missing = [f for f in fields if not payload.get(f)]
        if missing:
            raise Exception(f"Missing required field(s) {missing} on row {rownum}")

    def _common_fields(payload: dict, rownum: int):
        _require_fields(payload, ["assetId", "title", "description", "solution", "impactLevel", "probabilityLevel", "severity", "summary", "impactDescription", "stepsToReproduce"], rownum)
        sev = str(payload.get("severity", "")).upper()
        if sev not in SEVERITY_ALLOWED:
            raise Exception(f"Invalid severity '{payload.get('severity')}' on row {rownum}")
        payload["severity"] = sev
        for k in ("impactLevel", "probabilityLevel"):
            if payload.get(k):
                payload[k] = str(payload[k]).upper()
        if payload.get("status"):
            payload["status"] = str(payload["status"]).upper()
        if payload.get("compromisedEnvironment") is not None:
            payload["compromisedEnvironment"] = str(payload["compromisedEnvironment"]).lower() in {"true","1","yes","y"}
        # ints
        for k in ("assetId", "projectId"):
            if payload.get(k) not in (None, ""):
                try:
                    payload[k] = int(payload[k])
                except Exception:
                    raise Exception(f"Invalid integer for {k} on row {rownum}")

    def handle_create(payload, rownum):
        vtype = str(payload.get("type", "")).upper()
        if vtype not in {"WEB", "NETWORK", "SOURCE"}:
            raise Exception(f"Invalid type '{payload.get('type')}' (expected WEB|NETWORK|SOURCE)")
        payload.pop("type", None)
        _common_fields(payload, rownum)

        if vtype == "WEB":
            _require_fields(payload, ["method", "scheme", "url", "port", "request", "response"], rownum)
            for k in ("port",):
                try:
                    payload[k] = int(payload[k])
                except Exception:
                    raise Exception(f"Invalid integer for {k} on row {rownum}")
            mutation = """
            mutation CreateWeb($input: CreateWebVulnerabilityInput!) {
              createWebVulnerability(input: $input) { issue { id title } }
            }
            """
            try:
                graphql_request(mutation, {"input": payload})
            except Exception as exc:
                msg = str(exc)
                if "Record not found" in msg:
                    raise Exception(f"Row {rownum} (WEB): assetId/projectId not found or invalid scope")
                raise Exception(f"Row {rownum} (WEB): {exc}")

        elif vtype == "NETWORK":
            _require_fields(payload, ["address", "protocol", "port", "attackVector"], rownum)
            for k in ("port",):
                try:
                    payload[k] = int(payload[k])
                except Exception:
                    raise Exception(f"Invalid integer for {k} on row {rownum}")
            mutation = """
            mutation CreateNetwork($input: CreateNetworkVulnerabilityInput!) {
              createNetworkVulnerability(input: $input) { issue { id title } }
            }
            """
            try:
                graphql_request(mutation, {"input": payload})
            except Exception as exc:
                msg = str(exc)
                if "Record not found" in msg:
                    raise Exception(f"Row {rownum} (NETWORK): assetId/projectId not found or invalid scope")
                raise Exception(f"Row {rownum} (NETWORK): {exc}")

        elif vtype == "SOURCE":
            _require_fields(payload, ["fileName", "vulnerableLine", "firstLine", "codeSnippet"], rownum)
            for k in ("vulnerableLine", "firstLine"):
                try:
                    payload[k] = int(payload[k])
                except Exception:
                    raise Exception(f"Invalid integer for {k} on row {rownum}")
            mutation = """
            mutation CreateSource($input: CreateSourceCodeVulnerabilityInput!) {
              createSourceCodeVulnerability(input: $input) { issue { id title } }
            }
            """
            try:
                graphql_request(mutation, {"input": payload})
            except Exception as exc:
                msg = str(exc)
                if "Record not found" in msg:
                    raise Exception(f"Row {rownum} (SOURCE): assetId/projectId not found or invalid scope")
                raise Exception(f"Row {rownum} (SOURCE): {exc}")

    column_map = {
        "type": "type",
        "assetId": "assetId",
        "title": "title",
        "description": "description",
        "reference": "reference",
        "category": "category",
        "solution": "solution",
        "impactLevel": "impactLevel",
        "probabilityLevel": "probabilityLevel",
        "severity": "severity",
        "summary": "summary",
        "impactDescription": "impactDescription",
        "stepsToReproduce": "stepsToReproduce",
        "compromisedEnvironment": "compromisedEnvironment",
        "projectId": "projectId",
        "status": "status",
        # WEB
        "method": "method",
        "scheme": "scheme",
        "url": "url",
        "port": "port",
        "request": "request",
        "response": "response",
        "parameters": "parameters",
        # NETWORK
        "address": "address",
        "protocol": "protocol",
        "attackVector": "attackVector",
        # SOURCE
        "fileName": "fileName",
        "vulnerableLine": "vulnerableLine",
        "firstLine": "firstLine",
        "codeSnippet": "codeSnippet",
        "source": "source",
        "sink": "sink",
        "commitRef": "commitRef",
        "deployId": "deployId",
    }

    handler = {"create": handle_create}[op]
    info("Running dry-run (no changes will be applied)...")
    preview = bulk_process(rows, column_map, handler, dry_run=True)
    preview.report()

    if preview_only:
        info("Preview-only mode: no changes applied.")
        raise typer.Exit()

    if not force:
        confirm = typer.confirm("Apply changes now (run without dry-run)?")
        if not confirm:
            info("Aborted. No changes applied.")
            raise typer.Exit()

    info("Applying changes...")
    result = bulk_process(rows, column_map, handler, dry_run=False)
    result.report()


def _show_asset_template():
    table = Table(title="Assets CSV Columns", header_style="bold cyan")
    table.add_column("Column", style="bold")
    table.add_column("Required", style="yellow")
    table.add_column("Values / Format", style="green")
    table.add_column("Example", style="cyan")

    table.add_row("id", "update/delete", "Integer ID (use --id-column to change header)", "123")
    table.add_row("name", "create/update", "Text", "Asset A")
    table.add_row("businessImpact", "optional", "LOW | MEDIUM | HIGH | NOT_DEFINED", "HIGH")
    table.add_row(
        "dataClassification",
        "optional",
        "PII | PAYMENT_CARD_INDUSTRY | NON_SENSITIVE | NOT_DEFINED (comma-separated allowed)",
        "NON_SENSITIVE",
    )
    table.add_row("tags", "optional", "Comma-separated", "tag1,tag2")
    table.add_row("attackSurface", "optional", "INTERNET_FACING | INTERNAL | NOT_DEFINED", "INTERNET_FACING")
    table.add_row("threat", "optional", "CRITICAL | HIGH | MEDIUM | LOW | NOTIFICATION", "HIGH")
    table.add_row("environmentCompromised", "optional", "true/false", "false")

    console.print(table)
    console.print("\nExample create CSV:\n")
    console.print("name,businessImpact,dataClassification,tags,attackSurface")
    console.print("Asset A,HIGH,NON_SENSITIVE,\"tag1,tag2\",INTERNET_FACING\n")

    console.print("Example update CSV:\n")
    console.print("id,name,businessImpact")
    console.print("123,Asset A Updated,MEDIUM")


def _show_requirement_template():
    table = Table(title="Requirements CSV Columns", header_style="bold cyan")
    table.add_column("Column", style="bold")
    table.add_column("Required", style="yellow")
    table.add_column("Values / Format", style="green")
    table.add_column("Example", style="cyan")

    table.add_row("id", "update/delete", "Integer ID (use --id-column to change header)", "123")
    table.add_row("label", "create/update", "Text", "Req A")
    table.add_row("description", "create/update", "Text", "Do X")
    table.add_row("global", "optional", "true/false", "true")
    table.add_row(
        "activities",
        "optional",
        "Semicolon-separated activities; each activity uses pipe-separated fields: label|description|typeId|reference|item|category|actionPlan|templateId|sort",
        "Login|Check login|1|REF||Category||123|1;Logout|Check logout|1",
    )

    console.print(table)
    console.print("\nExample create CSV:\n")
    console.print("label,description,global,activities")
    console.print("Req A,Do X,true,\"Login|Check login|1|REF||Category||123|1\"\n")

    console.print("Example update CSV:\n")
    console.print("id,label,description")
    console.print("123,Req A Updated,Do Y")


def _show_vuln_template():
    table = Table(title="Vulnerabilities CSV Columns (type = WEB|NETWORK|SOURCE)", header_style="bold cyan")
    table.add_column("Column", style="bold")
    table.add_column("Required", style="yellow")
    table.add_column("Values / Format", style="green")
    table.add_column("Example", style="cyan")

    # Common
    table.add_row("type", "create", "WEB | NETWORK | SOURCE", "WEB")
    table.add_row("assetId", "create", "Int", "12345")
    table.add_row("title", "create", "Text", "XSS reflected")
    table.add_row("description", "create", "Text", "Description here")
    table.add_row("solution", "create", "Text", "Fix input validation")
    table.add_row("impactLevel", "create", "ImpactLevelCategory", "HIGH")
    table.add_row("probabilityLevel", "create", "ProbabilityLevelCategory", "MEDIUM")
    table.add_row("severity", "create", "NOTIFICATION|LOW|MEDIUM|HIGH|CRITICAL", "HIGH")
    table.add_row("summary", "create", "Text", "Short summary")
    table.add_row("impactDescription", "create", "Text", "Impact description")
    table.add_row("stepsToReproduce", "create", "Text", "Steps...")
    table.add_row("reference", "optional", "Text/URL", "CWE-79")
    table.add_row("category", "optional", "Text", "Injection")
    table.add_row("projectId", "optional", "Int", "443")
    table.add_row("status", "optional", "IssueStatusLabel", "ANALYSIS")
    table.add_row("compromisedEnvironment", "optional", "true/false", "false")

    # WEB
    table.add_row("method", "WEB", "HTTPMethod (GET|POST|...)", "GET")
    table.add_row("scheme", "WEB", "SchemeCategory (HTTP|HTTPS)", "HTTPS")
    table.add_row("url", "WEB", "String", "https://app/login")
    table.add_row("port", "WEB", "Int", "443")
    table.add_row("request", "WEB", "String", "GET /login")
    table.add_row("response", "WEB", "String", "HTTP/1.1 200 OK")
    table.add_row("parameters", "WEB optional", "String", "user=1")

    # NETWORK
    table.add_row("address", "NETWORK", "String (host/IP)", "10.0.0.1")
    table.add_row("protocol", "NETWORK", "String", "tcp")
    table.add_row("port", "NETWORK", "Int", "22")
    table.add_row("attackVector", "NETWORK", "String", "ssh brute force")

    # SOURCE
    table.add_row("fileName", "SOURCE", "String", "app/controllers/user.rb")
    table.add_row("vulnerableLine", "SOURCE", "Int", "42")
    table.add_row("firstLine", "SOURCE", "Int", "40")
    table.add_row("codeSnippet", "SOURCE", "String", "user_input = params[:user]")
    table.add_row("source", "SOURCE optional", "String", "")
    table.add_row("sink", "SOURCE optional", "String", "")
    table.add_row("commitRef", "SOURCE optional", "String", "")
    table.add_row("deployId", "SOURCE optional", "String", "")

    console.print(table)
    console.print("\nExample create CSV (WEB):\n")
    console.print("type,assetId,title,description,solution,impactLevel,probabilityLevel,severity,summary,impactDescription,stepsToReproduce,method,scheme,url,port,request,response")
    console.print("WEB,12345,XSS,\"desc\",\"fix\",HIGH,MEDIUM,HIGH,\"summary\",\"impact\",\"steps\",GET,HTTPS,https://app/login,443,\"GET /login\",\"HTTP/1.1 200\"")
