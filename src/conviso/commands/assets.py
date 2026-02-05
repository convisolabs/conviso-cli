# conviso/commands/assets.py
"""
Assets Command Module
---------------------
Manages asset CRUD operations via Conviso GraphQL API.
Now standardized with core/output_manager for unified output formats.
"""

import typer
from typing import Optional
from conviso.core.notifier import info, success, error, summary, warning
from conviso.clients.client_graphql import graphql_request
from conviso.schemas.assets_schema import schema
from conviso.core.output_manager import export_data

app = typer.Typer(help="Manage company assets via Conviso GraphQL API.")


# ---------------------- LIST COMMAND ---------------------- #
@app.command("list")
def list_assets(
    company_id: str = typer.Option(..., "--company-id", "-c", help="Company ID."),
    limit: int = typer.Option(10, "--limit", "-l", help="Number of assets per page."),
    page: int = typer.Option(1, "--page", "-p", help="Page number."),
    tags: Optional[str] = typer.Option(None, "--tags", "-t", help="Comma-separated asset tags filter."),
    business_impact: Optional[str] = typer.Option(None, "--business-impact", help="Comma-separated business impact levels (LOW,MEDIUM,HIGH,NOT_DEFINED)."),
    data_classification: Optional[str] = typer.Option(None, "--data-classification", help="Comma-separated data classifications (PII,PAYMENT_CARD_INDUSTRY,NON_SENSITIVE,NOT_DEFINED)."),
    attack_surface: Optional[str] = typer.Option(None, "--attack-surface", "-A", help="Comma-separated attack surfaces (INTERNET_FACING,INTERNAL,NOT_DEFINED)."),
    threat: Optional[str] = typer.Option(None, "--threat", help="Comma-separated threat levels (CRITICAL,HIGH,MEDIUM,LOW,NOTIFICATION)."),
    env_compromised: bool = typer.Option(False, "--compromised-env", help="Filter environmentCompromised=true."),
    all_pages: bool = typer.Option(False, "--all", help="Fetch all pages."),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table, json, csv."),
    output: str = typer.Option(None, "--output", "-o", help="Output file path (for JSON or CSV export)."),
):
    """List all assets for a specific company."""
    info(f"Listing assets for company {company_id} (page {page}, limit {limit})...")

    query = """
    query Assets($companyId: ID!, $limit: Int, $page: Int, $search: AssetsSearch) {
      assets(companyId: $companyId, limit: $limit, page: $page, search: $search) {
        collection {
          id
          name
          businessImpact
          dataClassification
          exploitability
          threat
          environmentCompromised
          updatedAt
          assetsTagList
          integrations
          pendingVulnerabilitiesStats { count value }
          riskScore { current { value } }
        }
        metadata {
          totalPages
          totalCount
        }
      }
    }
    """

    BUSINESS_IMPACT_ALLOWED = {"LOW", "MEDIUM", "HIGH", "NOT_DEFINED"}
    ATTACK_SURFACE_ALLOWED = {"INTERNET_FACING", "INTERNAL", "NOT_DEFINED"}

    def _split_list(value: Optional[str], upper: bool = False, allowed: Optional[set] = None, label: str = ""):
        if not value:
            return None
        items = []
        for raw in value.split(","):
            v = raw.strip()
            if not v:
                continue
            v = v.upper() if upper else v
            if allowed and v not in allowed:
                warning(f"Ignoring invalid {label or 'value'}: {v}")
                continue
            items.append(v)
        return items or None

    search_filters = {
        "tags": _split_list(tags),
        "businessImpact": _split_list(business_impact, upper=True, allowed=BUSINESS_IMPACT_ALLOWED, label="business impact"),
        "dataClassification": _split_list(data_classification),
        "exploitability": _split_list(attack_surface, upper=True, allowed=ATTACK_SURFACE_ALLOWED, label="attack surface"),
        "threat": _split_list(threat, upper=True),
    }
    if env_compromised:
        search_filters["environmentCompromised"] = True
    search_filters = {k: v for k, v in search_filters.items() if v is not None}

    try:
        current_page = page
        rows = []
        total_count = 0
        total_pages = None
        while True:
            variables = {"companyId": str(company_id), "limit": limit, "page": current_page}
            if search_filters:
                variables["search"] = search_filters
            data = graphql_request(query, variables, log_request=True, verbose_only=all_pages)
            assets_data = data["assets"]
            collection = assets_data["collection"]
            metadata = assets_data["metadata"]
            total_pages = metadata.get("totalPages")
            total_count = metadata.get("totalCount", total_count)

            if not collection:
                if current_page == page:
                    typer.echo("⚠️  No assets found.")
                    raise typer.Exit()
                break

            for a in collection:
                # Flatten nested and list-based fields
                risk_value = ((a.get("riskScore") or {}).get("current") or {}).get("value", "-")

                # Pending vulnerabilities by severity
                pending_total = 0
                stats = a.get("pendingVulnerabilitiesStats") or []
                stats_iter = stats if isinstance(stats, list) else [stats] if isinstance(stats, dict) else []
                for s in stats_iter:
                    if not isinstance(s, dict):
                        continue
                    count = s.get("count", 0) or 0
                    severity = str(s.get("value", "")).upper()
                    pending_total += count

                # Flatten arrays into comma-separated strings
                tags = ", ".join(a.get("assetsTagList") or [])
                data_classification = ", ".join(a.get("dataClassification") or [])

                impact = a.get("businessImpact") or ""
                impact_color = {
                    "HIGH": "bold white on red",
                    "MEDIUM": "yellow",
                    "LOW": "green",
                    "NOT_DEFINED": "dim",
                }.get(str(impact).upper())
                impact_display = f"[{impact_color}]{impact}[/{impact_color}]" if impact_color else impact

                rows.append({
                    "id": a.get("id") or "",
                    "name": a.get("name") or "",
                    "riskScore.current.value": str(risk_value),
                    "openVulnerabilities": str(pending_total),
                    "businessImpact": impact_display,
                    "dataClassification": data_classification,
                    "exploitability": a.get("exploitability") or "",
                    "environmentCompromised": str(a.get("environmentCompromised")),
                    "assetsTagList": tags,
                    "integrations": ", ".join(a.get("integrations") or []),
                    "updatedAt": a.get("updatedAt") or "",
                })

            if not all_pages or (total_pages is not None and current_page >= total_pages):
                break
            current_page += 1

        export_data(
            rows,
            schema=schema,
            fmt=fmt,
            output=output,
            title=f"Assets (Company {company_id}) - Page {page}/{total_pages or '?'}",
        )

        summary(f"{len(rows)} asset(s) listed out of {total_count or len(rows)} total.\n")

    except Exception as e:
        error(f"Error listing assets: {e}")
        raise typer.Exit(code=1)


# ---------------------- CREATE COMMAND ---------------------- #
@app.command("create")
def create_asset(
    company_id: str = typer.Option(..., "--company-id", "-c", help="Company ID."),
    name: str = typer.Option(..., "--name", "-n", help="Asset name."),
    business_impact: str = typer.Option(None, "--business-impact", help="Business impact (LOW|MEDIUM|HIGH|NOT_DEFINED)."),
    data_classification: str = typer.Option(None, "--data-classification", help="Data classification (PII|PAYMENT_CARD_INDUSTRY|NON_SENSITIVE|NOT_DEFINED)."),
    integrations: str = typer.Option(None, "--integrations", help="Comma-separated integrations."),
    environment_compromised: bool = typer.Option(False, "--environment-compromised", help="Environment compromised."),
    tags: str = typer.Option(None, "--tags", help="Comma-separated list of tags."),
):
    """Create a new asset in a given company."""
    info(f"Creating new asset '{name}' for company {company_id}...")

    BUSINESS_IMPACT_ALLOWED = {"LOW", "MEDIUM", "HIGH", "NOT_DEFINED"}
    DATA_CLASS_ALLOWED = {"PERSONALLY_IDENTIFIABLE_INFORMATION", "PAYMENT_CARD_INDUSTRY", "NON_SENSITIVE", "NOT_DEFINED"}

    def _parse_business(value: Optional[str]):
        if not value:
            return None
        up = value.strip().upper()
        if up not in BUSINESS_IMPACT_ALLOWED:
            warning(f"Ignoring invalid business impact: {value}")
            return None
        return up

    def _parse_data_class(value: Optional[str]):
        if not value:
            return None
        vals = []
        for raw in value.split(","):
            v = raw.strip().upper()
            if not v:
                continue
            if v not in DATA_CLASS_ALLOWED:
                warning(f"Ignoring invalid data classification: {raw}")
                continue
            vals.append(v)
        return vals or None

    parsed_business = _parse_business(business_impact)
    parsed_data_class = _parse_data_class(data_classification)

    mutation = """
    mutation CreateAsset($input: CreateAssetInput!) {
      createAsset(input: $input) {
        asset {
          id
          name
          businessImpact
          dataClassification
          environmentCompromised
          assetsTagList
          updatedAt
        }
      }
    }
    """

    input_data = {
        "companyId": int(company_id),
        "name": name,
        "businessImpact": parsed_business,
        "dataClassification": parsed_data_class,
        "assetsTagList": tags.split(",") if tags else None,
        "integrations": integrations.split(",") if integrations else None,
        "environmentCompromised": environment_compromised or None,
    }

    try:
        data = graphql_request(mutation, {"input": {k: v for k, v in input_data.items() if v is not None}})
        asset = data["createAsset"]["asset"]
        success(f"Asset created successfully: ID {asset['id']} - {asset['name']}")
    except Exception as e:
        error(f"Error creating asset: {e}")
        raise typer.Exit(code=1)


# ---------------------- UPDATE COMMAND ---------------------- #
@app.command("update")
def update_asset(
    asset_id: int = typer.Option(..., "--id", "-i", help="Asset ID to update."),
    company_id: str = typer.Option(..., "--company-id", "-c", help="Company ID."),
    name: str = typer.Option(None, "--name", "-n", help="New asset name."),
    business_impact: str = typer.Option(None, "--business-impact", help="Business impact (LOW|MEDIUM|HIGH|NOT_DEFINED)."),
    data_classification: str = typer.Option(None, "--data-classification", help="Data classification (PII|PAYMENT_CARD_INDUSTRY|NON_SENSITIVE|NOT_DEFINED)."),
    integrations: str = typer.Option(None, "--integrations", help="Comma-separated integrations."),
    environment_compromised: bool = typer.Option(None, "--environment-compromised", help="Environment compromised."),
    tags: str = typer.Option(None, "--tags"),
):
    """Update an existing asset."""
    info(f"Updating asset ID {asset_id} in company {company_id}...")

    BUSINESS_IMPACT_ALLOWED = {"LOW", "MEDIUM", "HIGH", "NOT_DEFINED"}
    DATA_CLASS_ALLOWED = {"PERSONALLY_IDENTIFIABLE_INFORMATION", "PAYMENT_CARD_INDUSTRY", "NON_SENSITIVE", "NOT_DEFINED"}

    def _parse_business(value: Optional[str]):
        if value is None:
            return None
        up = value.strip().upper()
        if up not in BUSINESS_IMPACT_ALLOWED:
            warning(f"Ignoring invalid business impact: {value}")
            return None
        return up

    def _parse_data_class(value: Optional[str]):
        if value is None:
            return None
        vals = []
        for raw in value.split(","):
            v = raw.strip().upper()
            if not v:
                continue
            if v not in DATA_CLASS_ALLOWED:
                warning(f"Ignoring invalid data classification: {raw}")
                continue
            vals.append(v)
        return vals or None

    parsed_business = _parse_business(business_impact)
    parsed_data_class = _parse_data_class(data_classification)

    mutation = """
    mutation UpdateAsset($input: UpdateAssetInput!) {
      updateAsset(input: $input) {
        asset {
          id
          name
          businessImpact
          dataClassification
          environmentCompromised
          assetsTagList
          updatedAt
        }
      }
    }
    """

    input_data = {
        "id": asset_id,
        "companyId": int(company_id),
        "name": name,
        "businessImpact": parsed_business,
        "dataClassification": parsed_data_class,
        "assetsTagList": tags.split(",") if tags else None,
        "integrations": integrations.split(",") if integrations else None,
        "environmentCompromised": environment_compromised,
    }

    try:
        data = graphql_request(mutation, {"input": {k: v for k, v in input_data.items() if v is not None}})
        asset = data["updateAsset"]["asset"]
        success(f"Asset updated successfully: ID {asset['id']} - {asset['name']}")
    except Exception as e:
        msg = str(e)
        if "Record not found" in msg:
            error(f"Asset {asset_id} not found for company {company_id}.")
        else:
            error(f"Error updating asset: {e}")
        raise typer.Exit(code=1)


# ---------------------- DELETE COMMAND ---------------------- #
@app.command("delete")
def delete_assets(
    company_id: int = typer.Option(..., "--company-id", "-c", help="Company ID."),
    ids: str = typer.Option(..., "--ids", "-i", "-ids", help="Comma-separated list of asset IDs."),
    force: bool = typer.Option(False, "--force", help="Skip confirmation prompt."),
):
    """Delete one or more assets by ID."""
    asset_ids = [int(x.strip()) for x in ids.split(",") if x.strip()]
    info(f"Deleting {len(asset_ids)} asset(s) from company {company_id}...")

    if not force:
        confirm = typer.confirm(f"Are you sure you want to delete {len(asset_ids)} asset(s)?")
        if not confirm:
            info("Aborted.")
            raise typer.Exit()

    mutation = """
    mutation DeleteAsset($input: DeleteAssetInput!) {
      deleteAsset(input: $input) {
        asset {
          collection {
            id
            name
          }
        }
      }
    }
    """

    success_count = 0
    errors = []

    # Pre-check assets belong to the company to avoid deleting from another scope
    precheck_query = """
    query Asset($id: ID!) {
      asset(id: $id) {
        id
        name
        company { id label }
      }
    }
    """

    for asset_id in asset_ids:
        input_data = {"companyId": company_id, "id": asset_id}
        try:
            # Fetch asset to confirm company
            asset_data = graphql_request(precheck_query, {"id": asset_id}, log_request=False)
            asset_info = (asset_data.get("asset") or {})
            if not asset_info:
                warning(f"Skipping asset {asset_id}: not found.")
                errors.append(asset_id)
                continue
            asset_company = ((asset_info.get("company") or {}).get("id"))
            if asset_company and str(asset_company) != str(company_id):
                warning(f"Skipping asset {asset_id}: belongs to company {asset_company}, not {company_id}.")
                errors.append(asset_id)
                continue

            data = graphql_request(mutation, {"input": input_data})
            assets = data["deleteAsset"]["asset"]["collection"]
            if assets:
                deleted = assets[0]
                success(f"Deleted asset ID {deleted['id']} - {deleted.get('name', '-')}")
                success_count += 1
            else:
                info(f"⚠️ Asset {asset_id} deleted but no details returned.")
        except Exception as e:
            msg = str(e)
            if "Record not found" in msg:
                warning(f"Asset {asset_id} not found or already deleted.")
            else:
                error(f"Error deleting asset {asset_id}: {e}")
            errors.append(asset_id)

    summary(f"Summary: {success_count} deleted, {len(errors)} failed.")
    if errors:
        error(f"Failed asset IDs: {', '.join(map(str, errors))}")
        raise typer.Exit(code=1)
