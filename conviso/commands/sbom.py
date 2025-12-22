# conviso/commands/sbom.py
"""
SBOM Command Module
-------------------
List and import SBOM components.
"""

import typer
from typing import Optional
from conviso.core.notifier import info, error, summary, success
from conviso.clients.client_graphql import graphql_request, graphql_request_upload
from conviso.core.output_manager import export_data
from conviso.schemas.sbom_schema import schema as sbom_schema
import requests
import json
import uuid

app = typer.Typer(help="List and import SBOM components.")


@app.command("list")
def list_sbom(
    company_id: int = typer.Option(..., "--company-id", "-c", help="Company ID."),
    name: Optional[str] = typer.Option(None, "--name", help="Filter by component name (contains)."),
    vulnerable_only: bool = typer.Option(False, "--vulnerable-only", help="Return only components with vulnerabilities."),
    asset_ids: Optional[str] = typer.Option(None, "--asset-ids", help="Comma-separated asset IDs to filter."),
    tags: Optional[str] = typer.Option(None, "--tags", help="Comma-separated tags."),
    sort_by: Optional[str] = typer.Option(None, "--sort-by", help="Sort field (as supported by API)."),
    order: Optional[str] = typer.Option(None, "--order", help="Sort order ASC|DESC."),
    page: int = typer.Option(1, "--page", "-p", help="Page number."),
    per_page: int = typer.Option(50, "--per-page", "-l", help="Items per page."),
    all_pages: bool = typer.Option(False, "--all", help="Fetch all pages."),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table|csv|json|cyclonedx"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file for csv/json."),
):
    """
    List SBOM components for a company.
    """
    query = """
    query SbomComponents($companyId: ID!, $search: SbomComponentSearchInput, $page: Int, $limit: Int) {
      sbomComponents(companyId: $companyId, search: $search, page: $page, limit: $limit) {
        collection {
          id
          name
          asset { id name }
          technology
          license
          packageManager
          version
          issuesBySeverity
        }
        metadata { currentPage limitValue totalCount totalPages }
      }
    }
    """
    search = {}
    if name:
        search["name"] = name
    if vulnerable_only:
        search["vulnerableOnly"] = True
    if asset_ids:
        try:
            search["assetIds"] = [int(x.strip()) for x in asset_ids.split(",") if x.strip()]
        except Exception:
            error("Invalid --asset-ids; provide comma-separated integers.")
            raise typer.Exit(code=1)
    if tags:
        search["tags"] = [t.strip() for t in tags.split(",") if t.strip()]
    if sort_by:
        search["sortBy"] = sort_by
    if order:
        search["order"] = order

    variables = {
        "companyId": str(company_id),
        "search": search or None,
        "page": page,
        "limit": per_page,
    }

    try:
        def _format_issues_by_severity(issues_val):
            # Accept dict or JSON-like string
            import json
            if isinstance(issues_val, str):
                try:
                    issues_val = json.loads(issues_val)
                except Exception:
                    pass
            if isinstance(issues_val, dict):
                order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NOTIFICATION"]
                parts = []
                # Normalize keys to upper
                normalized = {}
                for k, v in issues_val.items():
                    key_up = str(k).upper()
                    # If nested dict with count, extract
                    if isinstance(v, dict) and "count" in v:
                        normalized[key_up] = v.get("count")
                    else:
                        normalized[key_up] = v
                for sev in order:
                    if sev in normalized:
                        try:
                            val = int(normalized.get(sev))
                        except Exception:
                            val = normalized.get(sev)
                        # show only severities with count > 0 to keep compact; show zeros if all zero
                        if val not in (None, "", 0):
                            parts.append(f"{sev}:{val}")
                if not parts and normalized:
                    # If all zeros, show explicit zeros
                    for sev in order:
                        if sev in normalized:
                            parts.append(f"{sev}:{normalized.get(sev)}")
                # include any unexpected keys
                for k, v in normalized.items():
                    if k not in order:
                        parts.append(f"{k}:{v}")
                return ", ".join(parts) if parts else "-"
            return str(issues_val) if issues_val not in (None, "", {}) else "-"

        fetch_all = all_pages
        current_page = page
        rows = []
        total_count = 0
        total_pages = None

        while True:
            variables["page"] = current_page
            data = graphql_request(query, variables, log_request=True, verbose_only=True)
            sbom = data["sbomComponents"]
            collection = sbom.get("collection") or []
            metadata = sbom.get("metadata") or {}
            total_pages = metadata.get("totalPages")
            total_count = metadata.get("totalCount", total_count)

            if not collection:
                if current_page == page:
                    typer.echo("⚠️  No SBOM components found.")
                    raise typer.Exit()
                break

            for comp in collection:
                issues = comp.get("issuesBySeverity") or {}
                issues_str = _format_issues_by_severity(issues)
                asset = comp.get("asset") or {}
                rows.append({
                    "id": comp.get("id"),
                    "name": comp.get("name"),
                    "version": comp.get("version"),
                    "technology": comp.get("technology"),
                    "license": comp.get("license"),
                    "packageManager": comp.get("packageManager"),
                    "issuesBySeverity": issues_str,
                    "asset": asset.get("name"),
                    "assetId": asset.get("id"),
                })

            if not fetch_all:
                break
            if total_pages is not None and current_page >= total_pages:
                break
            if len(collection) < per_page:
                break
            current_page += 1

        fmt_lower = fmt.lower()
        if fmt_lower == "cyclonedx":
            bom = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "version": 1,
                "serialNumber": f"urn:uuid:{uuid.uuid4()}",
                "components": [],
            }
            for r in rows:
                comp = {
                    "type": "application",
                    "name": r.get("name") or "unknown",
                    "version": r.get("version") or "unknown",
                }
                if r.get("license"):
                    comp["licenses"] = [{"license": {"id": r["license"]}}]
                props = []
                if r.get("packageManager"):
                    props.append({"name": "packageManager", "value": r["packageManager"]})
                if r.get("asset"):
                    props.append({"name": "asset", "value": str(r["asset"])})
                if r.get("assetId"):
                    props.append({"name": "assetId", "value": str(r["assetId"])})
                if r.get("issuesBySeverity"):
                    props.append({"name": "vulnsBySeverity", "value": r["issuesBySeverity"]})
                if props:
                    comp["properties"] = props
                bom["components"].append(comp)
            payload = json.dumps(bom, indent=2)
            if output:
                with open(output, "w", encoding="utf-8") as f:
                    f.write(payload)
                summary(f"CycloneDX exported to {output}")
            else:
                print(payload)
            summary(f"{len(rows)} component(s) listed out of {total_count or len(rows)}.")
        else:
            export_data(
                rows,
                schema=sbom_schema,
                fmt=fmt,
                output=output,
                title=f"SBOM Components (Company {company_id}) - Page {page}/{total_pages or '?'}",
            )
            summary(f"{len(rows)} component(s) listed out of {total_count or len(rows)}.")
    except Exception as exc:
        error(f"Error listing SBOM components: {exc}")
        raise typer.Exit(code=1)


@app.command("import")
def import_sbom(
    company_id: int = typer.Option(..., "--company-id", "-c", help="Company ID."),
    file: str = typer.Option(..., "--file", "-f", help="Path to SBOM file (CycloneDX/SPDX)."),
    asset_id: int = typer.Option(..., "--asset-id", "-a", help="Asset ID (required; import SBOM for a specific asset)."),
):
    """
    Import an SBOM file for the given company.
    """
    mutation = """
    mutation ImportSbom($input: ImportSbomInput!) {
      importSbom(input: $input) {
        __typename
      }
    }
    """
    variables = {
        "input": {
            "companyId": str(company_id),
            "assetId": asset_id,
            "file": None,  # placeholder for Upload
        }
    }
    try:
        data = graphql_request_upload(
            mutation,
            variables=variables,
            file_param="input.file",
            file_path=file,
            log_request=True,
            verbose_only=True,
        )
        res = (data.get("importSbom") or {})
        success(f"SBOM import request sent. Response type: {res.get('__typename','unknown')}.")
    except Exception as exc:
        error(f"Error importing SBOM: {exc}")
        raise typer.Exit(code=1)


def _map_ecosystem(package_manager: Optional[str], purl: Optional[str]) -> str:
    # Try purl first
    if purl:
        try:
            # purl format: pkg:type/name@version
            if purl.startswith("pkg:"):
                rest = purl[4:]
                eco = rest.split("/")[0]
                return eco.lower()
        except Exception:
            pass
    pm = (package_manager or "").lower()
    mapping = {
        "npm": "npm",
        "yarn": "npm",
        "pnpm": "npm",
        "pypi": "PyPI",
        "pip": "PyPI",
        "maven": "Maven",
        "gradle": "Maven",
        "nuget": "NuGet",
        "go": "Go",
        "golang": "Go",
        "cargo": "crates.io",
        "rust": "crates.io",
        "composer": "Packagist",
        "packagist": "Packagist",
    }
    return mapping.get(pm, pm or "UNKNOWN")


@app.command("check-vulns", help="Check SBOM components against OSV (online) using list or a local SBOM file.")
def check_vulns(
    company_id: Optional[int] = typer.Option(None, "--company-id", "-c", help="Company ID (required if not using --file)."),
    asset_ids: Optional[str] = typer.Option(None, "--asset-ids", help="Comma-separated asset IDs to filter (when pulling from API)."),
    tags: Optional[str] = typer.Option(None, "--tags", help="Comma-separated tags to filter (API)."),
    vulnerable_only: bool = typer.Option(False, "--vulnerable-only", help="Filter vulnerableOnly=true when fetching from API."),
    file: Optional[str] = typer.Option(None, "--file", "-f", help="Path to SBOM file (CycloneDX JSON) to check locally."),
    per_page: int = typer.Option(200, "--per-page", help="Items per page when fetching SBOM via API."),
    all_pages: bool = typer.Option(True, "--all", help="Fetch all pages when using API source."),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table|json (default table)."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file (json)."),
):
    """
    If --file is provided, reads components from a CycloneDX JSON file.
    Otherwise fetches SBOM components via API (requires --company-id).
    """
    if not file and company_id is None:
        error("Provide --company-id or --file.")
        raise typer.Exit(code=1)

    rows = []
    if file:
        try:
            with open(file, encoding="utf-8") as fh:
                data = json.load(fh)
            comps = data.get("components") or []
            for comp in comps:
                name = comp.get("name")
                version = comp.get("version")
                purl = comp.get("purl")
                licenses = comp.get("licenses") or []
                license_id = ""
                if licenses and isinstance(licenses[0], dict):
                    license_id = (licenses[0].get("license") or {}).get("id") or ""
                pm = None
                props = comp.get("properties") or []
                for prop in props:
                    if isinstance(prop, dict) and prop.get("name") == "packageManager":
                        pm = prop.get("value")
                ecosystem = _map_ecosystem(pm, purl)
                rows.append({"name": name, "version": version, "purl": purl, "ecosystem": ecosystem, "license": license_id})
        except Exception as exc:
            error(f"Failed to read SBOM file: {exc}")
            raise typer.Exit(code=1)
    else:
        # Fetch via API
        query = """
        query SbomComponents($companyId: ID!, $search: SbomComponentSearchInput, $page: Int, $limit: Int) {
          sbomComponents(companyId: $companyId, search: $search, page: $page, limit: $limit) {
            collection {
              name
              version
              packageManager
              license
            }
            metadata { currentPage limitValue totalCount totalPages }
          }
        }
        """
        search = {}
        if vulnerable_only:
            search["vulnerableOnly"] = True
        if asset_ids:
            try:
                search["assetIds"] = [int(x.strip()) for x in asset_ids.split(",") if x.strip()]
            except Exception:
                error("Invalid --asset-ids; provide comma-separated integers.")
                raise typer.Exit(code=1)
        if tags:
            search["tags"] = [t.strip() for t in tags.split(",") if t.strip()]
        variables = {"companyId": str(company_id), "search": search or None, "page": 1, "limit": per_page}

        try:
            fetch_all = all_pages
            current_page = 1
            while True:
                variables["page"] = current_page
                data = graphql_request(query, variables, log_request=True, verbose_only=True)
                sbom = data["sbomComponents"]
                collection = sbom.get("collection") or []
                metadata = sbom.get("metadata") or {}
                total_pages = metadata.get("totalPages")
                if not collection:
                    break
                for comp in collection:
                    pm = comp.get("packageManager")
                    purl = None  # API não expõe purl; fallback only
                    ecosystem = _map_ecosystem(pm, purl)
                    rows.append({
                        "name": comp.get("name"),
                        "version": comp.get("version"),
                        "purl": purl,
                        "ecosystem": ecosystem,
                        "license": comp.get("license"),
                    })
                if not fetch_all:
                    break
                if total_pages is not None and current_page >= total_pages:
                    break
                if len(collection) < per_page:
                    break
                current_page += 1
        except Exception as exc:
            error(f"Error fetching SBOM: {exc}")
            raise typer.Exit(code=1)

    if not rows:
        info("No components to check.")
        raise typer.Exit()

    # Build OSV batch queries
    queries = []
    for comp in rows:
        name = comp.get("purl") or comp.get("name")
        version = comp.get("version") or ""
        ecosystem = comp.get("ecosystem") or ""
        pkg = {}
        if comp.get("purl"):
            pkg["purl"] = comp["purl"]
        if ecosystem and ecosystem.upper() != "UNKNOWN":
            pkg["ecosystem"] = ecosystem
            pkg["name"] = comp.get("name")
        else:
            pkg["name"] = comp.get("name")
        queries.append({"package": pkg, "version": version})

    try:
        resp = requests.post(
            "https://api.osv.dev/v1/querybatch",
            json={"queries": queries},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        error(f"OSV query failed: {exc}")
        raise typer.Exit(code=1)

    results = data.get("results") or []
    out_rows = []
    for comp, res in zip(rows, results):
        vulns = res.get("vulns") or []
        vuln_ids = [v.get("id") for v in vulns if v.get("id")]
        out_rows.append({
            "name": comp.get("name"),
            "version": comp.get("version"),
            "ecosystem": comp.get("ecosystem"),
            "purl": comp.get("purl"),
            "vulnCount": len(vuln_ids),
            "vulnIds": ", ".join(vuln_ids),
        })

    fmt_lower = fmt.lower()
    if fmt_lower == "json":
        payload = json.dumps(out_rows, indent=2)
        if output:
            with open(output, "w", encoding="utf-8") as f:
                f.write(payload)
            success(f"OSV check exported to {output}")
        else:
            print(payload)
    else:
        export_data(out_rows, schema=None, fmt="table")
