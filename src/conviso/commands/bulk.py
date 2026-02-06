# conviso/commands/bulk.py
"""
Bulk import/update/delete commands.
Initial scope: assets (create/update/delete) via CSV.
"""

import typer
import os
from typing import Optional, List, Dict, Any, Tuple
from rich.table import Table
from conviso.core.notifier import info, success, error, warning
from conviso.core.bulk_loader import load_csv, bulk_process, SkipRow, BulkResult
from conviso.clients.client_graphql import graphql_request
from conviso.core.logger import VERBOSE
from conviso.core.output_manager import console
from rich.progress import Progress
import json

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

    info("Applying changes in chunks...")
    result = BulkResult()
    total_rows = len(rows)
    with Progress() as progress:
        task = progress.add_task("Importing vulnerabilities", total=total_rows)
        for offset in range(0, total_rows, chunk_size):
            chunk = rows[offset : offset + chunk_size]
            for idx, row in enumerate(chunk, start=offset + 2):  # header is line 1
                payload: Dict[str, Any] = {}
                for header, target in column_map.items():
                    if header in row:
                        payload[target] = row[header]
                try:
                    handler(payload, idx)
                    result.add_success(idx, "ok")
                except SkipRow as exc:
                    result.add_skip(idx, str(exc))
                except Exception as exc:
                    result.add_error(idx, str(exc))
                progress.update(task, advance=1)
    result.report()


def load_vuln_rows(path: str, sarif: bool = False) -> List[Dict[str, Any]]:
    if not sarif:
        return load_csv(path)
    try:
        from sarif_om import SarifLog
    except ImportError as e:
        raise RuntimeError("sarif-om is required for --sarif. Install with: pip install --user sarif-om") from e

    with open(path, encoding="utf-8") as f:
        raw = json.load(f)

    # Remove top-level keys that sarif-om may not accept (e.g., $schema)
    if isinstance(raw, dict):
        raw = {k: v for k, v in raw.items() if not str(k).startswith("$")}

    try:
        log_obj = SarifLog(**raw)
        runs = getattr(log_obj, "runs", None) or []
    except Exception as e:
        raise RuntimeError(f"sarif-om failed to parse the file: {e}") from e

    rows: List[Dict[str, Any]] = []
    for run in runs:
        # Handle sarif-om objects or plain dicts
        if hasattr(run, "results"):
            results = getattr(run, "results", None)
        elif isinstance(run, dict):
            results = run.get("results")
        else:
            results = None
        results = results or []
        for res in results:
            # unify access whether sarif-om object or dict
            if hasattr(res, "properties"):
                props = getattr(res, "properties", None)
                msg = getattr(res, "message", None)
                locs = getattr(res, "locations", None)
                rule_id = getattr(res, "ruleId", None)
                level = getattr(res, "level", None)
            elif isinstance(res, dict):
                props = res.get("properties")
                msg = res.get("message")
                locs = res.get("locations")
                rule_id = res.get("ruleId")
                level = res.get("level")
            else:
                continue

            props = props or {}
            if not isinstance(props, dict):
                # sarif-om properties may be converted to dict by __iter__
                try:
                    props = dict(props)
                except Exception:
                    props = {}
            norm_props = {str(k).lower(): v for k, v in props.items()}
            row = dict(props)
            row["type"] = props.get("type") or (rule_id or "").upper()
            msg_dict = msg.__dict__ if hasattr(msg, "__dict__") else (msg or {})
            row["title"] = msg_dict.get("text") or props.get("title") or "Vulnerability"
            # severity fallback from level
            if not row.get("severity"):
                lvl = (level or "note").lower() if isinstance(level, str) else "note"
                level_map = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}
                row["severity"] = level_map.get(lvl, "LOW")
            # impact/probability defaults
            row["impactLevel"] = row.get("impactLevel") or norm_props.get("impactlevel") or "LOW"
            row["probabilityLevel"] = row.get("probabilityLevel") or norm_props.get("probabilitylevel") or "LOW"
            # summary / impactDescription / steps
            row["summary"] = row.get("summary") or row.get("title") or msg_dict.get("text")
            row["impactDescription"] = row.get("impactDescription") or row.get("description") or norm_props.get("impactdescription")
            row["stepsToReproduce"] = row.get("stepsToReproduce") or norm_props.get("stepstoreproduce") or row.get("description")
            # solution fallback
            row["solution"] = row.get("solution") or norm_props.get("solution") or row.get("reference")
            # map SARIF location artifact name to asset if present
            locations = locs or []
            if locations:
                loc0 = locations[0]
                phys = getattr(loc0, "physicalLocation", None) if sarif else loc0.get("physicalLocation")
                artifact = getattr(phys, "artifactLocation", None) if sarif else (phys or {}).get("artifactLocation")
                uri = getattr(artifact, "uri", None) if sarif else (artifact or {}).get("uri")
                if uri and not row.get("asset"):
                    row["asset"] = uri
            # assetId from properties variants
            for key in ("assetId", "asset_id", "assetid"):
                if key in norm_props and not row.get("assetId"):
                    row["assetId"] = norm_props[key]
            rows.append(row)
    return rows


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

            rest = parts[2:]
            if rest:
                first = rest[0]
                if first:
                    try:
                        act["typeId"] = int(first)
                        rest = rest[1:]
                    except Exception:
                        act["reference"] = first
                        rest = rest[1:]
                else:
                    rest = rest[1:]

            field_order = ["reference", "item", "category", "actionPlan", "vulnerabilityTemplateId", "sort"]
            start_index = 1 if "reference" in act else 0
            for idx, value in enumerate(rest):
                field_idx = idx + start_index
                if field_idx >= len(field_order):
                    break
                if not value:
                    continue
                field = field_order[field_idx]
                if field == "vulnerabilityTemplateId":
                    try:
                        act[field] = int(value)
                    except Exception:
                        warning(f"Ignoring invalid vulnerabilityTemplateId in activity: {value}")
                else:
                    act[field] = value
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
    result = BulkResult()
    total_rows = len(rows)
    with Progress() as progress:
        task = progress.add_task("Importing vulnerabilities", total=total_rows)
        for idx, row in enumerate(rows, start=2):  # header is line 1
            payload: Dict[str, Any] = {}
            for header, target in column_map.items():
                if header in row:
                    payload[target] = row[header]
            try:
                handler(payload, idx)
                result.add_success(idx, "ok")
            except SkipRow as exc:
                result.add_skip(idx, str(exc))
            except Exception as exc:
                result.add_error(idx, str(exc))
            progress.update(task, advance=1)
    result.report()


@app.command("vulns")
def bulk_vulns(
    company_id: int = typer.Option(None, "--company-id", "-c", help="Company ID."),
    file: str = typer.Option(None, "--file", "-f", help="Path to CSV or SARIF file."),
    operation: str = typer.Option(None, "--op", "-o", help="Operation: create|update|delete (WEB|NETWORK|SOURCE)", case_sensitive=False),
    force: bool = typer.Option(False, "--force", help="Apply changes after dry-run without confirmation."),
    preview_only: bool = typer.Option(False, "--preview-only", help="Run dry-run only and exit without applying."),
    show_template: bool = typer.Option(False, "--show-template", help="Display expected CSV columns and examples, then exit."),
    sarif: bool = typer.Option(False, "--sarif", help="Treat input file as SARIF."),
    default_asset_id: Optional[int] = typer.Option(None, "--asset-id-default", help="Fallback asset ID when SARIF lacks assetId (discouraged; prefer --sarif-asset-field)."),
    sarif_asset_field: Optional[str] = typer.Option(None, "--sarif-asset-field", help="SARIF field to use as asset identifier (e.g., 'asset' or 'assetId'). If omitted, you will be prompted."),
    stop_on_first_error: bool = typer.Option(False, "--stop-on-first-error", help="Abort on the first error and show the failing payload."),
):
    """
    Bulk create vulnerabilities (WEB, NETWORK, SOURCE) using CSV or SARIF (--sarif).
    Always runs dry-run first; requires --force or confirmation to apply.
    """
    if show_template:
        _show_vuln_template()
        raise typer.Exit()
    if file is None or operation is None or company_id is None:
        error("Missing required options. Use --company-id, --file, --op. For columns, run --show-template.")
        raise typer.Exit(code=1)

    op = operation.lower()
    if op not in {"create", "update", "delete"}:
        error("Invalid --op. Use create|update|delete.")
        raise typer.Exit(code=1)

    if not os.path.isfile(file):
        error(f"File not found: {file}")
        raise typer.Exit(code=1)

    rows = load_vuln_rows(file, sarif=sarif)
    if not rows:
        warning("No rows found in file.")
        raise typer.Exit()

    if op in {"update", "delete"}:
        _bulk_vulns_update_delete(
            op=op,
            rows=rows,
            company_id=company_id,
            force=force,
            preview_only=preview_only,
            stop_on_first_error=stop_on_first_error,
            sarif=sarif,
        )
        return

    chunk_size = 10  # API limit; fixed (no override)

    info(f"Loaded {len(rows)} row(s) from {file}. Operation={op}.")

    # Ask for SARIF asset field if not provided
    if sarif and not sarif_asset_field:
        sarif_asset_field = typer.prompt("Which SARIF field should be used as asset identifier? (e.g., asset, assetId)")

    def _as_int(val):
        try:
            return int(val)
        except Exception:
            return None

    # Preload all assets once, build name->id map (case-insensitive)
    asset_map: Dict[str, int] = {}
    try:
        page = 1
        per_page_assets = 200
        while True:
            query = """
            query Assets($companyId: ID!, $limit: Int!, $page: Int!) {
              assets(companyId: $companyId, limit: $limit, page: $page) {
                collection { id name }
                metadata { totalPages }
              }
            }
            """
            data = graphql_request(
                query,
                {"companyId": str(company_id), "limit": per_page_assets, "page": page},
                log_request=False,
                verbose_only=True,
            )
            assets_data = data.get("assets") or {}
            collection = assets_data.get("collection") or []
            for a in collection:
                nm = (a.get("name") or "").strip().lower()
                aid = _as_int(a.get("id"))
                if nm and aid is not None:
                    asset_map[nm] = aid
            meta = assets_data.get("metadata") or {}
            total_pages = meta.get("totalPages")
            if total_pages is not None and page >= total_pages:
                break
            if len(collection) < per_page_assets:
                break
            page += 1
    except Exception as exc:
        warning(f"Could not prefetch assets: {exc}")

    def _resolve_asset_by_name(name: str) -> Optional[int]:
        if not name:
            return None
        return asset_map.get(str(name).strip().lower())

    def _create_asset(name: str) -> Optional[int]:
        if not name:
            return None
        mutation = """
        mutation CreateAsset($input: CreateAssetInput!) {
          createAsset(input: $input) { asset { id name } }
        }
        """
        try:
            data = graphql_request(
                mutation,
                {"input": {"companyId": company_id, "name": name}},
                log_request=False,
                verbose_only=True,
            )
            asset = ((data.get("createAsset") or {}).get("asset")) if isinstance(data, dict) else None
            aid = asset.get("id") if isinstance(asset, dict) else None
            if aid:
                nm = name.strip().lower()
                asset_map[nm] = aid
                info(f"Created asset '{name}' with id {aid}")
                return aid
        except Exception as exc:
            warning(f"Could not create asset '{name}': {exc}")
        return None

    # Stats on referenced assets
    asset_names = set()
    if sarif_asset_field:
        asset_names.update([r.get(sarif_asset_field) for r in rows if r.get(sarif_asset_field)])
    asset_names.update([r.get("asset") for r in rows if r.get("asset")])
    resolved_assets = {nm: _resolve_asset_by_name(nm) for nm in asset_names if _resolve_asset_by_name(nm)}
    missing_assets = [nm for nm in asset_names if not _resolve_asset_by_name(nm)]
    info(f"Assets referenced in SARIF: {len(asset_names)}. Resolved by name: {len(resolved_assets)}. Missing: {len(missing_assets)}.")

    # Auto-create missing assets by name
    for nm in missing_assets:
        created = _create_asset(nm)
        if created:
            resolved_assets[nm] = created
    # Recompute missing after creation attempts
    missing_assets = [nm for nm in asset_names if not _resolve_asset_by_name(nm)]

    # Map assetId onto rows before dry-run
    def row_asset_candidate(r):
        if sarif_asset_field and r.get(sarif_asset_field):
            return r.get(sarif_asset_field)
        return r.get("asset")

    for r in rows:
        if r.get("assetId"):
            continue
        cand = row_asset_candidate(r)
        cand_int = _as_int(cand)
        if cand_int:
            r["assetId"] = cand_int
            continue
        if cand:
            resolved = _resolve_asset_by_name(cand)
            if not resolved:
                resolved = _create_asset(cand)
            if resolved:
                r["assetId"] = resolved
                continue
        if default_asset_id is not None:
            r["assetId"] = default_asset_id

    ready_assets = sum(1 for r in rows if r.get("assetId"))
    missing_after_map = len(rows) - ready_assets
    info(f"Asset mapping: {ready_assets}/{len(rows)} rows with assetId after mapping; missing: {missing_after_map}")

    # SARIF safety: summarize asset resolution and potential fallback/default usage
    if sarif:
        missing_asset_rows = sum(1 for r in rows if not r.get("assetId"))
        default_rows = sum(1 for r in rows if r.get("assetId") == default_asset_id) if default_asset_id is not None else 0
        resolved_by_name_rows = len(resolved_assets)
        info(
            f"Asset resolution summary → by name: {resolved_by_name_rows}, "
            f"default: {default_rows}, missing assetId after mapping: {missing_asset_rows}"
        )
        if missing_assets and default_asset_id is None:
            warning(f"{len(missing_assets)} asset name(s) were not resolved in company {company_id}.")
        if missing_asset_rows and default_asset_id is None:
            warning(f"{missing_asset_rows} row(s) still have no assetId; they will be skipped.")
            raise typer.Exit(code=1)

    SEVERITY_ALLOWED = {"NOTIFICATION", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def _require_fields(payload: dict, fields: list, rownum: int):
        missing = [f for f in fields if payload.get(f) in (None, "")]
        if missing:
            raise SkipRow(f"Missing required field(s) {missing} on row {rownum}")

    asset_cache: Dict[str, Optional[int]] = {}

    def _resolve_asset_by_name(name: str) -> Optional[int]:
        if not name:
            return None
        if name in asset_cache:
            return asset_cache[name]
        query = """
        query Assets($companyId: ID!, $search: String!) {
          assets(companyId: $companyId, limit: 1, page: 1, search: $search) {
            collection { id name }
          }
        }
        """
        try:
            data = graphql_request(
                query,
                {"companyId": str(company_id), "search": name},
                log_request=False,
                verbose_only=True,
            )
            collection = ((data.get("assets") or {}).get("collection")) or []
            if collection:
                aid = collection[0].get("id")
                asset_cache[name] = aid
                return aid
        except Exception:
            pass
        asset_cache[name] = None
        return None

    def _common_fields(payload: dict, rownum: int):
        # Defaults for optional/missing fields from SARIF
        if sarif_asset_field and not payload.get("assetId"):
            candidate = payload.get(sarif_asset_field)
            # If candidate looks like int, treat as id; else name resolution
            cand_int = _as_int(candidate)
            if cand_int:
                payload["assetId"] = cand_int
            else:
                resolved = _resolve_asset_by_name(candidate)
                if resolved:
                    payload["assetId"] = resolved
        if not payload.get("assetId"):
            resolved = _resolve_asset_by_name(payload.get("asset"))
            if resolved:
                payload["assetId"] = resolved
        if not payload.get("assetId") and default_asset_id:
            payload["assetId"] = default_asset_id
        # Required after default fill
        _require_fields(payload, ["assetId", "title", "description", "severity"], rownum)
        # Fill sensible defaults
        allowed_levels = {"LOW", "MEDIUM", "HIGH"}
        payload["impactLevel"] = (payload.get("impactLevel") or "LOW").upper()
        if payload["impactLevel"] not in allowed_levels:
            payload["impactLevel"] = "LOW"
        payload["probabilityLevel"] = (payload.get("probabilityLevel") or "LOW").upper()
        if payload["probabilityLevel"] not in allowed_levels:
            payload["probabilityLevel"] = "LOW"
        payload["summary"] = payload.get("summary") or payload.get("title")
        payload["impactDescription"] = payload.get("impactDescription") or payload.get("description")
        payload["stepsToReproduce"] = payload.get("stepsToReproduce") or payload.get("description")
        payload["solution"] = payload.get("solution") or "See description"
        # severity validation
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
                val = _as_int(payload[k])
                if val is None:
                    raise SkipRow(f"Invalid integer for {k} on row {rownum}, skipping")
                payload[k] = val

    def handle_create(payload, rownum):
        raw_type = str(payload.get("type", "")).upper()
        type_map = {
            "WEB": "WEB",
            "WEB_VULNERABILITY": "WEB",
            "DAST_FINDING": "WEB",
            "NETWORK": "NETWORK",
            "NETWORK_VULNERABILITY": "NETWORK",
            "SOURCE": "SOURCE",
            "SOURCE_CODE_VULNERABILITY": "SOURCE",
            "SAST_FINDING": "SOURCE",
            "SCA_FINDING": "SOURCE",  # treat SCA as source-like
        }
        vtype = type_map.get(raw_type)
        if not vtype:
            # Infer based on available fields (fallback to WEB)
            if payload.get("address") or payload.get("protocol"):
                vtype = "NETWORK"
            elif payload.get("fileName") or payload.get("vulnerableLine") or payload.get("firstLine") or payload.get("codeSnippet"):
                vtype = "SOURCE"
            else:
                # If we lack URL/method and address/protocol/fileName, default to SOURCE to avoid WEB requirements
                if payload.get("url") or payload.get("method"):
                    vtype = "WEB"
                else:
                    vtype = "SOURCE"
        payload.pop("type", None)
        _common_fields(payload, rownum)

        # No API call here; we only prepare payload. Sending occurs in send_batch.
        if vtype == "WEB":
            # Fill missing with safe defaults to avoid skips
            payload["method"] = (payload.get("method") or "GET").upper()
            payload["scheme"] = (payload.get("scheme") or "HTTPS").upper()
            payload["url"] = payload.get("url") or "https://example.com"
            payload["port"] = _as_int(payload.get("port")) or 443
            payload["request"] = payload.get("request") or "-"
            payload["response"] = payload.get("response") or "-"
            _require_fields(payload, ["method", "scheme", "url", "port", "request", "response"], rownum)
            for k in ("port",):
                try:
                    payload[k] = int(payload[k])
                except Exception:
                    raise SkipRow(f"Invalid integer for {k} on row {rownum}, skipping")
        elif vtype == "NETWORK":
            payload["address"] = payload.get("address") or "N/A"
            payload["protocol"] = payload.get("protocol") or "TCP"
            payload["attackVector"] = payload.get("attackVector") or "N/A"
            payload["port"] = _as_int(payload.get("port")) or 0
            _require_fields(payload, ["address", "protocol", "port", "attackVector"], rownum)
            for k in ("port",):
                try:
                    payload[k] = int(payload[k])
                except Exception:
                    raise SkipRow(f"Invalid integer for {k} on row {rownum}, skipping")
        elif vtype == "SOURCE":
            payload["fileName"] = payload.get("fileName") or "unknown"
            payload["vulnerableLine"] = _as_int(payload.get("vulnerableLine")) or 1
            payload["firstLine"] = _as_int(payload.get("firstLine")) or 1
            payload["codeSnippet"] = payload.get("codeSnippet") or "Not provided"
            _require_fields(payload, ["fileName", "vulnerableLine", "firstLine", "codeSnippet"], rownum)
            for k in ("vulnerableLine", "firstLine"):
                try:
                    payload[k] = int(payload[k])
                except Exception:
                    raise SkipRow(f"Invalid integer for {k} on row {rownum}, skipping")
        return vtype, payload

    column_map = {
        "type": "type",
        "assetId": "assetId",
        "asset": "asset",
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
    result = BulkResult()
    total_rows = len(rows)
    prepared: List[Tuple[int, str, Dict[str, Any]]] = []

    # Prepare payloads (validate and enrich)
    for idx, row in enumerate(rows, start=2):
        payload: Dict[str, Any] = {}
        for header, target in column_map.items():
            if header in row:
                payload[target] = row[header]
        try:
            vtype, built = handler(payload, idx)
            if vtype == "WEB":
                built["method"] = (built.get("method") or "GET").upper()
                built["scheme"] = (built.get("scheme") or "HTTPS").upper()
                built["url"] = built.get("url") or "https://example.com"
                built["port"] = _as_int(built.get("port")) or 443
                built["request"] = built.get("request") or "-"
                built["response"] = built.get("response") or "-"
                _require_fields(built, ["method", "scheme", "url", "port", "request", "response"], idx)
                # Remove fields not accepted by CreateWebVulnerabilityInput
                for extra in ("asset", "fileName", "vulnerableLine", "codeSnippet"):
                    built.pop(extra, None)
            elif vtype == "NETWORK":
                built["address"] = built.get("address") or "N/A"
                built["protocol"] = built.get("protocol") or "TCP"
                built["attackVector"] = built.get("attackVector") or "N/A"
                built["port"] = _as_int(built.get("port")) or 0
                _require_fields(built, ["address", "protocol", "port", "attackVector"], idx)
                for extra in ("asset", "fileName", "vulnerableLine", "codeSnippet"):
                    built.pop(extra, None)
            else:
                built["fileName"] = built.get("fileName") or "unknown"
                built["vulnerableLine"] = _as_int(built.get("vulnerableLine")) or 1
                built["firstLine"] = _as_int(built.get("firstLine")) or 1
                built["codeSnippet"] = built.get("codeSnippet") or "Not provided"
                _require_fields(built, ["fileName", "vulnerableLine", "firstLine", "codeSnippet"], idx)
                # Remove fields not accepted by Source mutation
                for extra in ("asset",):
                    built.pop(extra, None)
            prepared.append((idx, vtype, built))
        except SkipRow as exc:
            result.add_skip(idx, str(exc))
        except Exception as exc:
            result.add_error(idx, str(exc))

    info(
        f"Prepared for send: WEB={len([1 for _, t, _ in prepared if t=='WEB'])}, "
        f"NETWORK={len([1 for _, t, _ in prepared if t=='NETWORK'])}, "
        f"SOURCE={len([1 for _, t, _ in prepared if t=='SOURCE'])}"
    )

    def _send_single(vtype: str, rownum: int, payload: Dict[str, Any]) -> Tuple[int, int]:
        if vtype == "WEB":
            mutation = """
            mutation CreateWeb($input: CreateWebVulnerabilityInput!) {
              createWebVulnerability(input: $input) { issue { id title } }
            }
            """
        elif vtype == "NETWORK":
            mutation = """
            mutation CreateNetwork($input: CreateNetworkVulnerabilityInput!) {
              createNetworkVulnerability(input: $input) { issue { id title } }
            }
            """
        else:
            mutation = """
            mutation CreateSource($input: CreateSourceCodeVulnerabilityInput!) {
              createSourceCodeVulnerability(input: $input) { issue { id title } }
            }
            """
        if VERBOSE:
            info(f"[DEBUG] Single {vtype} mutation: {mutation.strip()}")
        try:
            data = graphql_request(mutation, {"input": payload}, log_request=VERBOSE, verbose_only=not VERBOSE)
            issue = None
            if vtype == "WEB":
                issue = ((data.get("createWebVulnerability") or {}).get("issue")) if isinstance(data, dict) else None
            elif vtype == "NETWORK":
                issue = ((data.get("createNetworkVulnerability") or {}).get("issue")) if isinstance(data, dict) else None
            else:
                issue = ((data.get("createSourceCodeVulnerability") or {}).get("issue")) if isinstance(data, dict) else None
            if issue and issue.get("id"):
                result.add_success(rownum, f"created {vtype} id {issue.get('id')}")
                return (1, 0)
            result.add_error(rownum, f"no issue returned (title='{payload.get('title','-')}', assetId={payload.get('assetId')})")
            return (0, 1)
        except Exception as exc:
            # Show minimal payload for debugging
            debug_payload = {k: payload.get(k) for k in ("title", "assetId", "type", "method", "scheme", "url", "port", "address", "protocol", "fileName")}
            result.add_error(rownum, f"{vtype} error: {exc} payload={debug_payload}")
            if stop_on_first_error:
                raise Exception(f"Stop on first error: {vtype} payload={debug_payload} error={exc}")
            return (0, 1)

    def send_batch(vtype: str, batch: List[Tuple[int, Dict[str, Any]]]) -> Tuple[int, int]:
        if not batch:
            return (0, 0)
        var_defs = []
        fields = []
        variables = {}
        for i, (_, payload) in enumerate(batch):
            var_name = f"issue{i}"
            if vtype == "WEB":
                var_defs.append(f"${var_name}: CreateWebVulnerabilityInput!")
                fields.append(f"c{i}: createWebVulnerability(input: ${var_name}) {{ issue {{ id title }} }}")
            elif vtype == "NETWORK":
                var_defs.append(f"${var_name}: CreateNetworkVulnerabilityInput!")
                fields.append(f"c{i}: createNetworkVulnerability(input: ${var_name}) {{ issue {{ id title }} }}")
            else:
                var_defs.append(f"${var_name}: CreateSourceCodeVulnerabilityInput!")
                fields.append(f"c{i}: createSourceCodeVulnerability(input: ${var_name}) {{ issue {{ id title }} }}")
            variables[var_name] = payload
        mutation = f"mutation Batch({', '.join(var_defs)}) {{ " + " ".join(fields) + " }}"
        if VERBOSE:
            info(f"[DEBUG] Batch {vtype} mutation: {mutation.strip()}")
        try:
            data = graphql_request(mutation, variables, log_request=VERBOSE, verbose_only=not VERBOSE)
        except Exception as exc:
            # Backend may reject multi-mutation batches; fallback silently to per-item.
            succ, err = 0, 0
            for (rownum, payload) in batch:
                s, e = _send_single(vtype, rownum, payload)
                succ += s
                err += e
                if stop_on_first_error and e:
                    raise Exception(f"Stop on first error: {vtype} row {rownum} payload={{'title': payload.get('title'), 'assetId': payload.get('assetId')}} error={exc}")
            return (succ, err)

        succ = 0
        err = 0
        for i, (rownum, _) in enumerate(batch):
            key = f"c{i}"
            entry = data.get(key) if isinstance(data, dict) else None
            issue = (entry or {}).get("issue") if isinstance(entry, dict) else None
            if issue and issue.get("id"):
                result.add_success(rownum, f"created {vtype} id {issue.get('id')}")
                succ += 1
            else:
                result.add_error(rownum, f"no issue returned for {vtype} (row {rownum})")
                err += 1
        return (succ, err)

    # If chunk_size == 1, skip batch path and send individually to avoid noisy fallbacks
    if chunk_size == 1:
        info("Chunk size is 1: sending items individually (no batch).")
        with Progress() as progress:
            task = progress.add_task("Importing vulnerabilities", total=len(prepared))
            for rownum, vtype, payload in prepared:
                _send_single(vtype, rownum, payload)
                progress.update(task, advance=1)
    else:
        # Batch by type with progress
        with Progress() as progress:
            total_prepared = len(prepared)
            task = progress.add_task("Importing vulnerabilities", total=total_prepared)
            for vtype in ("WEB", "NETWORK", "SOURCE"):
                items = [(rownum, payload) for (rownum, t, payload) in prepared if t == vtype]
                if not items:
                    continue
                info(f"Sending {len(items)} {vtype} vulns in batches of {chunk_size}...")
                batch_num = 0
                # Chunk according to chunk_size
                for offset in range(0, len(items), chunk_size):
                    batch = items[offset : offset + chunk_size]
                    batch_num += 1
                    info(f"[{vtype}] Batch {batch_num}: rows {batch[0][0]} to {batch[-1][0]} (size {len(batch)})")
                    try:
                        succ, err = send_batch(vtype, batch)
                        info(f"[{vtype}] Batch {batch_num} result: {succ} ok, {err} error(s)")
                        if err == len(batch):
                            error(f"[{vtype}] Batch {batch_num} failed completely; continuing to next batch.")
                    except Exception as exc:
                        error(f"Batch error for {vtype} rows {batch[0][0]}-{batch[-1][0]}: {exc}")
                        for rownum, _ in batch:
                            result.add_error(rownum, str(exc))
                    progress.update(task, advance=len(batch))
            info(f"Completed batches.")

    result.report()


def _bulk_vulns_update_delete(
    op: str,
    rows: List[Dict[str, Any]],
    company_id: int,
    force: bool,
    preview_only: bool,
    stop_on_first_error: bool,
    sarif: bool,
):
    info(f"Loaded {len(rows)} row(s). Operation={op}.")

    if preview_only:
        for idx, row in enumerate(rows, start=2):
            console.print(f"ℹ️  [dry-run] Row {idx}: {row}", markup=False)
        info("Preview-only mode: no changes applied.")
        raise typer.Exit()

    if not force:
        confirm = typer.confirm("Apply changes now (run without dry-run)?")
        if not confirm:
            info("Aborted. No changes applied.")
            raise typer.Exit()

    def _as_int(val):
        try:
            return int(val)
        except Exception:
            return None

    def _strip_markup(text: str) -> str:
        import re
        return re.sub(r"\[/?[^\]]+\]", "", text or "")

    def _infer_type(row: Dict[str, Any]) -> str:
        raw_type = (row.get("type") or row.get("ruleId") or row.get("kind") or "").upper()
        type_map = {
            "WEB": "WEB",
            "WEB_VULNERABILITY": "WEB",
            "DAST_FINDING": "WEB",
            "NETWORK": "NETWORK",
            "NETWORK_VULNERABILITY": "NETWORK",
            "SOURCE": "SOURCE",
            "SOURCE_CODE_VULNERABILITY": "SOURCE",
            "SAST_FINDING": "SOURCE",
        }
        mapped = type_map.get(raw_type)
        if mapped:
            return mapped
        if row.get("address") or row.get("protocol"):
            return "NETWORK"
        if row.get("fileName") or row.get("vulnerableLine") or row.get("codeSnippet"):
            return "SOURCE"
        return "WEB"

    SEVERITY_ALLOWED = {"NOTIFICATION", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def _coerce_bool(val):
        if isinstance(val, bool):
            return val
        if val is None:
            return None
        return str(val).lower() in {"true", "1", "yes", "y"}

    result = BulkResult()

    update_mutations = {
        "WEB": """
        mutation UpdateWeb($input: UpdateWebVulnerabilityInput!) {
          updateWebVulnerability(input: $input) { issue { id title } }
        }
        """,
        "NETWORK": """
        mutation UpdateNetwork($input: UpdateNetworkVulnerabilityInput!) {
          updateNetworkVulnerability(input: $input) { issue { id title } }
        }
        """,
        "SOURCE": """
        mutation UpdateSource($input: UpdateSourceCodeVulnerabilityInput!) {
          updateSourceCodeVulnerability(input: $input) { issue { id title } }
        }
        """,
    }

    delete_mutation = """
    mutation DeleteIssue($input: DeleteIssueInput!) {
      deleteIssue(input: $input) { issue { id } }
    }
    """

    def _build_update_payload(row: Dict[str, Any], rownum: int) -> Tuple[str, Dict[str, Any]]:
        issue_id = _as_int(row.get("id") or row.get("issueId"))
        if issue_id is None:
            raise SkipRow("Missing id/issueId for update")
        vtype = _infer_type(row)
        payload = {"id": issue_id, "companyId": company_id}

        def _maybe_set(key, target=None, transform=None):
            if key in row and row[key] not in (None, ""):
                val = row[key]
                if transform:
                    val = transform(val)
                payload[target or key] = val

        for key in (
            "assetId",
            "projectId",
        ):
            _maybe_set(key, key, _as_int)
        for key in (
            "title",
            "description",
            "solution",
            "summary",
            "impactDescription",
            "stepsToReproduce",
            "reference",
            "category",
        ):
            _maybe_set(key)
        _maybe_set("status", "status", lambda v: str(v).upper())
        _maybe_set("probabilityLevel", "probabilityLevel", lambda v: str(v).upper())
        _maybe_set("impactLevel", "impactLevel", lambda v: str(v).upper())
        _maybe_set("compromisedEnvironment", "compromisedEnvironment", _coerce_bool)

        if "severity" in row and row.get("severity") not in (None, ""):
            sev = _strip_markup(row.get("severity"))
            sev_up = str(sev).upper()
            if sev_up in SEVERITY_ALLOWED:
                payload["severity"] = sev_up
            else:
                raise SkipRow(f"Invalid severity '{row.get('severity')}'")

        if vtype == "WEB":
            for key in ("method", "scheme", "url", "request", "response", "parameters"):
                _maybe_set(key, key, lambda v: str(v).upper() if key in ("method", "scheme") else v)
            _maybe_set("port", "port", _as_int)
            allowed = {
                "id",
                "companyId",
                "assetId",
                "projectId",
                "title",
                "description",
                "solution",
                "impactLevel",
                "probabilityLevel",
                "severity",
                "summary",
                "impactDescription",
                "stepsToReproduce",
                "reference",
                "category",
                "status",
                "compromisedEnvironment",
                "method",
                "scheme",
                "url",
                "port",
                "request",
                "response",
                "parameters",
            }
        elif vtype == "NETWORK":
            for key in ("address", "protocol", "attackVector"):
                _maybe_set(key)
            _maybe_set("port", "port", _as_int)
            allowed = {
                "id",
                "companyId",
                "assetId",
                "projectId",
                "title",
                "description",
                "solution",
                "impactLevel",
                "probabilityLevel",
                "severity",
                "summary",
                "impactDescription",
                "stepsToReproduce",
                "reference",
                "category",
                "status",
                "compromisedEnvironment",
                "address",
                "protocol",
                "attackVector",
                "port",
            }
        else:  # SOURCE
            for key in ("fileName", "codeSnippet", "source", "sink", "commitRef", "deployId"):
                _maybe_set(key)
            _maybe_set("vulnerableLine", "vulnerableLine", _as_int)
            _maybe_set("firstLine", "firstLine", _as_int)
            allowed = {
                "id",
                "companyId",
                "assetId",
                "projectId",
                "title",
                "description",
                "solution",
                "impactLevel",
                "probabilityLevel",
                "severity",
                "summary",
                "impactDescription",
                "stepsToReproduce",
                "reference",
                "category",
                "status",
                "compromisedEnvironment",
                "fileName",
                "vulnerableLine",
                "firstLine",
                "codeSnippet",
                "source",
                "sink",
                "commitRef",
                "deployId",
            }

        payload = {k: v for k, v in payload.items() if v not in (None, "") and k in allowed}
        return vtype, payload

    with Progress() as progress:
        task = progress.add_task("Processing vulnerabilities", total=len(rows))
        for idx, row in enumerate(rows, start=2):
            try:
                if op == "delete":
                    issue_id = _as_int(row.get("id") or row.get("issueId"))
                    if issue_id is None:
                        raise SkipRow("Missing id/issueId for delete")
                    variables = {"input": {"id": issue_id, "companyId": company_id}}
                    data = graphql_request(delete_mutation, variables)
                    issue = ((data.get("deleteIssue") or {}).get("issue")) if isinstance(data, dict) else None
                    if issue and issue.get("id"):
                        result.add_success(idx, f"deleted issue {issue.get('id')}")
                    else:
                        result.add_error(idx, "delete returned no issue")
                else:
                    vtype, payload = _build_update_payload(row, idx)
                    mutation = update_mutations.get(vtype)
                    if not mutation:
                        raise SkipRow(f"Unsupported type for update: {vtype}")
                    data = graphql_request(mutation, {"input": payload})
                    key = {"WEB": "updateWebVulnerability", "NETWORK": "updateNetworkVulnerability", "SOURCE": "updateSourceCodeVulnerability"}[vtype]
                    issue = ((data.get(key) or {}).get("issue")) if isinstance(data, dict) else None
                    if issue and issue.get("id"):
                        result.add_success(idx, f"updated {vtype} {issue.get('id')}")
                    else:
                        result.add_error(idx, f"{vtype} update returned no issue")
            except SkipRow as exc:
                result.add_skip(idx, str(exc))
            except Exception as exc:
                result.add_error(idx, str(exc))
                if stop_on_first_error:
                    raise
            finally:
                progress.update(task, advance=1)

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
        "Semicolon-separated activities; each activity uses pipe-separated fields: label|description|[typeId]|reference|item|category|actionPlan|templateId|sort",
        "Login|Check login|REF||Category||123|1;Logout|Check logout|1",
    )

    console.print(table)
    console.print("\nExample create CSV:\n")
    console.print("label,description,global,activities")
    console.print("Req A,Do X,true,\"Login|Check login|REF||Category||123|1\"\n")

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
    console.print("\nSARIF import:\nPass --sarif to read a SARIF file. It maps result.properties into the same columns above (no Attack Surface field).")
    console.print("Types accepted: WEB, NETWORK, SOURCE. Other SARIF types (e.g., SAST_FINDING/SOURCE_CODE_VULNERABILITY) are inferred to SOURCE;")
    console.print("entries with network fields infer NETWORK; otherwise fallback to WEB. Ensure properties.assetId is present.")
