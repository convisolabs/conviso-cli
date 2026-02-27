# conviso/commands/projects.py
"""
Projects Command Module
-----------------------
Manages project operations (list, create, update, delete) via Conviso GraphQL API.
Now standardized to use the new core/output_manager for unified output handling.
"""

import math
import typer
from typing import Optional, List
from datetime import datetime, timezone
from conviso.core.notifier import info, success, error, summary, warning
from conviso.clients.client_graphql import graphql_request
from conviso.schemas.projects_schema import schema
from conviso.schemas.project_requirements_activities_schema import schema as project_requirements_schema
from conviso.core.output_manager import export_data

app = typer.Typer(help="Manage projects via Conviso GraphQL API.")

# ---------------------- LIST COMMAND ---------------------- #
@app.command("list")
def list_projects(
    company_id: int = typer.Option(..., "--company-id", "-c", help="Company ID (required)"),
    filters: Optional[List[str]] = typer.Option(
        None,
        "--filter",
        "-F",
        help="Apply filters in 'field=value' format. Supports aliases (e.g., id=123, name=foo, status=DONE).",
    ),
    sort_by: Optional[str] = typer.Option(
        None,
        "--sort-by",
        "-s",
        help="Sort results by a field (e.g. createdAt, label, startDate, endDate).",
    ),
    descending: bool = typer.Option(False, "--desc", help="Sort in descending order."),
    page: int = typer.Option(1, "--page", "-p", help="Page number."),
    limit: int = typer.Option(50, "--limit", "-l", help="Items per page."),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table, json, csv."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file (for JSON or CSV export)."),
    all_pages: bool = typer.Option(False, "--all", help="Fetch all pages."),
):
    """List projects for a given company using the unified output manager."""
    info(f"Listing projects for company {company_id} (page {page}, limit {limit})...")

    # Build search parameters
    params = {"scopeIdEq": company_id}
    if filters:
        for f in filters:
            if "=" not in f:
                warning(f"[WARN] Invalid filter syntax: {f} (expected key=value)")
                continue
            key, value = f.split("=", 1)
            gql_key = schema.resolve_filter_key(key.strip())
            casted = schema.cast_filter_value(gql_key, value.strip())
            params[gql_key] = casted

    variables = {
        "page": page,
        "limit": limit,
        "params": params,
        "sortBy": sort_by,
        "descending": descending,
    }

    query = """
    query projects(
      $page: Int
      $limit: Int
      $params: ProjectSearch
      $sortBy: String
      $descending: Boolean
    ) {
      projects(
        page: $page
        limit: $limit
        params: $params
        sortBy: $sortBy
        descending: $descending
      ) {
        collection {
          id
          label
          status
          createdAt
          startDate
          endDate
          estimatedHours
          environmentCompromised
          projectType { label }
          tags { name }
          assets { id name }
          requirementsProgress { done total }
        }
        metadata { totalCount totalPages }
      }
    }
    """

    try:
        current_page = page
        rows = []
        total_pages = None
        total_count = 0
        while True:
            variables["page"] = current_page
            data = graphql_request(query, variables, log_request=True, verbose_only=all_pages)
            projects_data = data["projects"]
            collection = projects_data["collection"]
            metadata = projects_data["metadata"]
            total_pages = metadata.get("totalPages")
            total_count = metadata.get("totalCount", total_count)

            if not collection:
                if current_page == page:
                    typer.echo("⚠️  No projects found.")
                    raise typer.Exit()
                break

            for p in collection:
                done = (p.get("requirementsProgress") or {}).get("done", 0)
                total = (p.get("requirementsProgress") or {}).get("total", 0)
                requirements = f"{done}/{total}"

                tags_list = p.get("tags") or []
                tags_str = ", ".join(t.get("name", "") for t in tags_list if t and t.get("name"))

                assets_list = []
                for a in p.get("assets") or []:
                    name = a.get("name")
                    aid = a.get("id")
                    if name:
                        assets_list.append(name)
                    elif aid:
                        assets_list.append(str(aid))

                rows.append({
                    "id": p.get("id") or "",
                    "label": p.get("label") or "",
                    "projectType.label": (p.get("projectType") or {}).get("label", ""),
                    "status": p.get("status") or "",
                    "requirements": requirements,
                    "assets": ", ".join(assets_list),
                    "createdAt": p.get("createdAt") or "",
                    "startDate": p.get("startDate") or "",
                    "endDate": p.get("endDate") or "",
                    "tags": tags_str,
                })

            if not all_pages or (total_pages is not None and current_page >= total_pages):
                break
            current_page += 1


        export_data(
            rows,
            schema=schema,
            fmt=fmt,
            output=output,
            title=f"Projects (Company {company_id}) - Page {page}/{total_pages or '?'}",
        )

        if fmt != "json":
            total = total_count or len(rows)
            effective_limit = max(limit, 1)

            start = (page - 1) * effective_limit + 1 if total > 0 else 0
            end = min(page * effective_limit, total)

            total_pages_calc = math.ceil(total / effective_limit)

            summary(
                f"Showing {start}-{end} of {total} "
                f"(page {page}/{total_pages_calc}).\n"
            )

    except Exception as e:
        error(f"Error listing projects: {e}")
        raise typer.Exit(code=1)


# ---------------------- PROJECT REQUIREMENTS COMMAND ---------------------- #
@app.command("requirements")
def list_project_requirements(
    project_id: int = typer.Option(..., "--project-id", "-p", help="Target project ID."),
    requirement_id: Optional[int] = typer.Option(
        None,
        "--requirement-id",
        "-r",
        help="Filter activities by a specific requirement (playbook) ID.",
    ),
    status: Optional[str] = typer.Option(
        None,
        "--status",
        "-s",
        help="Activity status: IN_PROGRESS, DONE, NOT_APPLICABLE, NOT_STARTED, NOT_ACCORDING.",
    ),
    history_attachments: bool = typer.Option(
        False,
        "--history-attachments",
        help="Only return activities with at least one attached file.",
    ),
    history_email: Optional[str] = typer.Option(
        None,
        "--history-email",
        help="Filter by history actor email (contains, case-insensitive).",
    ),
    history_start: Optional[str] = typer.Option(
        None,
        "--history-start",
        help="History created_at >= this value (YYYY-MM-DD or ISO-8601).",
    ),
    history_end: Optional[str] = typer.Option(
        None,
        "--history-end",
        help="History created_at <= this value (YYYY-MM-DD or ISO-8601).",
    ),
    attachment_name: Optional[str] = typer.Option(
        None,
        "--attachment-name",
        help="Filter by attached filename (contains, case-insensitive).",
    ),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table, json, csv."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file (for JSON or CSV export)."),
):
    """List project requirements and activities with attachment/history filters."""
    info(f"Listing requirements/activities for project {project_id}...")

    allowed_status = {"IN_PROGRESS", "DONE", "NOT_APPLICABLE", "NOT_STARTED", "NOT_ACCORDING"}

    def _norm(value: Optional[str]) -> str:
        if not value:
            return ""
        chars = []
        for ch in value.lower():
            chars.append(ch if ch.isalnum() else " ")
        return " ".join("".join(chars).split())

    def _parse_dt(value: Optional[str], end_of_day: bool = False) -> Optional[datetime]:
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

    status_filter = status.strip().upper() if status else None
    if status_filter and status_filter not in allowed_status:
        warning(f"Unknown status '{status_filter}'. Allowed: {', '.join(sorted(allowed_status))}")

    history_email_filter = (history_email or "").strip().lower() or None
    attachment_name_filter = (attachment_name or "").strip().lower() or None
    history_start_dt = _parse_dt(history_start, end_of_day=False)
    history_end_dt = _parse_dt(history_end, end_of_day=True)
    has_history_filters = bool(history_email_filter or history_start_dt or history_end_dt)

    query = """
    query ProjectRequirements($id: ID!) {
      project(id: $id) {
        id
        label
        activities {
          id
          title
          status
          startedAt
          finishedAt
          evidences { filename }
          playbook { id label }
          history(pagination: { page: 1, perPage: 200 }) {
            collection {
              id
              createdAt
              actionType
              portalUser { email name }
              evidences { filename }
            }
          }
        }
      }
    }
    """

    try:
        data = graphql_request(query, {"id": str(project_id)})
        project = data.get("project")
        if not project:
            typer.echo("⚠️  Project not found.")
            raise typer.Exit()

        rows = []
        for activity in project.get("activities") or []:
            playbook = activity.get("playbook") or {}
            playbook_id = playbook.get("id")
            if requirement_id is not None:
                try:
                    if int(playbook_id) != int(requirement_id):
                        continue
                except Exception:
                    continue
            activity_status = (activity.get("status") or "").upper()
            activity_evidences = activity.get("evidences") or []
            history_rows = ((activity.get("history") or {}).get("collection") or [])

            attachment_names = []
            for ev in activity_evidences:
                filename = (ev or {}).get("filename")
                if filename:
                    attachment_names.append(filename)
            for h in history_rows:
                for ev in (h.get("evidences") or []):
                    filename = (ev or {}).get("filename")
                    if filename:
                        attachment_names.append(filename)
            # preserve order while removing duplicates
            seen_names = set()
            attachment_names = [n for n in attachment_names if not (n in seen_names or seen_names.add(n))]
            has_attachments = bool(attachment_names)

            if attachment_name_filter:
                if not any(attachment_name_filter in name.lower() for name in attachment_names):
                    continue

            if status_filter and activity_status != status_filter:
                continue
            if history_attachments and not has_attachments:
                continue

            matched_history = []
            for h in history_rows:
                h_email = ((h.get("portalUser") or {}).get("email") or "").lower()
                h_created_at = _safe_parse_iso(h.get("createdAt"))

                if history_email_filter and history_email_filter not in h_email:
                    continue
                if history_start_dt and (h_created_at is None or h_created_at < history_start_dt):
                    continue
                if history_end_dt and (h_created_at is None or h_created_at > history_end_dt):
                    continue
                matched_history.append(h)

            if has_history_filters and not matched_history:
                continue

            history_for_output = matched_history if has_history_filters else history_rows
            history_emails = []
            for h in history_for_output:
                email = (h.get("portalUser") or {}).get("email") or ""
                if email and email not in history_emails:
                    history_emails.append(email)
            history_dates = [h.get("createdAt") for h in history_for_output if h.get("createdAt")]

            rows.append({
                "projectId": project.get("id") or "",
                "projectLabel": project.get("label") or "",
                "requirementId": playbook.get("id") or "",
                "requirementLabel": playbook.get("label") or "",
                "activityId": activity.get("id") or "",
                "activityTitle": activity.get("title") or "",
                "activityStatus": activity_status,
                "hasAttachments": str(has_attachments),
                "attachments": ", ".join(attachment_names),
                "historyEvents": str(len(history_for_output)),
                "historyEmails": ", ".join(history_emails),
                "historyLastAt": max(history_dates) if history_dates else "",
                "startedAt": activity.get("startedAt") or "",
                "finishedAt": activity.get("finishedAt") or "",
            })

        if not rows:
            typer.echo("⚠️  No requirements/activities found for the given filters.")
            raise typer.Exit()

        export_data(
            rows,
            schema=project_requirements_schema,
            fmt=fmt,
            output=output,
            title=f"Project {project.get('id')} - Requirements Activities",
        )

        unique_requirements = len({r["requirementId"] for r in rows if r.get("requirementId")})
        summary(f"{len(rows)} activit(ies) listed across {unique_requirements} requirement(s).")

    except typer.Exit:
        raise
    except Exception as e:
        error(f"Error listing project requirements: {e}")
        raise typer.Exit(code=1)


# ---------------------- CREATE COMMAND ---------------------- #
@app.command("create")
def create_project(
    company_id: int = typer.Option(..., "--company-id", "-c", help="Company (scope) ID"),
    label: str = typer.Option(..., "--name", "-n", help="Project name or label"),
    goal: str = typer.Option(..., "--goal", "-g", help="Project goal or purpose"),
    scope: str = typer.Option(..., "--scope", "-s", help="Scope or context of the project"),
    type_id: int = typer.Option(..., "--type-id", "-t", help="Project type ID"),
    start_date: str = typer.Option(None, "--start-date", help="Start date (YYYY-MM-DD)"),
    end_date: str = typer.Option(None, "--end-date", help="End date (YYYY-MM-DD)"),
    estimated_hours: str = typer.Option(None, "--hours", help="Estimated hours"),
    tags: Optional[str] = typer.Option(None, "--tags", help="Comma-separated tags."),
    assets: Optional[str] = typer.Option(None, "--assets", help="Comma-separated asset IDs."),
    requirements: Optional[str] = typer.Option(None, "--requirements", help="Comma-separated requirement IDs."),
):
    """Create a new project in the specified company."""
    info(f"Creating project '{label}' in company {company_id}...")

    def _split_assets(value: Optional[str]) -> Optional[List[int]]:
        """Parse comma-separated asset IDs into a list of ints."""
        if value is None:
            return None
        parsed = []
        for raw in value.split(","):
            raw = raw.strip()
            if not raw:
                continue
            try:
                parsed.append(int(raw))
            except ValueError:
                warning(f"Ignoring invalid asset ID: {raw}")
        return parsed

    def _split_requirements(value: Optional[str]) -> Optional[List[int]]:
        """Parse comma-separated requirement IDs into a list of ints."""
        if value is None:
            return None
        parsed = []
        for raw in value.split(","):
            raw = raw.strip()
            if not raw:
                continue
            try:
                parsed.append(int(raw))
            except ValueError:
                warning(f"Ignoring invalid requirement ID: {raw}")
        return parsed

    mutation = """
    mutation CreateProject($input: CreateProjectInput!) {
      createProject(input: $input) {
        project {
          id
          pid
          label
          goal
          scope
          createdAt
          startDate
          endDate
          estimatedHours
          projectType { id label }
        }
      }
    }
    """

    assets_ids = _split_assets(assets)
    playbooks_ids = _split_requirements(requirements)

    input_data = {
        "companyId": company_id,
        "label": label,
        "goal": goal,
        "scope": scope,
        "typeId": type_id,
        "startDate": start_date,
        "endDate": end_date,
        "estimatedHours": estimated_hours,
        "tags": tags.split(",") if tags else None,
        "assetsIds": assets_ids if assets_ids else None,
        "playbooksIds": playbooks_ids if playbooks_ids else None,
    }
    input_data = {k: v for k, v in input_data.items() if v is not None}

    try:
        data = graphql_request(mutation, {"input": input_data})
        project = data["createProject"]["project"]
        success(f"Project created successfully: ID {project['id']} - {project['label']}")
    except Exception as e:
        error(f"Error creating project: {e}")
        raise typer.Exit(code=1)


# ---------------------- UPDATE COMMAND ---------------------- #
@app.command("update")
def update_project(
    project_id: int = typer.Option(..., "--id", "-i", help="Project ID to update."),
    company_id: int = typer.Option(..., "--company-id", "-c", help="Company ID."),
    label: str = typer.Option(None, "--name", "-n", help="New name or label."),
    goal: str = typer.Option(None, "--goal", "-g", help="Project goal."),
    scope: str = typer.Option(None, "--scope", "-s", help="Scope or context."),
    type_id: int = typer.Option(None, "--type-id", "-t", help="Project type ID."),
    start_date: str = typer.Option(None, "--start-date", help="Start date (YYYY-MM-DD)."),
    end_date: str = typer.Option(None, "--end-date", help="End date (YYYY-MM-DD)."),
    estimated_hours: str = typer.Option(None, "--hours", help="Estimated hours."),
    tags: Optional[str] = typer.Option(None, "--tags", help="Comma-separated list of tags (replaces existing)."),
    assets: Optional[str] = typer.Option(None, "--assets", help="Comma-separated list of asset IDs (replaces existing)."),
    requirements: Optional[str] = typer.Option(None, "--requirements", help="Comma-separated requirement IDs (replaces existing)."),
    add_tags: Optional[str] = typer.Option(None, "--add-tags", help="Comma-separated tags to add."),
    remove_tags: Optional[str] = typer.Option(None, "--remove-tags", help="Comma-separated tags to remove."),
    clear_tags: bool = typer.Option(False, "--clear-tags", help="Remove all tags."),
    add_assets: Optional[str] = typer.Option(None, "--add-assets", help="Comma-separated asset IDs to add."),
    remove_assets: Optional[str] = typer.Option(None, "--remove-assets", help="Comma-separated asset IDs to remove."),
    clear_assets: bool = typer.Option(False, "--clear-assets", help="Remove all assets."),
):
    """Update an existing project."""
    info(f"✏️ Updating project ID {project_id} in company {company_id}...")

    mutation = """
    mutation UpdateProject($input: UpdateProjectInput!) {
      updateProject(input: $input) {
        project {
          id
          label
          goal
          scope
          startDate
          endDate
          estimatedHours
          projectType { id label }
          tags { name }
          assets { id name }
        }
      }
    }
    """

    def _split_csv_str(value: Optional[str]) -> Optional[List[str]]:
        """Split comma-separated strings into list, trimming blanks."""
        if value is None:
            return None
        return [v.strip() for v in value.split(",") if v.strip()]

    def _split_csv_ids(value: Optional[str]) -> Optional[List[int]]:
        """Split comma-separated asset IDs into list of ints."""
        if value is None:
            return None
        items: List[int] = []
        for raw in value.split(","):
            raw = raw.strip()
            if not raw:
                continue
            try:
                items.append(int(raw))
            except ValueError:
                warning(f"Ignoring invalid asset ID: {raw}")
        return items

    # Pre-parse direct replacements
    direct_tags = _split_csv_str(tags)
    direct_assets = _split_csv_ids(assets)
    direct_playbooks = _split_csv_ids(requirements)

    # Determine if we need to fetch current associations for merge-style operations
    needs_merge_tags = any([add_tags, remove_tags, clear_tags]) and direct_tags is None
    needs_merge_assets = any([add_assets, remove_assets, clear_assets]) and direct_assets is None

    current_tags: List[str] = []
    current_assets: List[int] = []
    current_playbooks: List[int] = []

    if needs_merge_tags or needs_merge_assets:
        info("Fetching current tags/assets for merge...")
        fetch_query = """
        query Project($id: ID!, $companyId: ID!) {
          project(id: $id, companyId: $companyId) {
            id
            tags { name }
            assets { id }
            playbooks { id }
          }
        }
        """
        try:
            fetched = graphql_request(fetch_query, {"id": project_id, "companyId": company_id})
            project = fetched.get("project") or {}
            current_tags = [t.get("name") for t in project.get("tags") or [] if t.get("name")]
            # Some APIs return IDs as strings; cast defensively
            for a in project.get("assets") or []:
                aid = a.get("id")
                if aid is None:
                    continue
                try:
                    current_assets.append(int(aid))
                except ValueError:
                    warning(f"Asset ID '{aid}' is not numeric; skipping.")
            for pb in project.get("playbooks") or []:
                pid = pb.get("id")
                if pid is None:
                    continue
                try:
                    current_playbooks.append(int(pid))
                except ValueError:
                    warning(f"Requirement ID '{pid}' is not numeric; skipping.")
        except Exception as fetch_err:
            error(f"Could not fetch current tags/assets: {fetch_err}")
            return

    def _unique_preserve(seq):
        """Remove duplicates while preserving order."""
        seen = set()
        result = []
        for item in seq:
            key = item
            if key in seen:
                continue
            seen.add(key)
            result.append(item)
        return result

    # Start with explicit replacements when provided; otherwise use fetched values
    merged_tags = direct_tags if direct_tags is not None else list(current_tags)
    merged_assets = direct_assets if direct_assets is not None else list(current_assets)
    merged_playbooks = direct_playbooks if direct_playbooks is not None else list(current_playbooks)

    # Apply merge operations for tags
    add_tags_list = _split_csv_str(add_tags) or []
    remove_tags_list = _split_csv_str(remove_tags) or []
    if clear_tags:
        merged_tags = []
    if add_tags_list:
        merged_tags = _unique_preserve([*merged_tags, *add_tags_list])
    if remove_tags_list:
        merged_tags = [t for t in merged_tags if t not in remove_tags_list]

    # Apply merge operations for assets
    add_assets_list = _split_csv_ids(add_assets) or []
    remove_assets_list = _split_csv_ids(remove_assets) or []
    if clear_assets:
        merged_assets = []
    if add_assets_list:
        merged_assets = _unique_preserve([*merged_assets, *add_assets_list])
    if remove_assets_list:
        merged_assets = [a for a in merged_assets if a not in remove_assets_list]

    include_playbooks = direct_playbooks is not None

    include_tags = (
        direct_tags is not None
        or clear_tags
        or bool(add_tags_list)
        or bool(remove_tags_list)
        or needs_merge_tags
    )
    include_assets = (
        direct_assets is not None
        or clear_assets
        or bool(add_assets_list)
        or bool(remove_assets_list)
        or needs_merge_assets
    )

    input_data = {
        "id": project_id,
        "companyId": company_id,
        "label": label,
        "goal": goal,
        "scope": scope,
        "typeId": type_id,
        "startDate": start_date,
        "endDate": end_date,
        "estimatedHours": estimated_hours,
        "tags": merged_tags if include_tags else None,
        "assetsIds": merged_assets if include_assets else None,
        "playbooksIds": merged_playbooks if include_playbooks else None,
    }
    input_data = {k: v for k, v in input_data.items() if v is not None}

    try:
        data = graphql_request(mutation, {"input": input_data})
        project = data["updateProject"]["project"]
        success(f"Project updated successfully: ID {project['id']} - {project['label']}")
    except Exception as e:
        error(f"Error updating project: {e}")
        raise typer.Exit(code=1)


# ---------------------- DELETE COMMAND ---------------------- #
@app.command("delete")
def delete_projects(
    company_id: int = typer.Option(..., "--company-id", "-c", help="Company ID."),
    ids: str = typer.Option(..., "--ids", "-i", "-ids", help="Comma-separated list of project IDs (accepts single ID)."),
    force: bool = typer.Option(False, "--force", help="Skip confirmation prompt."),
):
    """Delete one or more projects by ID, then verify by querying which IDs still exist."""
    project_ids = [int(x.strip()) for x in ids.split(",") if x.strip()]
    info(f"Deleting {len(project_ids)} project(s) from company {company_id}...")

    if not force:
        confirm = typer.confirm(f"Are you sure you want to delete {len(project_ids)} project(s)?")
        if not confirm:
            info("Aborted.")
            raise typer.Exit()

    mutation = """
    mutation BulkDeleteProject($input: BulkDeleteProjectInput!) {
      bulkDeleteProjects(input: $input) {
        clientMutationId
      }
    }
    """
    variables = {"input": {"companyId": company_id, "ids": project_ids}}

    try:
        data = graphql_request(mutation, variables)
        # If API returned errors, graphql_request will raise.
        info(f"Delete request sent for {len(project_ids)} project(s). Verifying...")

    except Exception as e:
        msg = str(e)
        if "Record not found" in msg:
            for pid in project_ids:
                info(f"Project {pid} was not found (likely already deleted).")
            summary(f"Summary: 0 deleted, {len(project_ids)} skipped (already removed).")
            return
        else:
            error(f"Error deleting project(s): {e}")
            summary(f"Summary: 0 deleted, {len(project_ids)} failed.")
            return

    # Optional verification
    verify_query = """
    query projects(
      $page: Int
      $limit: Int
      $params: ProjectSearch!
    ) {
      projects(page: $page, limit: $limit, params: $params) {
        collection { id label }
      }
    }
    """
    verify_vars = {
        "page": 1,
        "limit": len(project_ids),
        "params": {"scopeIdEq": str(company_id), "idIn": [str(pid) for pid in project_ids]},
    }

    try:
        data = graphql_request(verify_query, verify_vars)
        remaining = (data.get("projects") or {}).get("collection") or []
        remaining_ids = {int(p["id"]) for p in remaining if p.get("id")}
        deleted_ids = [pid for pid in project_ids if pid not in remaining_ids]
        failed_ids = [pid for pid in project_ids if pid in remaining_ids]

        for pid in deleted_ids:
            success(f"Deleted project ID {pid}")
        for pid in failed_ids:
            error(f"Failed to delete project ID {pid} (still present)")
        summary(f"Summary: {len(deleted_ids)} deleted, {len(failed_ids)} failed.")

    except Exception as e:
        error(f"Deletion verification failed: {e}")
        summary("Deletion attempted, but verification failed. Try listing the IDs again.")
        raise typer.Exit(code=1)
