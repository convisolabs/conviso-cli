# conviso/commands/projects.py
"""
Projects Command Module
-----------------------
Implements CLI commands to interact with Conviso Platform projects.

Columns shown:
  ID | Name | Project Type | Status | Requirements | Associated Assets | Created at | Start Date | End Date | Tags
"""

import typer
from typing import Optional, List

from conviso.clients.client_graphql import graphql_request
from conviso.core.schema_alias import registry
from conviso.core.output_manager import export_data
from conviso.core.doc_generator import generate_schema_doc
from conviso.core.logger import log
from conviso.schemas.projects_schema import schema

app = typer.Typer(help="Manage and search projects in Conviso Platform.")


# ------------------ Autocomplete Helpers ------------------ #

def autocomplete_filters(ctx: typer.Context, incomplete: str):
    """Autocomplete for --filter key=val pairs (supports aliases)."""
    all_fields = set(schema.all_search_fields()) | set(schema.all_aliases().keys())
    return [f for f in sorted(all_fields) if f.startswith(incomplete)]


def autocomplete_sort(ctx: typer.Context, incomplete: str):
    """Autocomplete for --sort-by with displayable (raw) fields."""
    return [f for f in schema.all_sortable_fields() if f.startswith(incomplete)]


# ------------------ List Command ------------------ #

@app.command("list")
def list_projects(
    company_id: int = typer.Option(..., "--company-id", "-c", help="Company ID (required)"),
    filters: Optional[List[str]] = typer.Option(
        None,
        "--filter",
        "-f",
        help="Apply filters in 'field=value' format. Supports aliases (e.g., id=123, name=foo, status=DONE).",
        autocompletion=autocomplete_filters,
    ),
    sort_by: Optional[str] = typer.Option(
        None,
        "--sort-by",
        "-s",
        help="Sort results by a field (e.g. createdAt, label, startDate, endDate).",
        autocompletion=autocomplete_sort,
    ),
    descending: bool = typer.Option(False, "--desc", help="Sort in descending order."),
    page: int = typer.Option(1, "--page", "-p", help="Page number."),
    limit: int = typer.Option(50, "--limit", "-l", help="Items per page."),
    fmt: str = typer.Option("table", "--format", help="Output format: table, csv, json."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path (for CSV/JSON export)."),
):
    """
    List projects for a given company using GraphQL + ProjectSearch filters.
    """
    # Build ProjectSearch params
    params = {"scopeIdEq": company_id}

    if filters:
        for f in filters:
            if "=" not in f:
                log(f"[WARN] Invalid filter syntax: {f} (expected key=value)")
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

    # GraphQL: fetch only what we need for the 10 definitive columns
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

    data = graphql_request(query, variables)
    projects = data["projects"]["collection"]

    if not projects:
        typer.echo("No projects found.")
        raise typer.Exit()

    log(f"Received {len(projects)} projects")

    # Flatten to the exact 10 columns
    rows = []
    for p in projects:
        done = (p.get("requirementsProgress") or {}).get("done", 0)
        total = (p.get("requirementsProgress") or {}).get("total", 0)
        requirements = f"{done}/{total}"

        assets = p.get("assets") or []
        assets_count = len(assets)

        tags_list = p.get("tags") or []
        tags_str = ", ".join(t.get("name", "") for t in tags_list if t and t.get("name"))

        row = {
            "id": p.get("id") or "",
            "label": p.get("label") or "",
            "projectType.label": (p.get("projectType") or {}).get("label", "") or "",
            "status": p.get("status") or "",
            "requirements": requirements,
            "assetsCount": assets_count,
            "createdAt": p.get("createdAt") or "",
            "startDate": p.get("startDate") or "",
            "endDate": p.get("endDate") or "",
            "tags": tags_str,
        }
        rows.append(row)

    # Fixed column order + headers from schema
    cols = schema.all_display_fields()
    headers = [schema.display_name(c) for c in cols]

    # Repackage with user-friendly headers for export/output
    export_rows = []
    for r in rows:
        export_rows.append({schema.display_name(k): r.get(k, "") for k in cols})

    export_data(export_rows, headers, fmt, output)

# ------------------ Delete Command ------------------ #
@app.command("delete")
def delete_projects(
    company_id: int = typer.Option(..., "--company-id", "-c", help="Company (scope) ID"),
    ids: str = typer.Option(..., "--ids", "-i", help="Comma-separated list of project IDs to delete"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation prompt"),
):
    """
    Delete one or more projects by ID (requires company ID for scope validation).
    """

    id_list = [int(x.strip()) for x in ids.split(",") if x.strip()]
    if not id_list:
        typer.echo("❌ No project IDs provided.")
        raise typer.Exit()

    log(f"Preparing to delete {len(id_list)} project(s) for company {company_id}...")

    if not force:
        confirm = typer.confirm(f"Are you sure you want to delete {len(id_list)} project(s)?")
        if not confirm:
            typer.echo("🛑 Operation cancelled.")
            raise typer.Exit()

    mutation = """
    mutation BulkDeleteProject($input: BulkDeleteProjectInput!) {
      bulkDeleteProjects(input: $input) {
        clientMutationId
      }
    }
    """

    # ✅ Include companyId in the input
    variables = {"input": {"companyId": company_id, "ids": id_list}}

    log("Sending GraphQL mutation to delete projects...")
    data = graphql_request(mutation, variables)

    typer.echo(f"✅ Successfully deleted {len(id_list)} project(s) for company {company_id}")


# ------------------ Documentation ------------------ #

@app.command("doc")
def generate_doc():
    """Generate CLI documentation for the project schema (fields & filters)."""
    doc = generate_schema_doc(schema)
    typer.echo(doc)


# ------------------ Registration ------------------ #

def register(app_ref: typer.Typer):
    """Register this command under the main Typer app."""
    log("Registering command: projects")
    app_ref.add_typer(app, name="projects")
