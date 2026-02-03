# conviso/commands/requirements.py
"""
Requirements Command Module
---------------------------
Lists requirements (playbooks) so users can pick valid IDs for project associations.
"""

import typer
from typing import Optional
from conviso.core.notifier import info, error, success, summary, warning
from conviso.clients.client_graphql import graphql_request
from conviso.core.output_manager import export_data
from conviso.schemas.requirements_schema import schema

app = typer.Typer(help="List requirements/playbooks available in a given scope.")


@app.command("list")
def list_requirements(
    company_id: int = typer.Option(..., "--company-id", "-c", help="Company/Scope ID."),
    page: int = typer.Option(1, "--page", "-p", help="Page number."),
    per_page: int = typer.Option(20, "--per-page", "-l", help="Items per page."),
    label: Optional[str] = typer.Option(None, "--label", help="Filter by label (contains)."),
    only_company: bool = typer.Option(False, "--only-company", help="Only requirements owned by this company."),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table, json, csv."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file for json/csv."),
):
    """List requirements (playbooks) for a scope."""
    info(f"Listing requirements for company {company_id} (page {page}, per_page {per_page})...")

    query = """
    query Requirements($scopeId: Int!, $pagination: BasePaginationInput!, $filters: RequirementsFilterInput) {
      requirements(scopeId: $scopeId, pagination: $pagination, filters: $filters) {
        collection {
          id
          label
          global
          projectType { id label }
          updatedAt
          createdAt
        }
        metadata { totalCount totalPages }
      }
    }
    """

    variables = {
        "scopeId": company_id,
        "pagination": {"page": page, "perPage": per_page},
        "filters": {
            "label": label,
            "onlyFromCompany": only_company or None,
        },
    }

    try:
        data = graphql_request(query, variables)
        reqs = data["requirements"]
        collection = reqs.get("collection") or []
        metadata = reqs.get("metadata") or {}

        if not collection:
            typer.echo("No requirements found.")
            raise typer.Exit()

        rows = []
        for r in collection:
            rows.append({
                "id": r.get("id"),
                "label": r.get("label"),
                "global": r.get("global"),
                "projectTypes": ", ".join(pt.get("label", "") for pt in r.get("projectType") or []),
                "updatedAt": r.get("updatedAt"),
                "createdAt": r.get("createdAt"),
            })

        export_data(
            rows,
            schema=schema,
            fmt=fmt,
            output=output,
            title=f"Requirements (Company {company_id}) - Page {page}/{metadata.get('totalPages')}",
        )
        summary(f"{len(collection)} requirement(s) listed out of {metadata.get('totalCount')}.")

    except Exception as e:
        error(f"Error listing requirements: {e}")


@app.command("project")
def list_project_requirements(
    company_id: int = typer.Option(..., "--company-id", "-c", help="Company/Scope ID."),
    project_id: int = typer.Option(..., "--project-id", "-i", help="Project ID."),
    with_activities: bool = typer.Option(
        True,
        "--with-activities/--no-activities",
        help="Include activities (checks) for each requirement.",
    ),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table, json, csv."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file for json/csv."),
):
    """List requirements (playbooks) associated with a project."""
    info(f"Listing requirements for project {project_id} in company {company_id}...")

    query_with_activities = """
    query ProjectRequirements($id: ID!) {
      project(id: $id) {
        id
        label
        playbooks {
          id
          label
          global
          updatedAt
          createdAt
          check {
            id
            label
            description
            reference
            item
            category
            actionPlan
            sort
          }
        }
      }
    }
    """

    query_requirements_only = """
    query ProjectRequirements($id: ID!) {
      project(id: $id) {
        id
        label
        playbooks {
          id
          label
          global
          updatedAt
          createdAt
        }
      }
    }
    """

    try:
        data = graphql_request(query_with_activities if with_activities else query_requirements_only, {"id": project_id})
        project = data.get("project") or {}
        collection = project.get("playbooks") or []

        if not collection:
            typer.echo("No requirements found for this project.")
            raise typer.Exit()

        rows = []
        if with_activities:
            for r in collection:
                checks = r.get("check") or []
                if not checks:
                    rows.append({
                        "requirementId": r.get("id"),
                        "requirementLabel": r.get("label"),
                        "global": r.get("global"),
                        "updatedAt": r.get("updatedAt"),
                        "createdAt": r.get("createdAt"),
                        "activityId": "",
                        "activityLabel": "",
                        "description": "",
                        "reference": "",
                        "item": "",
                        "category": "",
                        "actionPlan": "",
                        "sort": "",
                    })
                    continue
                for a in checks:
                    rows.append({
                        "requirementId": r.get("id"),
                        "requirementLabel": r.get("label"),
                        "global": r.get("global"),
                        "updatedAt": r.get("updatedAt"),
                        "createdAt": r.get("createdAt"),
                        "activityId": a.get("id"),
                        "activityLabel": a.get("label"),
                        "description": a.get("description"),
                        "reference": a.get("reference"),
                        "item": a.get("item"),
                        "category": a.get("category"),
                        "actionPlan": a.get("actionPlan"),
                        "sort": a.get("sort"),
                    })
        else:
            for r in collection:
                rows.append({
                    "id": r.get("id"),
                    "label": r.get("label"),
                    "global": r.get("global"),
                    "updatedAt": r.get("updatedAt"),
                    "createdAt": r.get("createdAt"),
                })

        export_data(
            rows,
            schema=None,
            fmt=fmt,
            output=output,
            title=f"Requirements (Project {project_id}) - {project.get('label') or ''}".strip(),
        )
        if with_activities:
            summary(f"{len(rows)} activit(ies) listed for project {project_id}.")
        else:
            summary(f"{len(collection)} requirement(s) listed for project {project_id}.")

    except Exception as e:
        error(f"Error listing project requirements: {e}")
        raise typer.Exit(code=1)


@app.command("activities")
def list_requirement_activities(
    company_id: int = typer.Option(..., "--company-id", "-c", help="Company/Scope ID."),
    requirement_id: Optional[int] = typer.Option(None, "--requirement-id", "-r", help="Requirement ID."),
    project_id: Optional[int] = typer.Option(None, "--project-id", "-i", help="Project ID."),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table, json, csv."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file for json/csv."),
):
    """List activities (checks) inside a requirement."""
    if not requirement_id and not project_id:
        error("You must provide either --requirement-id or --project-id.")
        raise typer.Exit(code=1)
    if requirement_id and project_id:
        error("Provide only one of --requirement-id or --project-id.")
        raise typer.Exit(code=1)

    if requirement_id:
        info(f"Listing activities for requirement {requirement_id} in company {company_id}...")
    else:
        info(f"Listing activities for requirements in project {project_id} (company {company_id})...")

    requirement_query = """
    query Requirement($companyId: ID!, $id: ID!) {
      requirement(companyId: $companyId, id: $id) {
        id
        label
        check {
          id
          label
          description
          reference
          item
          category
          actionPlan
          sort
        }
      }
    }
    """

    project_query = """
    query ProjectRequirements($id: ID!) {
      project(id: $id) {
        id
        label
        playbooks {
          id
          label
          check {
            id
            label
            description
            reference
            item
            category
            actionPlan
            sort
          }
        }
      }
    }
    """

    try:
        rows = []
        if requirement_id:
            data = graphql_request(requirement_query, {"companyId": company_id, "id": requirement_id})
            req = data.get("requirement") or {}
            collection = req.get("check") or []

            if not collection:
                typer.echo("No activities found for this requirement.")
                raise typer.Exit()

            for a in collection:
                rows.append({
                    "requirementId": req.get("id"),
                    "requirementLabel": req.get("label"),
                    "id": a.get("id"),
                    "label": a.get("label"),
                    "description": a.get("description"),
                    "reference": a.get("reference"),
                    "item": a.get("item"),
                    "category": a.get("category"),
                    "actionPlan": a.get("actionPlan"),
                    "sort": a.get("sort"),
                })

            export_data(
                rows,
                fmt=fmt,
                output=output,
                title=f"Activities (Requirement {requirement_id}) - {req.get('label') or ''}".strip(),
            )
            summary(f"{len(collection)} activit(ies) listed for requirement {requirement_id}.")
        else:
            data = graphql_request(project_query, {"id": project_id})
            project = data.get("project") or {}
            playbooks = project.get("playbooks") or []

            for req in playbooks:
                checks = req.get("check") or []
                for a in checks:
                    rows.append({
                        "requirementId": req.get("id"),
                        "requirementLabel": req.get("label"),
                        "id": a.get("id"),
                        "label": a.get("label"),
                        "description": a.get("description"),
                        "reference": a.get("reference"),
                        "item": a.get("item"),
                        "category": a.get("category"),
                        "actionPlan": a.get("actionPlan"),
                        "sort": a.get("sort"),
                    })

            if not rows:
                typer.echo("No activities found for this project's requirements.")
                raise typer.Exit()

            export_data(
                rows,
                fmt=fmt,
                output=output,
                title=f"Activities (Project {project_id}) - {project.get('label') or ''}".strip(),
            )
            summary(f"{len(rows)} activit(ies) listed for project {project_id}.")

    except Exception as e:
        error(f"Error listing requirement activities: {e}")
        raise typer.Exit(code=1)


# ---------------------- CREATE COMMAND ---------------------- #
@app.command("create")
def create_requirement(
    company_id: int = typer.Option(..., "--company-id", "-c", help="Company ID."),
    label: str = typer.Option(..., "--label", "-n", help="Requirement label/name."),
    description: str = typer.Option(..., "--description", "-d", help="Requirement description."),
    global_flag: bool = typer.Option(False, "--global", help="Mark as global requirement."),
    activities: Optional[list[str]] = typer.Option(
        None,
        "--activity",
        "-a",
        help="Activity in format 'label|description|typeId|reference|item|category|actionPlan|templateId|sort'. Omit trailing fields if not needed.",
    ),
):
    """Create a requirement (playbook)."""
    info(f"Creating requirement '{label}' for company {company_id}...")

    mutation = """
    mutation CreateOrUpdateRequirement($input: RequirementInput!) {
      createOrUpdateRequirement(input: $input) {
        requirement {
          id
          label
          global
        }
      }
    }
    """

    def _parse_activities(raw_list: Optional[list[str]]):
        if not raw_list:
            return []
        parsed = []
        for raw in raw_list:
            parts = [p.strip() for p in raw.split("|")]
            if len(parts) < 2:
                warning(f"Ignoring activity (expected at least label|description): {raw}")
                continue
            act = {
                "label": parts[0],
                "description": parts[1],
            }
            # Optional fields by position
            if len(parts) > 2 and parts[2]:
                try:
                    act["typeId"] = int(parts[2])
                except ValueError:
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
                except ValueError:
                    warning(f"Ignoring invalid vulnerabilityTemplateId in activity: {parts[7]}")
            if len(parts) > 8 and parts[8]:
                act["sort"] = parts[8]
            parsed.append(act)
        return parsed

    activities_payload = _parse_activities(activities)

    input_data = {
        "companyId": company_id,
        "label": label,
        "description": description,
        "type": "Procedures",  # default type as requested
        "global": global_flag or None,
        "activities": activities_payload,  # API fails on nil activities; send at least empty list
    }
    input_data = {k: v for k, v in input_data.items() if v is not None}

    try:
        data = graphql_request(mutation, {"input": input_data})
        req = data["createOrUpdateRequirement"]["requirement"]
        success(f"Requirement created: ID {req.get('id')} - {req.get('label')}")
    except Exception as e:
        error(f"Error creating requirement: {e}")
        raise typer.Exit(code=1)


# ---------------------- UPDATE COMMAND ---------------------- #
@app.command("update")
def update_requirement(
    requirement_id: int = typer.Option(..., "--id", "-i", help="Requirement ID to update."),
    company_id: int = typer.Option(..., "--company-id", "-c", help="Company ID."),
    label: Optional[str] = typer.Option(None, "--label", "-n", help="New label."),
    description: Optional[str] = typer.Option(None, "--description", "-d", help="New description."),
    global_flag: Optional[bool] = typer.Option(None, "--global", help="Set global flag."),
    activities: Optional[list[str]] = typer.Option(
        None,
        "--activity",
        "-a",
        help="Activity in format 'label|description|typeId|reference|item|category|actionPlan|templateId|sort'. Omit trailing fields if not needed.",
    ),
):
    """Update an existing requirement."""
    info(f"Updating requirement ID {requirement_id} for company {company_id}...")

    mutation = """
    mutation CreateOrUpdateRequirement($input: RequirementInput!) {
      createOrUpdateRequirement(input: $input) {
        requirement {
          id
          label
          global
        }
      }
    }
    """

    def _parse_activities(raw_list: Optional[list[str]]):
        if raw_list is None:
            return None
        parsed = []
        for raw in raw_list:
            parts = [p.strip() for p in raw.split("|")]
            if len(parts) < 2:
                warning(f"Ignoring activity (expected at least label|description): {raw}")
                continue
            act = {"label": parts[0], "description": parts[1]}
            if len(parts) > 2 and parts[2]:
                try:
                    act["typeId"] = int(parts[2])
                except ValueError:
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
                except ValueError:
                    warning(f"Ignoring invalid vulnerabilityTemplateId in activity: {parts[7]}")
            if len(parts) > 8 and parts[8]:
                act["sort"] = parts[8]
            parsed.append(act)
        return parsed

    activities_payload = _parse_activities(activities)

    # Fetch current requirement when required fields are missing
    current_label = None
    current_description = None
    current_global = None
    current_activities = None
    if label is None or description is None or global_flag is None:
        fetch_query = """
        query Requirement($companyId: ID!, $id: ID!) {
          requirement(companyId: $companyId, id: $id) {
            id
            label
            description
            global
            check {
              id
              label
              description
              reference
              item
              category
              actionPlan
              sort
            }
          }
        }
        """
        try:
            fetched = graphql_request(fetch_query, {"companyId": company_id, "id": requirement_id}, log_request=False)
            req_data = fetched.get("requirement") or {}
            current_label = req_data.get("label")
            current_description = req_data.get("description")
            current_global = req_data.get("global")
            current_activities = req_data.get("check")
        except Exception as fetch_err:
            error(f"Could not fetch existing requirement to fill missing fields: {fetch_err}")
            return

    final_label = label if label is not None else current_label
    final_description = description if description is not None else current_description
    final_global = global_flag if global_flag is not None else current_global
    final_activities = activities_payload if activities_payload is not None else current_activities or []

    if final_label is None or final_description is None:
        error("Label and description are required; could not resolve missing values.")
        raise typer.Exit(code=1)

    input_data = {
        "id": requirement_id,
        "companyId": company_id,
        "label": final_label,
        "description": final_description,
        "global": final_global,
        "activities": final_activities or [],  # API fails on nil activities; send empty list by default
    }
    input_data = {k: v for k, v in input_data.items() if v is not None}

    try:
        data = graphql_request(mutation, {"input": input_data})
        req = data["createOrUpdateRequirement"]["requirement"]
        success(f"Requirement updated: ID {req.get('id')} - {req.get('label')}")
    except Exception as e:
        error(f"Error updating requirement: {e}")
        raise typer.Exit(code=1)


# ---------------------- DELETE COMMAND ---------------------- #
@app.command("delete")
def delete_requirement(
    requirement_id: int = typer.Option(..., "--id", "-i", help="Requirement ID to delete."),
    force: bool = typer.Option(False, "--force", help="Skip confirmation prompt."),
):
    """Delete a requirement by ID."""
    info(f"Deleting requirement ID {requirement_id}...")

    if not force:
        confirm = typer.confirm(f"Are you sure you want to delete requirement {requirement_id}?")
        if not confirm:
            info("Aborted.")
            raise typer.Exit()

    mutation = """
    mutation DeleteRequirement($input: DeleteRequirementInput!) {
      deleteRequirement(input: $input) {
        requirement { id }
      }
    }
    """
    variables = {"input": {"requirementId": requirement_id}}

    try:
        data = graphql_request(mutation, variables)
        deleted = ((data.get("deleteRequirement") or {}).get("requirement") or {}).get("id")
        if deleted:
            success(f"Deleted requirement ID {deleted}")
        else:
            warning("Delete request sent but no requirement returned.")
    except Exception as e:
        error(f"Error deleting requirement: {e}")
        raise typer.Exit(code=1)
