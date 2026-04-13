"""
Access control command module.
"""

from __future__ import annotations

import os
import typer

from conviso.clients.client_graphql import graphql_request
from conviso.core.bulk_loader import BulkResult, load_csv
from conviso.core.notifier import error, info, success

app = typer.Typer(help="Manage user access control settings.")


def _fetch_user_profile_id(company_id: str, user_id: str) -> str:
    query = """
    query PortalUserProfile($companyId: ID!, $id: ID) {
      portalUserProfile(companyId: $companyId, id: $id) {
        id
        profile(companyId: $companyId) {
          id
        }
      }
    }
    """
    data = graphql_request(query, {"companyId": company_id, "id": user_id})
    portal_user = data.get("portalUserProfile") or {}
    profile = portal_user.get("profile") or {}
    profile_id = profile.get("id")
    if not portal_user:
        raise RuntimeError(f"User {user_id} not found in company {company_id}")
    if not profile_id:
        raise RuntimeError(f"User {user_id} has no access profile in company {company_id}")
    return str(profile_id)


def _parse_team_ids(team_ids: str) -> list[str]:
    parsed = [item.strip() for item in str(team_ids).split(",") if item.strip()]
    if not parsed:
        raise ValueError("Provide at least one team ID in --team-ids, or use --clear.")
    return parsed


def _parse_bool(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y"}


def _confirm_or_abort(message: str, force: bool) -> None:
    if force:
        return
    if not typer.confirm(message, default=False):
        info("Aborted.")
        raise typer.Exit()


def _show_bulk_users_template() -> None:
    typer.echo("Columns for accesscontrol bulk-users CSV:")
    typer.echo("  company_id,user_id,profile_id,team_ids,clear_teams")
    typer.echo("")
    typer.echo("Rules:")
    typer.echo("  - company_id: required")
    typer.echo("  - user_id: required")
    typer.echo("  - profile_id: optional if only changing teams; current profile will be preserved")
    typer.echo("  - team_ids: optional comma-separated team IDs")
    typer.echo("  - clear_teams: optional true/false; when true, removes all teams")
    typer.echo("  - each row must change at least one thing: profile_id, team_ids, or clear_teams=true")
    typer.echo("")
    typer.echo("Example:")
    typer.echo("company_id,user_id,profile_id,team_ids,clear_teams")
    typer.echo('443,123,7,"10,11",false')
    typer.echo("444,456,9,,false")
    typer.echo("445,789,, ,true")


def _prepare_bulk_user_input(row: dict[str, str], rownum: int) -> tuple[dict[str, str | list[str]], str]:
    company_id = (row.get("company_id") or "").strip()
    user_id = (row.get("user_id") or "").strip()
    profile_id = (row.get("profile_id") or "").strip()
    team_ids_raw = row.get("team_ids")
    clear_teams = _parse_bool(row.get("clear_teams"))

    if not company_id:
        raise ValueError("Missing company_id")
    if not user_id:
        raise ValueError("Missing user_id")
    if clear_teams and (team_ids_raw or "").strip():
        raise ValueError("Use team_ids or clear_teams=true, not both")

    has_team_update = clear_teams or bool((team_ids_raw or "").strip())
    if not profile_id and not has_team_update:
        raise ValueError("Row must include profile_id and/or team_ids/clear_teams")

    effective_profile_id = profile_id or _fetch_user_profile_id(company_id, user_id)
    input_data: dict[str, str | list[str]] = {
        "portalUserId": user_id,
        "accessProfileId": effective_profile_id,
        "companyId": company_id,
    }

    action_parts = []
    if profile_id:
        action_parts.append(f"profile={effective_profile_id}")
    else:
        action_parts.append(f"profile={effective_profile_id} (preserved)")

    if clear_teams:
        input_data["teamsIds"] = []
        action_parts.append("teams=clear")
    elif (team_ids_raw or "").strip():
        parsed_team_ids = _parse_team_ids(team_ids_raw)
        input_data["teamsIds"] = parsed_team_ids
        action_parts.append(f"teams={','.join(parsed_team_ids)}")

    return input_data, f"company={company_id} user={user_id} " + " ".join(action_parts)


@app.command("user-profile")
def update_user_profile(
    company_id: str = typer.Option(..., "--company-id", "-c", help="Company ID."),
    user_id: str = typer.Option(..., "--user-id", "-u", help="Portal user ID."),
    profile_id: str = typer.Option(..., "--profile-id", "-p", help="Access profile ID."),
    force: bool = typer.Option(False, "--force", help="Skip confirmation prompt."),
):
    """Change the access profile associated with a user."""
    _confirm_or_abort(
        f"Change access profile for user {user_id} in company {company_id} to profile {profile_id}?",
        force,
    )
    info(f"Updating access profile for user {user_id} in company {company_id}...")

    mutation = """
    mutation UpdateUserAccess($input: UpdatePortalUserAccessInput!) {
      updatePortalUserAccess(input: $input) {
        portalUserAccess {
          portalUser {
            id
          }
        }
      }
    }
    """

    variables = {
        "input": {
            "portalUserId": user_id,
            "accessProfileId": profile_id,
            "companyId": company_id,
        }
    }

    try:
        data = graphql_request(mutation, variables)
        portal_user = ((data.get("updatePortalUserAccess") or {}).get("portalUserAccess") or {}).get("portalUser") or {}
        updated_user_id = portal_user.get("id") or user_id
        success(f"User {updated_user_id} access profile updated successfully to profile {profile_id}")
    except Exception as exc:
        error(f"Error updating user access profile: {exc}")
        raise typer.Exit(code=1)


@app.command("user-teams")
def update_user_teams(
    company_id: str = typer.Option(..., "--company-id", "-c", help="Company ID."),
    user_id: str = typer.Option(..., "--user-id", "-u", help="Portal user ID."),
    team_ids: str = typer.Option(
        None,
        "--team-ids",
        "-t",
        help="Comma-separated team IDs to associate with the user.",
    ),
    clear: bool = typer.Option(False, "--clear", help="Remove all teams from the user."),
    force: bool = typer.Option(False, "--force", help="Skip confirmation prompt."),
):
    """Change the teams associated with a user."""
    if clear and team_ids:
        error("Use either --team-ids or --clear, not both.")
        raise typer.Exit(code=1)
    if not clear and not team_ids:
        error("Provide --team-ids or use --clear.")
        raise typer.Exit(code=1)

    try:
        current_profile_id = _fetch_user_profile_id(company_id, user_id)
        parsed_team_ids = [] if clear else _parse_team_ids(team_ids)
    except ValueError as exc:
        error(str(exc))
        raise typer.Exit(code=1)
    except Exception as exc:
        error(f"Error loading current user access data: {exc}")
        raise typer.Exit(code=1)

    if clear:
        confirm_message = f"Remove all teams from user {user_id} in company {company_id}?"
    else:
        confirm_message = (
            f"Update teams for user {user_id} in company {company_id} "
            f"to: {', '.join(parsed_team_ids)}?"
        )
    _confirm_or_abort(confirm_message, force)

    info(f"Updating teams for user {user_id} in company {company_id}...")

    mutation = """
    mutation UpdateUserAccess($input: UpdatePortalUserAccessInput!) {
      updatePortalUserAccess(input: $input) {
        portalUserAccess {
          portalUser {
            id
          }
        }
      }
    }
    """

    variables = {
        "input": {
            "portalUserId": user_id,
            "accessProfileId": current_profile_id,
            "companyId": company_id,
            "teamsIds": parsed_team_ids,
        }
    }

    try:
        data = graphql_request(mutation, variables)
        portal_user = ((data.get("updatePortalUserAccess") or {}).get("portalUserAccess") or {}).get("portalUser") or {}
        updated_user_id = portal_user.get("id") or user_id
        if clear:
            success(f"All teams removed successfully from user {updated_user_id}")
        else:
            success(f"Teams updated successfully for user {updated_user_id}: {', '.join(parsed_team_ids)}")
    except Exception as exc:
        error(f"Error updating user teams: {exc}")
        raise typer.Exit(code=1)


@app.command("bulk-users")
def bulk_users(
    file: str = typer.Option(None, "--file", "-f", help="Path to CSV file."),
    force: bool = typer.Option(False, "--force", help="Apply changes after dry-run without confirmation."),
    preview_only: bool = typer.Option(False, "--preview-only", help="Run dry-run only and exit without applying."),
    show_template: bool = typer.Option(False, "--show-template", help="Display expected CSV columns and examples, then exit."),
):
    """Bulk update user access profiles and teams via CSV."""
    if show_template:
        _show_bulk_users_template()
        raise typer.Exit()
    if not file:
        error("Missing required option --file. For column layout, run --show-template.")
        raise typer.Exit(code=1)
    if not os.path.isfile(file):
        error(f"File not found: {file}")
        raise typer.Exit(code=1)

    rows = load_csv(file)
    if not rows:
        error("No rows found in CSV.")
        raise typer.Exit(code=1)

    info(f"Loaded {len(rows)} row(s) from {file}.")
    info("Running dry-run (no changes will be applied)...")
    preview = BulkResult()
    prepared_rows: list[tuple[int, dict[str, str | list[str]], str]] = []
    for idx, row in enumerate(rows, start=2):
        try:
            input_data, description = _prepare_bulk_user_input(row, idx)
            typer.echo(f"ℹ️  [dry-run] Row {idx}: {description}")
            prepared_rows.append((idx, input_data, description))
            preview.add_success(idx, "dry-run")
        except Exception as exc:
            preview.add_error(idx, str(exc))
    preview.report()

    if preview_only:
        info("Preview-only mode: no changes applied.")
        raise typer.Exit()
    if preview.errors:
        error("Dry-run found errors. Fix the CSV before applying changes.")
        raise typer.Exit(code=1)

    _confirm_or_abort("Apply bulk user access changes now (run without dry-run)?", force)

    mutation = """
    mutation UpdateUserAccess($input: UpdatePortalUserAccessInput!) {
      updatePortalUserAccess(input: $input) {
        portalUserAccess {
          portalUser {
            id
          }
        }
      }
    }
    """

    info("Applying changes...")
    result = BulkResult()
    for idx, input_data, _ in prepared_rows:
        try:
            graphql_request(mutation, {"input": input_data})
            result.add_success(idx, "ok")
        except Exception as exc:
            result.add_error(idx, str(exc))
    result.report()
