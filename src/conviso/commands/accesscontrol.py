"""
Access control command module.
"""

from __future__ import annotations

import typer

from conviso.clients.client_graphql import graphql_request
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


def _confirm_or_abort(message: str, force: bool) -> None:
    if force:
        return
    if not typer.confirm(message, default=False):
        info("Aborted.")
        raise typer.Exit()


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
