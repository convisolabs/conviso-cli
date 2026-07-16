"""
Authentication commands: login, logout, whoami
"""

import typer
from typing import Optional
from conviso.core.auth import (
    save_api_key,
    delete_credentials,
    is_logged_in,
    get_api_key,
    get_config_dir_path,
)
from conviso.core.output_manager import (
    success,
    error,
    info,
    warning,
)

app = typer.Typer(help="Manage authentication")


@app.command("login")
def login(
    api_key: Optional[str] = typer.Option(
        None,
        "--api-key",
        "-k",
        help="Your Conviso API key (or leave blank to be prompted)"
    )
) -> None:
    """
    Authenticate with Conviso Platform and save your API key securely.

    Your credentials are stored in ~/.config/conviso/credentials
    """
    # Show instructions before prompting
    info("📚 Where to get your API key:")
    info("  1. Go to: https://app.convisoappsec.com/spa/company/[COMPANY_ID]/api-keys")
    info("  2. Click 'Generate New Key'")
    info("  3. Copy the key and paste it below")
    info("")

    # Prompt for API key if not provided via option
    if api_key is None:
        api_key = typer.prompt("API Key", hide_input=True)

    if not api_key or not api_key.strip():
        error("API key cannot be empty")
        raise typer.Exit(1)

    try:
        save_api_key(api_key.strip())
        success("✅ Successfully logged in!")
        info(f"ℹ️  Credentials saved to: {get_config_dir_path()}/credentials")
        info("")
        info("🎯 Next steps:")
        info("  • Verify login: conviso auth whoami")
        info("  • List projects: conviso projects list")
        info("  • See all commands: conviso --help")
    except Exception as e:
        error(f"Failed to save credentials: {str(e)}")
        raise typer.Exit(1)


@app.command("logout")
def logout() -> None:
    """
    Remove stored credentials.

    Logs you out by deleting the saved API key.
    """
    try:
        delete_credentials()
        success("✅ Successfully logged out!")
        info("Stored credentials have been deleted")
    except Exception as e:
        error(f"Failed to delete credentials: {str(e)}")
        raise typer.Exit(1)


@app.command("whoami")
def whoami() -> None:
    """
    Show current authentication status.

    Displays whether you're logged in and where credentials are stored.
    """
    if is_logged_in():
        api_key = get_api_key()
        masked_key = f"{api_key[:10]}...{api_key[-4:]}" if api_key and len(api_key) > 14 else "***"

        success("✅ You are logged in")
        info(f"API Key: {masked_key}")
        info(f"Credentials location: {get_config_dir_path()}/credentials")
    else:
        warning("❌ You are not logged in")
        info("Use 'cvs auth login' to authenticate")
        raise typer.Exit(1)


@app.command("status")
def status() -> None:
    """
    Check authentication status (alias for whoami).
    """
    whoami()
