"""
Authentication management for Conviso CLI.

Stores API keys securely in ~/.config/conviso/credentials
"""

import os
import json
from pathlib import Path
from typing import Optional


def get_config_dir() -> Path:
    """Get the Conviso config directory, creating it if necessary."""
    config_dir = Path.home() / ".config" / "conviso"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def get_credentials_file() -> Path:
    """Get the path to the credentials file."""
    return get_config_dir() / "credentials"


def get_api_key() -> Optional[str]:
    """
    Get API key from (in order of priority):
    1. CONVISO_API_KEY environment variable
    2. .env file in current directory
    3. ~/.config/conviso/credentials file
    """
    # Check environment variable first
    api_key = os.getenv("CONVISO_API_KEY")
    if api_key:
        return api_key

    # Check .env file in current directory
    env_file = Path.cwd() / ".env"
    if env_file.exists():
        try:
            with open(env_file) as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("CONVISO_API_KEY="):
                        api_key = line.split("=", 1)[1].strip('"\'')
                        if api_key:
                            return api_key
        except Exception:
            pass

    # Check stored credentials
    creds_file = get_credentials_file()
    if creds_file.exists():
        try:
            with open(creds_file) as f:
                creds = json.load(f)
                return creds.get("api_key")
        except Exception:
            pass

    return None


def save_api_key(api_key: str) -> None:
    """Save API key to credentials file."""
    creds_file = get_credentials_file()
    creds_file.parent.mkdir(parents=True, exist_ok=True)

    # Make file readable only by owner (600 permissions)
    creds_file.touch(mode=0o600)

    with open(creds_file, "w") as f:
        json.dump({"api_key": api_key}, f, indent=2)

    # Ensure secure permissions
    creds_file.chmod(0o600)


def delete_credentials() -> None:
    """Delete saved credentials."""
    creds_file = get_credentials_file()
    if creds_file.exists():
        creds_file.unlink()


def is_logged_in() -> bool:
    """Check if user is logged in (has valid API key)."""
    return get_api_key() is not None


def get_config_dir_path() -> str:
    """Get config directory path as string."""
    return str(get_config_dir())
