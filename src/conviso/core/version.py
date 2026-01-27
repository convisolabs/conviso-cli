"""
Version utilities for Conviso CLI.
 - Reads local VERSION file
 - Optionally checks remote version (can be disabled via env)
 - Compares semver-ish strings safely
"""

import os
from typing import Optional, Tuple
from pathlib import Path

try:
    import requests
except Exception:  # pragma: no cover - defensive; requests is a dependency
    requests = None


VERSION_FILE = Path(__file__).parent.parent / "VERSION"
DEFAULT_REMOTE_URL = "https://raw.githubusercontent.com/convisolabs/conviso-cli/main/src/conviso/VERSION"


def read_local_version() -> str:
    try:
        with open(VERSION_FILE, encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return "0.0.0"


def _parse_version(ver: str) -> Tuple[int, ...]:
    parts = []
    for piece in str(ver).strip().split("."):
        try:
            parts.append(int(piece))
        except Exception:
            # Ignore non-numeric segments; keep comparison lenient
            break
    return tuple(parts)


def is_newer(remote: str, local: str) -> bool:
    if not remote or not local:
        return False
    return _parse_version(remote) > _parse_version(local)


def fetch_remote_version(url: str = DEFAULT_REMOTE_URL, timeout: float = 3.0) -> Optional[str]:
    # Allow overriding via env to support offline environments/tests
    env_ver = os.getenv("CONVISO_CLI_REMOTE_VERSION")
    if env_ver:
        return env_ver.strip()
    if not requests:
        return None
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            return resp.text.strip()
    except Exception:
        return None
    return None


def check_for_updates(
    remote_url: str = DEFAULT_REMOTE_URL,
    skip_env: str = "CONVISO_CLI_SKIP_UPDATE_CHECK",
) -> Tuple[str, Optional[str], bool, bool]:
    """
    Returns (local_version, remote_version, is_outdated, remote_missing)
    """
    if os.getenv(skip_env, "").lower() in {"1", "true", "yes", "y"}:
        return read_local_version(), None, False, False
    local = read_local_version()
    remote = fetch_remote_version(remote_url)
    if not remote:
        return local, None, False, True
    return local, remote, is_newer(remote, local), False
