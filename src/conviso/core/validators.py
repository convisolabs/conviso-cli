"""
Input validators for fixed CLI choices.
"""

from __future__ import annotations

import difflib
from typing import Iterable, Optional, List


def _suggest(value: str, allowed: Iterable[str]) -> Optional[str]:
    options = sorted({str(a).upper() for a in allowed})
    matches = difflib.get_close_matches(str(value).upper(), options, n=1, cutoff=0.6)
    return matches[0] if matches else None


def validate_choice(value: Optional[str], allowed: Iterable[str], param_name: str) -> Optional[str]:
    """
    Validate a single fixed choice (case-insensitive) and return normalized upper value.
    Raises ValueError with user-friendly guidance.
    """
    if value is None:
        return None
    up = str(value).strip().upper()
    allowed_set = {str(a).upper() for a in allowed}
    if up in allowed_set:
        return up
    hint = _suggest(up, allowed_set)
    if hint:
        raise ValueError(
            f"Invalid value for {param_name}: '{value}' (did you mean '{hint}'?). "
            f"Allowed values: {', '.join(sorted(allowed_set))}"
        )
    raise ValueError(
        f"Invalid value for {param_name}: '{value}'. "
        f"Allowed values: {', '.join(sorted(allowed_set))}"
    )


def validate_csv_choices(value: Optional[str], allowed: Iterable[str], param_name: str) -> Optional[List[str]]:
    """
    Validate comma-separated fixed choices (case-insensitive) and return normalized upper list.
    Raises ValueError with user-friendly guidance.
    """
    if not value:
        return None
    allowed_set = {str(a).upper() for a in allowed}
    parts = [p.strip() for p in str(value).split(",") if p.strip()]
    normalized: List[str] = []
    invalid: List[str] = []
    hints: List[str] = []
    for part in parts:
        up = part.upper()
        if up in allowed_set:
            normalized.append(up)
            continue
        invalid.append(part)
        maybe = _suggest(up, allowed_set)
        if maybe:
            hints.append(f"'{part}' (did you mean '{maybe}'?)")
        else:
            hints.append(f"'{part}'")
    if invalid:
        raise ValueError(
            f"Invalid value(s) for {param_name}: {', '.join(hints)}. "
            f"Allowed values: {', '.join(sorted(allowed_set))}"
        )
    return normalized or None

