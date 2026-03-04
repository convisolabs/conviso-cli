"""
Global output preferences
-------------------------
Stores CLI-wide output options configured in app callback.
"""

from typing import Optional, List

REPEAT_HEADER_EVERY = 0
SELECTED_COLUMNS: Optional[List[str]] = None


def set_output_preferences(repeat_header_every: int = 0, columns: Optional[str] = None):
    global REPEAT_HEADER_EVERY, SELECTED_COLUMNS
    REPEAT_HEADER_EVERY = repeat_header_every if repeat_header_every and repeat_header_every > 0 else 0
    if columns:
        parsed = [c.strip() for c in columns.split(",") if c.strip()]
        SELECTED_COLUMNS = parsed or None
    else:
        SELECTED_COLUMNS = None


def get_repeat_header_every() -> int:
    return REPEAT_HEADER_EVERY


def get_selected_columns() -> Optional[List[str]]:
    return SELECTED_COLUMNS

