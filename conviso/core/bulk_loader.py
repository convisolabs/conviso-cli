# conviso/core/bulk_loader.py
"""
Bulk Loader
-----------
Shared helpers to ingest CSV files and map columns to payloads for create/update/delete operations.
Supports:
 - CSV input
 - Column mapping (input header -> field key expected by mutation)
 - Dry-run (no mutations)
 - Per-row success/error reporting
"""

import csv
from typing import Callable, Dict, List, Any, Tuple
from conviso.core.notifier import info, success, error, warning, summary


class BulkResult:
    def __init__(self):
        self.successes: List[Tuple[int, str]] = []
        self.errors: List[Tuple[int, str]] = []
        self.skipped: List[Tuple[int, str]] = []

    def add_success(self, rownum: int, msg: str):
        self.successes.append((rownum, msg))

    def add_error(self, rownum: int, msg: str):
        self.errors.append((rownum, msg))

    def add_skip(self, rownum: int, msg: str):
        self.skipped.append((rownum, msg))

    def report(self):
        summary(f"Bulk summary: {len(self.successes)} success, {len(self.errors)} error(s), {len(self.skipped)} skipped.")
        if self.errors:
            for rownum, msg in self.errors:
                error(f"Row {rownum}: {msg}")
        if self.skipped:
            for rownum, msg in self.skipped:
                warning(f"Row {rownum}: {msg}")


def load_csv(path: str) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return [row for row in reader]


def bulk_process(
    rows: List[Dict[str, str]],
    column_map: Dict[str, str],
    op_handler: Callable[[Dict[str, Any], int], None],
    dry_run: bool = False,
) -> BulkResult:
    """
    rows: list of CSV rows (dict)
    column_map: input header -> payload key
    op_handler: function(payload, rownum) to perform create/update/delete
    dry_run: if True, only validate and show what would happen
    """
    result = BulkResult()
    for idx, row in enumerate(rows, start=2):  # header is line 1
        payload: Dict[str, Any] = {}
        for header, target in column_map.items():
            if header in row:
                payload[target] = row[header]
        if dry_run:
            info(f"[dry-run] Row {idx}: {payload}")
            result.add_success(idx, "dry-run")
            continue
        try:
            op_handler(payload, idx)
            result.add_success(idx, "ok")
        except Exception as exc:
            result.add_error(idx, str(exc))
    return result
