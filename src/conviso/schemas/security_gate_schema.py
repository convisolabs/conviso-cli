# conviso/schemas/security_gate_schema.py
"""
Security Gate Schema
--------------------
Defines display fields and headers for the security gate JSON output.
"""

from typing import Dict, List


class SecurityGateSchema:
    def __init__(self):
        self.display_fields: List[str] = [
            "severity",
            "count",
            "limit",
            "status",
        ]

        self.display_headers: Dict[str, str] = {
            "severity": "Severity",
            "count": "Count",
            "limit": "Limit",
            "status": "Status",
        }

    def display_name(self, field: str) -> str:
        return self.display_headers.get(field, field)

    def all_display_fields(self) -> List[str]:
        return list(self.display_fields)


schema = SecurityGateSchema()
