# conviso/schemas/vulnerabilities_schema.py
"""
Vulnerability Schema
--------------------
Defines display fields and headers for vulnerabilities listing.
"""

from typing import Dict, List


class VulnerabilitySchema:
    def __init__(self):
        self.display_fields: List[str] = [
            "id",
            "title",
            "type",
            "status",
            "severity",
            "asset",
            "tags",
            "author",
            "company",
            "attackSurface",
        ]

        self.display_headers: Dict[str, str] = {
            "id": "ID",
            "title": "Title",
            "type": "Type",
            "status": "Status",
            "severity": "Severity",
            "asset": "Asset",
            "tags": "Asset Tags",
            "author": "Author",
            "company": "Company",
            "attackSurface": "Attack Surface",
        }

    def display_name(self, field: str) -> str:
        return self.display_headers.get(field, field)

    def all_display_fields(self) -> List[str]:
        return list(self.display_fields)


schema = VulnerabilitySchema()
