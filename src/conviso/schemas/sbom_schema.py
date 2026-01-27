# conviso/schemas/sbom_schema.py
"""
SBOM Schema
-----------
Defines display fields and headers for SBOM components listing.
"""

from typing import Dict, List


class SbomSchema:
    def __init__(self):
        self.display_fields: List[str] = [
            "id",
            "name",
            "version",
            "technology",
            "license",
            "packageManager",
            "issuesBySeverity",
            "asset",
            "assetId",
        ]
        self.display_headers: Dict[str, str] = {
            "id": "ID",
            "name": "Name",
            "version": "Version",
            "technology": "Technology",
            "license": "License",
            "packageManager": "Pkg Manager",
            "issuesBySeverity": "Vulns by Severity",
            "asset": "Asset",
            "assetId": "Asset ID",
        }

    def display_name(self, field: str) -> str:
        return self.display_headers.get(field, field)

    def all_display_fields(self) -> List[str]:
        return list(self.display_fields)


schema = SbomSchema()
