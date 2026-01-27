# conviso/schemas/assets_schema.py
"""
Asset Schema
------------
Defines the structure and display behavior for Asset data in CLI tables.

This schema mirrors ProjectSchema, so both commands share the same
table rendering logic and conventions.
"""

from typing import Dict, List


class AssetSchema:
    """
    Provides:
      - Display fields and headers for consistent table rendering
      - (Future) alias support for filtering or sorting
    """

    def __init__(self):
        # --- Fields in the exact order to appear in CLI tables ---
        self.display_fields: List[str] = [
            "id",
            "name",
            "riskScore.current.value",
            "openVulnerabilities",
            "businessImpact",
            "dataClassification",
            "exploitability",
            "environmentCompromised",
            "assetsTagList",
            "integrations",
            "updatedAt",
        ]

        # --- User-facing headers for each field ---
        self.display_headers: Dict[str, str] = {
            "id": "ID",
            "name": "Name",
            "riskScore.current.value": "Risk Score",
            "openVulnerabilities": "Open Vulnerabilities",
            "businessImpact": "Business Impact",
            "dataClassification": "Data Classification",
            "exploitability": "Attack Surface",
            "environmentCompromised": "Env. Compromised",
            "assetsTagList": "Tags",
            "integrations": "Integrations",
            "updatedAt": "Last Updated",
        }

        # --- Sortable fields (optional, for later use) ---
        self.sortable_fields: List[str] = [
            "name",
            "businessImpact",
            "dataClassification",
            "updatedAt",
        ]

    def display_name(self, field: str) -> str:
        """Return a user-friendly header name."""
        return self.display_headers.get(field, field)

    def all_display_fields(self) -> List[str]:
        """Return ordered display field list."""
        return list(self.display_fields)


# Singleton instance (used by commands)
schema = AssetSchema()
