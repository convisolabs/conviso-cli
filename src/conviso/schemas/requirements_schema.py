# conviso/schemas/requirements_schema.py
"""
Requirement Schema
------------------
Defines display fields and headers for requirements listing.
"""

from typing import Dict, List


class RequirementSchema:
    def __init__(self):
        self.display_fields: List[str] = [
            "id",
            "label",
            "global",
            "projectTypes",
            "updatedAt",
            "createdAt",
        ]

        self.display_headers: Dict[str, str] = {
            "id": "ID",
            "label": "Label",
            "global": "Global",
            "projectTypes": "Project Types",
            "updatedAt": "Updated At",
            "createdAt": "Created At",
        }

    def display_name(self, field: str) -> str:
        return self.display_headers.get(field, field)

    def all_display_fields(self) -> List[str]:
        return list(self.display_fields)


schema = RequirementSchema()
