"""
Project Types Schema
--------------------
Defines display fields and headers for project type listing.
"""

from typing import Dict, List


class ProjectTypesSchema:
    def __init__(self):
        self.display_fields: List[str] = [
            "id",
            "label",
            "description",
        ]

        self.display_headers: Dict[str, str] = {
            "id": "ID",
            "label": "Label",
            "description": "Description",
        }

    def display_name(self, field: str) -> str:
        return self.display_headers.get(field, field)

    def all_display_fields(self) -> List[str]:
        return list(self.display_fields)


schema = ProjectTypesSchema()
