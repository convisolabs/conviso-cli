# conviso/schemas/projects_schema.py
"""
Project Schema
---------------
Defines the display and search schemas for Project data, matching the UI table:

Columns:
  - ID
  - Name
  - Project Type
  - Status
  - Requirements (done/total)
  - Associated Assets (count)
  - Created at
  - Start Date
  - End Date
  - Tags
"""

from typing import Dict, List, Any


class ProjectSchema:
    """
    Field aliases for display and utilities for:
      - Display name resolution
      - Filter alias resolution
      - Basic type casting for filter values
      - CLI help/autocomplete
    """

    def __init__(self):
        # EXACT display fields & order expected by the table
        self.display_fields: List[str] = [
            "id",
            "label",
            "projectType.label",
            "status",
            "requirements",
            "assets",
            "createdAt",
            "startDate",
            "endDate",
            "tags",
        ]

        # Map raw keys to user-friendly column headers
        self.display_headers: Dict[str, str] = {
            "id": "ID",
            "label": "Name",
            "projectType.label": "Project Type",
            "status": "Status",
            "requirements": "Requirements",
            "assets": "Associated Assets",
            "createdAt": "Created at",
            "startDate": "Start Date",
            "endDate": "End Date",
            "tags": "Tags",
        }

        # GraphQL ProjectSearch fields (backed by your schema)
        self.search_fields: Dict[str, str] = {
            "createdAtGteq": "Created At >= date",
            "createdAtLteq": "Created At <= date",
            "endDateGteq": "End Date >= date",
            "endDateLteq": "End Date <= date",
            "endDateCont": "End Date contains value",
            "endDateEq": "End Date = date",
            "endDate": "End Date (raw)",
            "labelCont": "Name contains string",
            "labelEq": "Name = exact match",
            "idEq": "Project ID = value",
            "idIn": "Project ID in list",
            "projectStatusLabelCont": "Status contains string",
            "projectStatusLabelEq": "Status = exact match",
            "projectStatusLabelIn": "Status in list",
            "projectTypeLabelCont": "Project Type contains string",
            "projectTypeLabelEq": "Project Type = exact match",
            "projectTypeLabelIn": "Project Type in list",
            "apiCodeEq": "API Code = exact match",
            "startDateGteq": "Start Date >= date",
            "startDateLteq": "Start Date <= date",
            "startDate": "Start Date (raw)",
            "startDateEq": "Start Date = date",
            "startDateCont": "Start Date contains value",
            "tagNameEq": "Tag = exact match",
            "scopeLabelCont": "Scope label contains string",
            "scopeIdEq": "Scope ID = value (Company ID)",
            "search": "Free text search",
            "engagementTypes": "Engagement types (array)",
            "engagementStatuses": "Engagement statuses (array)",
            "tags": "Tag list",
            "teams": "Team IDs",
            "showHidden": "Include hidden projects",
            "pendingRequirements": "Has pending requirements",
            "environmentCompromised": "Environment compromised",
        }

        # CLI aliases → GraphQL filters
        self.alias_map: Dict[str, str] = {
            "id": "idEq",
            "name": "labelCont",
            "label": "labelCont",
            "status": "projectStatusLabelEq",
            "type": "projectTypeLabelEq",
            "tag": "tagNameEq",
            "scope": "scopeIdEq",
            "created_after": "createdAtGteq",
            "created_before": "createdAtLteq",
            "start_after": "startDateGteq",
            "start_before": "startDateLteq",
        }

        # Primitive casters by key (only what differs from string)
        self._int_like = {"idEq"}
        self._id_like = {"scopeIdEq"}
        self._int_list = {"engagementTypes", "engagementStatuses", "teams"}
        self._str_list = {"idIn", "projectStatusLabelIn", "projectTypeLabelIn", "tags"}

        # Sortable raw fields accepted by API's sortBy
        self.sortable_fields: List[str] = [
            "createdAt",
            "startDate",
            "endDate",
            "label",
            "status",
        ]

    # -------------- Display helpers -------------- #

    def display_name(self, field: str) -> str:
        """Return user-friendly column header for a given field."""
        return self.display_headers.get(field, field)

    def all_display_fields(self) -> List[str]:
        """Return exact ordered list of display fields."""
        return list(self.display_fields)

    # -------------- Filters / aliases -------------- #

    def resolve_filter_key(self, key: str) -> str:
        """Resolve CLI alias (e.g., 'name') to real GraphQL field (e.g., 'labelCont')."""
        return self.alias_map.get(key, key)

    def all_search_fields(self) -> List[str]:
        """Return all available ProjectSearch filter keys."""
        return list(self.search_fields.keys())

    def all_aliases(self) -> Dict[str, str]:
        """Return alias → GraphQL map."""
        return dict(self.alias_map)

    # -------------- Casting -------------- #

    def cast_filter_value(self, key: str, value: str) -> Any:
        """
        Cast filter values to expected primitive types:
          - ints for idEq, etc.
          - lists for idIn, projectStatusLabelIn, ...
          - IDs (kept as str) for scopeIdEq
        """
        if key in self._int_like:
            try:
                return int(value)
            except Exception:
                return value  # keep raw; API will validate

        if key in self._id_like:
            # Scope ID (Company ID) is an opaque ID; keep string
            return value

        if key in self._int_list:
            try:
                return [int(x.strip()) for x in value.split(",") if x.strip()]
            except Exception:
                return value

        if key in self._str_list:
            return [x.strip() for x in value.split(",") if x.strip()]

        # default: leave as string
        return value

    # -------------- Sorting -------------- #

    def all_sortable_fields(self) -> List[str]:
        """Fields allowed in sortBy."""
        return list(self.sortable_fields)


# Singleton instance
schema = ProjectSchema()
