# conviso/core/schema_alias.py
from typing import Dict, List, Optional
from conviso.core.logger import log

class SchemaField:
    """Represents a filterable field within a schema."""
    def __init__(self, alias: str, gql_field: str, description: str, field_type: str = "string"):
        self.alias = alias
        self.gql_field = gql_field
        self.description = description
        self.field_type = field_type

class SchemaAlias:
    """Manages alias mapping and metadata for a given GraphQL object type."""
    def __init__(self, name: str, fields: List[SchemaField], display_columns: Dict[str, str]):
        self.name = name
        self.fields = {f.alias: f for f in fields}
        self.display_columns = display_columns

    def resolve_field(self, key: str) -> str:
        """Resolve a user-friendly alias (e.g. 'label') into a GraphQL field."""
        if key in self.fields:
            gql = self.fields[key].gql_field
            log(f"Applied alias: '{key}' → '{gql}'", "green")
            return gql
        log(f"Warning: Filter '{key}' not found in schema '{self.name}'", "yellow")
        return key

    def available_fields(self) -> List[str]:
        """Return all available aliases for autocompletion and docs."""
        return list(self.fields.keys())

    def describe_field(self, key: str) -> Optional[str]:
        """Return the description for a specific alias."""
        return self.fields[key].description if key in self.fields else None

    def display_name(self, key: str) -> str:
        """Return human-readable column name for table rendering."""
        return self.display_columns.get(key, key)

class SchemaRegistry:
    """Holds and manages all registered schemas for the CLI."""
    def __init__(self):
        self._schemas: Dict[str, SchemaAlias] = {}

    def register(self, schema: SchemaAlias):
        self._schemas[schema.name] = schema

    def get(self, name: str) -> Optional[SchemaAlias]:
        return self._schemas.get(name)

registry = SchemaRegistry()
