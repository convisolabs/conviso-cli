# conviso/core/doc_generator.py
from conviso.core.schema_alias import registry
from rich.console import Console
from rich.table import Table

console = Console()

def generate_schema_doc(schema_name: str):
    """Displays available filters for a given schema."""
    schema = registry.get(schema_name)
    if not schema:
        console.print(f"[red]Schema '{schema_name}' not found[/red]")
        return

    table = Table(title=f"Available filters for schema: {schema_name}")
    table.add_column("Alias", style="cyan")
    table.add_column("GraphQL Field", style="green")
    table.add_column("Description", style="white")
    table.add_column("Type", style="yellow")

    for field in schema.fields.values():
        table.add_row(field.alias, field.gql_field, field.description, field.field_type)
    console.print(table)
