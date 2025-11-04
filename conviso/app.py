# conviso/app.py
import typer
from conviso.commands.projects import register as register_projects
from conviso.core.logger import log

# ✅ Import all schemas explicitly to ensure registration happens at startup
import conviso.schemas.projects_schema  # Add future schemas here as well

app = typer.Typer(help="Conviso Platform CLI - interact with GraphQL API")

# Register CLI modules
register_projects(app)

if __name__ == "__main__":
    log("Starting Conviso CLI...")
    app()
