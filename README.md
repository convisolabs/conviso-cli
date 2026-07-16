# Conviso CLI

CLI to interact with Conviso Platform via GraphQL.

**📖 Full documentation:** https://docs.convisoappsec.com/new-cli

## Development

### Project Structure

- `src/conviso/app.py` — Typer entrypoint; registers subcommands
- `src/conviso/commands/` — CLI commands (projects, assets, requirements, vulnerabilities, auth, etc.)
- `src/conviso/clients/` — API clients (GraphQL)
- `src/conviso/core/` — Shared utilities (logging, output manager, auth)
- `src/conviso/schemas/` — Table schemas for consistent output

### Adding a New Command

1. Create `src/conviso/commands/<name>.py` with a `typer.Typer()` and subcommands
2. Register it in `src/conviso/app.py` via `app.add_typer(...)`
3. If you need tabular output, add a schema in `src/conviso/schemas/<name>_schema.py`
4. Use `graphql_request` from `conviso.clients.client_graphql` (enforces API key and timeout)
5. Ensure errors raise `typer.Exit(code=1)` for CI/automation

### Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
