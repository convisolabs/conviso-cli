# Contributing to Conviso CLI

Thanks for your interest in contributing! Below is a quick guide to help you get started.

## Branching
- Use descriptive branch names. Suggested patterns:
  - `feature/<slug>` (e.g., `feature/bulk-vulns`)
  - `fix/<slug>` (e.g., `fix/asset-list-pagination`)
  - `chore/<slug>` or `docs/<slug>` for maintenance/docs
- If you want to enforce patterns in GitHub branch protection, use:
  - `feature/**`, `fix/**`, `chore/**`, `docs/**`

## Setup
1. Python 3.9+.
2. Install deps:
   ```
   pip install -r requirements.txt  # if present
   ```
3. Create a `.env` with `CONVISO_API_KEY=<your-key>` (and optionally `CONVISO_API_TIMEOUT=30`).

## Running
- CLI entrypoint:
  ```
  python -m conviso.app --help
  ```
- Use `--quiet` to silence info logs, `--verbose` to show per-page requests when paginating.

## Testing / Lint (if available)
- Run lint/tests if configured (e.g., `pytest`, `ruff`, `black`). If not present, ensure code runs and commands work (list/create/update/delete/bulk).

## Code style
- Raise `typer.Exit(code=1)` on errors.
- Use schemas for table output and keep enums validated where possible.
- Prefer clear help strings with expected enum values.
- Keep CSV bulk helpers consistent: dry-run first, confirm/apply, `--force` and `--preview-only`.

## Pull Requests
- Include a clear description of the change and how to test it.
- If adding commands or bulk flows, update README and samples if needed.
- If touching bulk, ensure `--show-template` output stays consistent.

## Releases
- Versions follow [SemVer](https://semver.org) (`MAJOR.MINOR.PATCH`) and live in `src/conviso/VERSION`.
- Release tags use the `vX.Y.Z` format (e.g., `v0.5.1`) and must match `VERSION` without the `v`.
- Pushing a release tag runs the tests and publishes the package to PyPI:
  ```
  git tag v0.5.1
  git push origin v0.5.1
  ```
- Tags in any other format do not trigger a release.

## Reporting issues
- Provide command run, options used, expected vs. actual behavior, and any GraphQL errors returned.
