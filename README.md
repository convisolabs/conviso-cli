# Conviso CLI

CLI to interact with Conviso Platform via GraphQL.

## Requirements
- Python 3.10+ (`typer`, `rich`, `requests`, `python-dotenv`)
- Environment variable `CONVISO_API_KEY` (in shell or `.env`)
- Optional: `CONVISO_API_TIMEOUT` (seconds, default 30)

## Project structure
- `src/conviso/app.py`: Typer entrypoint; registers subcommands.
- `src/conviso/commands/`: CLI commands (`projects`, `assets`, `requirements`, `vulnerabilities`).
- `src/conviso/clients/`: API clients (GraphQL).
- `src/conviso/core/`: shared utilities (logging, notifications, output manager).
- `src/conviso/schemas/`: table schemas/headers for consistent output.

## Adding a new command
1) Create `src/conviso/commands/<name>.py` with a `typer.Typer()` and subcommands.
2) Register it in `src/conviso/app.py` via `app.add_typer(...)`.
3) If you need tabular output, add a schema in `src/conviso/schemas/<name>_schema.py` and pass it to `export_data`.
4) Use `graphql_request` from `conviso.clients.client_graphql` (it enforces API key and timeout).
5) Ensure errors raise `typer.Exit(code=1)` so CI/automation see failures.

## Installation & Setup

Choose the installation method that best fits your needs:

### 1. Development Setup (For Contributors)

Use this method if you plan to modify the source code. It installs the package in **editable mode**, so changes in the code are reflected immediately without re-installing.

**Prerequisites (Optional but Recommended):**

We recommend using [pyenv](https://github.com/pyenv/pyenv) to manage Python versions.

```bash
# 1. Install the required Python version
pyenv install 3.14.2

# 2. Set this version for the current project directory
pyenv local 3.14.2
```

**Setup & Installation:**

```bash
# 1. Create a virtual environment (it will use the version set by pyenv)
python3 -m venv .venv

# 2. Activate the environment
source .venv/bin/activate

# 3. Install the package in editable mode
pip install -e .
```

### 2. User Installation (Build from Source)

Use this method to install the package as a standard CLI tool. This involves building the distribution artifact (`.whl`) first.

**Steps:**

```bash
# 1. Install the build tool
pip install build

# 2. Build the package artifacts (sdist and wheel)
python -m build

# 3. Install the generated wheel from the dist/ directory
# Note: The wildcard (*) automatically selects the version generated in step 2
pip install dist/conviso_cli-*-py3-none-any.whl --force-reinstall
```

**Verification:**

After installation, verify that the CLI is correctly installed and accessible:

```bash
conviso --help
```

## Usage (examples)
- Projects: `python -m conviso.app projects list --company-id 443 --all`
- Assets: `python -m conviso.app assets list --company-id 443 --tags cloud --attack-surface INTERNET_FACING --all`
- Requirements: `python -m conviso.app requirements create --company-id 443 --label "Req" --description "Desc" --activity "Login|Check login"`
- Requirements (project): `python -m conviso.app requirements project --company-id 443 --project-id 26102`
- Requirements (activities): `python -m conviso.app requirements activities --company-id 443 --requirement-id 1503`
- Requirements (project activities): `python -m conviso.app requirements activities --company-id 443 --project-id 26102`
- Tasks (execute YAML from requirements): `python -m conviso.app tasks run --company-id 443 --project-id 26102`
- Tasks (list project): `python -m conviso.app tasks list --company-id 443 --project-id 26102`
- Tasks (only valid YAML): `python -m conviso.app tasks list --company-id 443 --project-id 26102 --only-valid`
- Vulnerabilities: `python -m conviso.app vulns list --company-id 443 --severities HIGH,CRITICAL --asset-tags cloud --all`

Output options: `--format table|json|csv`, `--output path` to save JSON/CSV.

Notes:
- GraphQL errors return exit code 1.
- Use `--all` on list commands to fetch every page.
- `--quiet` silences info logs; `--verbose` shows per-page requests when paginating.
- On startup the CLI checks for a newer version (via https://raw.githubusercontent.com/convisolabs/conviso-cli/main/VERSION). Set `CONVISO_CLI_SKIP_UPDATE_CHECK=1` to skip.
- When offline, the check warns and you can force the comparison by setting `CONVISO_CLI_REMOTE_VERSION` (manual override).
- Upgrade: `python -m conviso.app upgrade` (equiv. `conviso upgrade`) runs `git pull --ff-only` in the repo directory; if installed via pip, run `pip install .` after the pull.

## Tasks (YAML in activities)
- The YAML must be stored in the activity `description` field.
- Only requirements with labels starting with `TASK` (e.g., `TASK - ...` or `TASK:`) are processed (configurable with `--prefix`). Listing and execution are always project-scoped.
- Each activity must have **exactly one step** in the YAML.
- In `vulns.create`, `assetId` is required. If defined in YAML, it takes precedence. Otherwise it is resolved via `inputs.assets`. If it cannot be resolved, the command fails.
- To auto-create assets in `vulns.create`, use `asset.create_if_missing: true` and set `asset.map.name` to a field from the tool output. `description` is accepted in YAML but ignored by the API.
- YAML examples: `samples/task-nmap-nuclei.yaml`, `samples/task-nuclei.yaml`
- `scan-json-lines` example: `samples/task-naabu.yaml`
- Subdomains -> resolve -> ports pipeline: `samples/task-subfinder-dnsx-naabu.yaml`
- Execution:
  - Dry-run with confirmation: `python -m conviso.app tasks run --company-id 443 --project-id 26102`
  - Apply directly: `python -m conviso.app tasks run --company-id 443 --project-id 26102 --apply`
- Pentest guide: `docs/pentest-tasks-guide.md`

### scan-json-lines (agnostic format)
- In `run.parse.format`, use `scan-json-lines` to consume JSONL from any tool.
- Each line must be a JSON object with `finding`, or the whole object is treated as `finding`.

Exemplo mínimo:
```json
{"finding":{"type":"WEB","title":"X-Frame-Options Missing","description":"...","severity":"info","asset":"example.com","url":"https://example.com","method":"GET","scheme":"HTTPS","port":443,"request":"...","response":"..."}}
```

Automatic normalizations:
- `title` -> `name` (if `name` is missing)
- `asset` -> `host` (if `host` is missing)
- `matchedAt` -> `url` (if `url` is missing)

### Project targets helpers
- `inputs.targets` supports `export.mode: hosts` to normalize Target URLs into hostnames.
- Example:
  - `source: "project.target_urls"`
  - `export.file: ".task/targets.txt"`
  - `export.mode: "hosts"`

## SBOM
- List: `python -m conviso.app sbom list --company-id 443 --name log4j --all --format csv --output sbom.csv`
- Filters: `--name`, `--vulnerable-only`, `--asset-ids`, `--tags`, `--sort-by`, `--order`, pagination (`--page/--per-page/--all`).
- Import: `python -m conviso.app sbom import --company-id 443 --file bom.cdx --asset-id 123` (asset-id obrigatório; Upload, formato inferido pelo backend)
- Formats: table/CSV/JSON/CycloneDX for list (`--format cyclonedx`).
- Check vulns (OSV):
  - Using API: `python -m conviso.app sbom check-vulns --company-id 443 --asset-ids 123 --tags foo --format json --output osv.json`
  - Using CycloneDX file: `python -m conviso.app sbom check-vulns --file bom.cdx --format json --output osv.json`
  - Default output is table; use `--format json` for JSON (with or without `--output`).

## Bulk CSV (assets)
- Command: `python -m conviso.app bulk assets --company-id 443 --file assets.csv --op create|update|delete [--force] [--preview-only]`
- Headers (CSV columns)

  | Column                   | Required           | Values / Format                                                      |
  | ------------------------ | ------------------ | -------------------------------------------------------------------- |
  | id                       | update/delete only | Integer ID (column name configurable via `--id-column`)              |
  | name                     | create/update      | Text                                                                 |
  | businessImpact           | optional           | LOW, MEDIUM, HIGH, NOT_DEFINED                                       |
  | dataClassification       | optional           | PII, PAYMENT_CARD_INDUSTRY, NON_SENSITIVE, NOT_DEFINED (comma-separated allowed) |
  | tags                     | optional           | Comma-separated, e.g. `tag1,tag2`                                    |
  | attackSurface            | optional           | INTERNET_FACING, INTERNAL, NOT_DEFINED                               |

- Examples:
  - Create:
    ```
    name,businessImpact,dataClassification,tags,attackSurface
    Asset A,HIGH,NON_SENSITIVE,"tag1,tag2",INTERNET_FACING
    ```
  - Update/Delete:
    ```
    id,name,businessImpact
    123,Asset A Updated,MEDIUM
    ```
- Behavior:
  - Always runs a dry-run first and shows a report.
  - Use `--force` to apply without confirmation; otherwise you will be prompted after dry-run.
  - Use `--preview-only` to exit after dry-run without applying.

## Bulk CSV (requirements)
- Command: `python -m conviso.app bulk requirements --company-id 443 --file reqs.csv --op create|update|delete [--force] [--preview-only]`
- Headers (CSV columns)

  | Column                  | Required           | Values / Format                                      |
  | ----------------------- | ------------------ | ---------------------------------------------------- |
  | id                      | update/delete only | Integer ID (column name configurable via `--id-column`) |
  | label                   | create/update      | Text                                                 |
  | description             | create/update      | Text                                                 |
  | global                  | optional           | true/false                                           |
  | activities              | optional           | Semicolon-separated; each activity uses `label|description|typeId|reference|item|category|actionPlan|templateId|sort` |

- Examples:
  - Create:
    ```
    label,description,global,activities
    Requirement A,Do X,true,"Login|Check login|1|REF||Category||123|1;Logout|Check logout|1"
    ```
  - Update/Delete:
    ```
    id,label,description
    123,Requirement A Updated,Do Y
    ```

## Bulk CSV/SARIF (vulnerabilities)
- Command: `python -m conviso.app bulk vulns --company-id 443 --file vulns.csv --op create|update|delete [--force] [--preview-only] [--sarif]`
- Types: WEB, NETWORK, SOURCE. CSV por padrão; use `--sarif` para importar de SARIF (campos compatíveis com a tabela). `--sarif-asset-field <campo>` define de onde ler o asset (nome ou id); se o asset não existir, o CLI cria automaticamente no company informado.
- Template helper: `python -m conviso.app bulk vulns --show-template`
- Headers (CSV columns)

  | Column                 | Required          | Values / Format                                                      |
  | ---------------------- | ----------------- | -------------------------------------------------------------------- |
  | type                   | create            | WEB, NETWORK, SOURCE                                                 |
  | assetId                | create            | Int                                                                  |
  | title                  | create            | Text                                                                 |
  | description            | create            | Text                                                                 |
  | solution               | create            | Text                                                                 |
  | impactLevel            | create            | ImpactLevelCategory (e.g., HIGH)                                     |
  | probabilityLevel       | create            | ProbabilityLevelCategory (e.g., MEDIUM)                              |
  | severity               | create            | NOTIFICATION, LOW, MEDIUM, HIGH, CRITICAL                            |
  | summary                | create            | Text                                                                 |
  | impactDescription      | create            | Text                                                                 |
  | stepsToReproduce       | create            | Text                                                                 |
  | reference              | optional          | Text/URL                                                             |
  | category               | optional          | Text                                                                 |
  | projectId              | optional          | Int                                                                  |
  | status                 | optional          | IssueStatusLabel                                                     |
  | compromisedEnvironment | optional          | true/false                                                           |
  | method (WEB)           | WEB               | HTTPMethod (GET, POST, ...)                                          |
  | scheme (WEB)           | WEB               | SchemeCategory (HTTP, HTTPS)                                         |
  | url (WEB)              | WEB               | String                                                               |
  | port (WEB/NETWORK)     | WEB/NETWORK       | Int                                                                  |
  | request (WEB)          | WEB               | String                                                               |
  | response (WEB)         | WEB               | String                                                               |
  | parameters (WEB)       | WEB optional      | String                                                               |
  | address (NETWORK)      | NETWORK           | String (host/IP)                                                     |
  | protocol (NETWORK)     | NETWORK           | String                                                               |
  | attackVector (NETWORK) | NETWORK           | String                                                               |
  | fileName (SOURCE)      | SOURCE            | String                                                               |
  | vulnerableLine         | SOURCE            | Int                                                                  |
  | firstLine              | SOURCE            | Int                                                                  |
  | codeSnippet            | SOURCE            | String                                                               |
  | source                 | SOURCE optional   | String                                                               |
  | sink                   | SOURCE optional   | String                                                               |
  | commitRef              | SOURCE optional   | String                                                               |
  | deployId               | SOURCE optional   | String                                                               |

- Example (WEB create):
  ```
  type,assetId,title,description,solution,impactLevel,probabilityLevel,severity,summary,impactDescription,stepsToReproduce,method,scheme,url,port,request,response
  WEB,12345,XSS,"desc","fix",HIGH,MEDIUM,HIGH,"summary","impact","steps",GET,HTTPS,https://app/login,443,"GET /login","HTTP/1.1 200"
  ```
- Example (update/delete):
  - CSV export from `vulns list --format csv` pode ser usado em update/delete. Use coluna `id` ou `issueId`. Tipos são inferidos; `--sarif-asset-field` define onde achar o asset no SARIF; se o asset não existir, o CLI o cria automaticamente.
