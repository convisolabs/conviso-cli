# Conviso CLI

CLI to interact with Conviso Platform via GraphQL.

## Requirements
- Python 3.9+ (`typer`, `rich`, `requests`, `python-dotenv`)
- Environment variable `CONVISO_API_KEY` (in shell or `.env`)
- Optional: `CONVISO_API_TIMEOUT` (seconds, default 30)

## Project structure
- `conviso/app.py`: Typer entrypoint; registers subcommands.
- `conviso/commands/`: CLI commands (`projects`, `assets`, `requirements`, `vulnerabilities`).
- `conviso/clients/`: API clients (GraphQL).
- `conviso/core/`: shared utilities (logging, notifications, output manager).
- `conviso/schemas/`: table schemas/headers for consistent output.

## Adding a new command
1) Create `conviso/commands/<name>.py` with a `typer.Typer()` and subcommands.
2) Register it in `conviso/app.py` via `app.add_typer(...)`.
3) If you need tabular output, add a schema in `conviso/schemas/<name>_schema.py` and pass it to `export_data`.
4) Use `graphql_request` from `conviso.clients.client_graphql` (it enforces API key and timeout).
5) Ensure errors raise `typer.Exit(code=1)` so CI/automation see failures.

## Install (local)
```
pip install -r requirements.txt  # if present
# or run directly
python -m conviso.app --help
```

## Instal (Homebrew)
```
The easiest way to install the CLI on macOS (or Linux via Linuxbrew) is via our official tap:

```bash
brew tap convisolabs/conviso
brew install conviso
```

## Usage (examples)
- Projects: `python -m conviso.app projects list --company-id 443 --all`
- Assets: `python -m conviso.app assets list --company-id 443 --tags cloud --attack-surface INTERNET_FACING --all`
- Requirements: `python -m conviso.app requirements create --company-id 443 --label "Req" --description "Desc" --activity "Login|Check login"` 
- Vulnerabilities: `python -m conviso.app vulns list --company-id 443 --severities HIGH,CRITICAL --asset-tags cloud --all`

Output options: `--format table|json|csv`, `--output path` to save JSON/CSV.

Notes:
- GraphQL errors return exit code 1.
- Use `--all` on list commands to fetch every page.
- `--quiet` silences info logs; `--verbose` shows per-page requests when paginating.
- On startup the CLI checks for a newer version (via https://raw.githubusercontent.com/convisolabs/conviso-cli/main/VERSION). Set `CONVISO_CLI_SKIP_UPDATE_CHECK=1` to skip.
- Sem rede, o check avisa e você pode forçar a comparação definindo `CONVISO_CLI_REMOTE_VERSION` (override manual).
- Upgrade: `python -m conviso.app upgrade` (equiv. `conviso upgrade`) tenta `git pull --ff-only` no diretório do repo; se instalado via pip, rode `pip install .` após o pull.

## SBOM
- List: `python -m conviso.app sbom list --company-id 443 --name log4j --all --format csv --output sbom.csv`
- Filters: `--name`, `--vulnerable-only`, `--asset-ids`, `--tags`, `--sort-by`, `--order`, pagination (`--page/--per-page/--all`).
- Import: `python -m conviso.app sbom import --company-id 443 --file bom.cdx --asset-id 123` (asset-id obrigatório; Upload, formato inferido pelo backend)
- Formats: table/CSV/JSON/CycloneDX para list (`--format cyclonedx`).
- Check vulns (OSV):
  - Usando API: `python -m conviso.app sbom check-vulns --company-id 443 --asset-ids 123 --tags foo --format json --output osv.json`
  - Usando arquivo CycloneDX: `python -m conviso.app sbom check-vulns --file bom.cdx --format json --output osv.json`
  - Por padrão lista em tabela; use `--format json` para JSON (com ou sem `--output`).

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
