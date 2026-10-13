# TerraShield / tfreader

[tfreader-iac on PyPI](https://pypi.org/project/tfreader-iac/) — Terraform resource parser and security scanner with a CLI and FastAPI service.

Supports Python 3.10–3.15, including Python 3.15.0.

FastAPI service to read Terraform IaC and return recognized resources from `.tf` files.

## Run

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Web UI: `http://127.0.0.1:8000/`
Swagger UI: `http://127.0.0.1:8000/docs`

## Install As CLI Tool (No Clone Workflow)

Recommended: use `pipx` so the command is globally available.

Install `pipx` once:

```bash
python -m pip install --user pipx
python -m pipx ensurepath
```

Install from PyPI (no repository clone needed):

```bash
pipx install tfreader-iac
```

To use Python 3.15 explicitly, first install Python 3.15.0, then run:

```bash
pipx install --python python3.15 tfreader-iac
```

On Windows, use `pipx install --python 3.15 tfreader-iac`.
Restart your terminal after `pipx ensurepath` if `tfreader` is not found.

Upgrade an existing installation:

```bash
pipx upgrade tfreader-iac
```

Alternatively, install in an activated virtual environment:

```bash
python -m pip install --upgrade tfreader-iac
```

Then run:

```bash
tfreader --help
tfreader scan ./infra --fail-on high
```

The package name is `tfreader-iac`; the installed command is `tfreader`.
Security scanners (`checkov`, `tfsec`) are separate tools and
must be installed on PATH to produce their findings. Missing scanners are
reported in the scan summary; installation of this package does not install them.

For the development version:

```bash
pipx install git+https://github.com/skagos/TerraShield.git
```

## CLI (CI/CD Security Gate)

You can run security analysis from CLI so pipelines can block merges/deploys.

Command:

```bash
python -m app.cli scan <path> --fail-on high --out-json artifacts/security.json --out-md artifacts/security.md
```

Examples:

```bash
python -m app.cli scan ./exports/azure-terraform-export --fail-on critical
python -m app.cli scan ./exports/azure-terraform-export --fail-on high --out-md SECURITY_FINDINGS_REPORT.md
```

Installed command examples:

```bash
tfreader scan ./exports/azure-terraform-export --fail-on critical
tfreader scan ./exports/azure-terraform-export --fail-on high --out-json artifacts/security.json --out-md artifacts/security.md
```

Exit codes:
- `0`: scan finished, no findings at/above threshold
- `1`: policy gate failed (findings at/above `--fail-on`)
- `2`: invalid input/usage (e.g. bad path)
- `3`: runtime/scanner failure

Recommended rollout:
- start with `--fail-on critical`
- move to `--fail-on high` after initial cleanup
- enforce as required status check in PR protection

For local development of the package command:

```bash
pip install -e .
tfreader --help
```

## Run With Docker

Build and start:

```bash
docker compose up --build
```

The app will be available at `http://127.0.0.1:8000/`.

If you will use Azure export endpoints, run Azure login inside the container:

```bash
docker compose exec tfreader az login --use-device-code
```

Notes:
- The local `./exports` folder is mounted to `/app/exports` in the container.
- `Azure CLI` and `aztfexport` are included in the image.
- You do not need to install `az` or `aztfexport` on the host machine when using Docker.

## Frontend

The frontend supports both inputs:
- `Single TF File` -> sends multipart request to `POST /analyze/file`
- `Folder ZIP` -> sends multipart request to `POST /analyze/folder`

It renders:
- a type-to-resource diagram
- a detailed resource table with filter and expandable config JSON

## API Endpoints

- `GET /health`
- `POST /analyze/file`
  - multipart fields:
    - `tf_file`: a single `.tf` file
- `POST /analyze/folder`
  - multipart fields:
    - `tf_folder_zip`: a `.zip` containing one or more `.tf` files
- `POST /analyze/local-path`
  - multipart fields:
    - `path`: local file/folder path on the API server
- `POST /security/file`
  - multipart fields:
    - `tf_file`: a single `.tf` file
- `POST /security/folder`
  - multipart fields:
    - `tf_folder_zip`: a `.zip` containing one or more `.tf` files
- `POST /security/local-path`
  - multipart fields:
    - `path`: local file/folder path on the API server
- `POST /advise/file`
  - multipart fields:
    - `tf_file`: a single `.tf` file
- `POST /advise/folder`
  - multipart fields:
    - `tf_folder_zip`: a `.zip` containing one or more `.tf` files
- `POST /advise/local-path`
  - multipart fields:
    - `path`: local file/folder path on the API server

## Example `curl`

```bash
curl -X POST "http://127.0.0.1:8000/analyze/file" \
  -F "tf_file=@main.tf"
```

```bash
curl -X POST "http://127.0.0.1:8000/analyze/folder" \
  -F "tf_folder_zip=@infra.zip"
```

## Notes

- This phase only parses Terraform and returns detected resource types and resource entries.
- No database is used by the API.
- Security analysis phase:
  - runs as an additive layer after Terraform parsing
  - endpoints return both parsed resources and structured findings with severities (`low`, `medium`, `high`, `critical`)
  - findings are produced by scanner libraries: `checkov` and `tfsec`
  - each finding includes `source_library` so the UI can show which scanner detected it
  - includes a severity-weighted security score (`0-100`)
  - findings include resource-level keys (for attaching to visualization nodes) and optional compliance tags (CIS/NIST/ISO mapping hooks)
  - scanner binaries must be installed and available on PATH in the API runtime environment
- Azure export can include security analysis by setting `include_security=true` in `POST /export/azure`.
- Advisor phase:
  - default mode is rules-based (`ADVISOR_MODE=rules`)
  - optional future AI path is available via `ADVISOR_MODE=llm` (currently stubbed until provider integration is added)

## GitHub Actions Example

```yaml
name: iac-security-gate
on: [pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -r requirements.txt
      - run: python -m app.cli scan ./exports/azure-terraform-export --fail-on high --out-json artifacts/security.json --out-md artifacts/security.md
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: tfreader-security
          path: artifacts/
```

## Azure DevOps Example

```yaml
trigger:
- main

pool:
  vmImage: ubuntu-latest

steps:
- checkout: self
- task: UsePythonVersion@0
  inputs:
    versionSpec: "3.12"
- script: pip install -r requirements.txt
  displayName: Install dependencies
- script: python -m app.cli scan ./exports/azure-terraform-export --fail-on high --out-json artifacts/security.json --out-md artifacts/security.md
  displayName: Run tfreader security gate
- task: PublishBuildArtifacts@1
  condition: always()
  inputs:
    PathtoPublish: artifacts
    ArtifactName: tfreader-security
```

## Publishing a new PyPI release

The PyPI description comes from this README and is updated by uploading a
new release. Version `0.1.1` includes Python 3.15 compatibility, removal of the Terrascan
integration, and the installation instructions above.

Build and validate the distributions:

```bash
python -m pip install --upgrade build twine
python -m build
python -m twine check dist/*
```

Upload using a project-scoped PyPI API token (username `__token__`, token as
password when prompted; do not commit the token):

```bash
python -m twine upload dist/tfreader_iac-0.1.1*
```

Alternatively, configure a PyPI Trusted Publisher for GitHub owner `skagos`,
repository `TerraShield`, workflow `publish.yml`, environment `pypi`, then
run the **Publish to PyPI** workflow on the tested release commit. The workflow
checks Python 3.15, builds and validates the release before uploading it.
See [PyPI Trusted Publishing setup](https://docs.pypi.org/trusted-publishers/adding-a-publisher/).
Every subsequent upload needs a new version in `pyproject.toml` and `app/main.py`.
