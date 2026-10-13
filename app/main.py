from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from zipfile import ZipFile

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.schemas import (
    AnalyzeResponse,
    AnalyzeWithSecurityResponse,
    SecurityAnalysisResponse,
    SecurityAnalyzeResourcesRequest,
    AzureExportRequest,
    AzureExportResponse,
    ResourceRecord,
)
from app.security_analyzer import SecurityAnalyzer
from app.terraform_parser import parse_tf_content, parse_tf_directory, parse_tf_from_zip

app = FastAPI(
    title="Terraform Reader API",
    version="0.1.1",
    description=(
        "Upload Terraform IaC as a single .tf file or a zipped folder, then get "
        "recognized resource types."
    ),
)

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
EXPORTS_DIR = BASE_DIR / "exports"

app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


def _build_response(resources: list[ResourceRecord]) -> AnalyzeResponse:
    resource_types = sorted({r.resource_type for r in resources})
    return AnalyzeResponse(
        resource_types=resource_types,
        resource_count=len(resources),
        resources=resources,
    )


def _build_security_response(
    resources: list[ResourceRecord],
    scan_dir: str | Path | None = None,
) -> AnalyzeWithSecurityResponse:
    analyze = _build_response(resources)
    security = SecurityAnalyzer().analyze(resources, scan_dir=scan_dir)
    return AnalyzeWithSecurityResponse(analyze=analyze, security=security)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_command(
    command: list[str],
    cwd: Path | None = None,
    timeout_sec: int | None = None,
) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Executable not found: {command[0]}. Ensure it is on PATH.",
        ) from exc
    except subprocess.TimeoutExpired as exc:
        timeout_stdout = (exc.stdout or "").strip() if isinstance(exc.stdout, str) else ""
        timeout_stderr = (exc.stderr or "").strip() if isinstance(exc.stderr, str) else ""
        timeout_msg = (
            f"Command timed out after {timeout_sec}s: {' '.join(command)}"
            if timeout_sec is not None
            else f"Command timed out: {' '.join(command)}"
        )
        if timeout_stderr:
            timeout_msg = f"{timeout_msg}\n{timeout_stderr}"
        return 124, timeout_stdout, timeout_msg
    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    return result.returncode, stdout, stderr


def _run_and_record(
    command: list[str],
    steps: list[dict],
    cwd: Path | None = None,
    timeout_sec: int | None = None,
) -> tuple[int, str, str]:
    started_at = _utc_now_iso()
    start = time.perf_counter()
    rendered_cwd = str(cwd) if cwd else str(BASE_DIR)
    print(f"[CMD START {started_at}] cwd={rendered_cwd} cmd={' '.join(command)}")
    code, stdout, stderr = _run_command(command, cwd=cwd, timeout_sec=timeout_sec)
    finished_at = _utc_now_iso()
    duration_sec = round(time.perf_counter() - start, 3)
    print(f"[CMD END   {finished_at}] exit={code} duration={duration_sec}s cmd={' '.join(command)}")

    steps.append(
        {
            "command": command,
            "cwd": rendered_cwd,
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_sec": duration_sec,
            "exit_code": code,
            "stdout": stdout,
            "stderr": stderr,
        }
    )
    return code, stdout, stderr


def _resolve_executable(executable: str) -> str:
    resolved = shutil.which(executable)
    if resolved is None:
        raise HTTPException(
            status_code=500,
            detail=f"Required executable not found on PATH: {executable}",
        )
    return resolved


def _resolve_exporter(preferred: str | None) -> str:
    if preferred:
        return _resolve_executable(preferred)

    for candidate in ["aztfexport", "aztfexporter"]:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved

    raise HTTPException(
        status_code=500,
        detail="Exporter not found on PATH. Install aztfexport or aztfexporter.",
    )


def _resolve_output_dir(raw_dir: str) -> Path:
    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    candidate = Path(raw_dir)
    if candidate.is_absolute():
        resolved = candidate.resolve()
    else:
        resolved = (EXPORTS_DIR / candidate).resolve()

    exports_root = EXPORTS_DIR.resolve()
    try:
        resolved.relative_to(exports_root)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="Output directory must be inside the exports folder.",
        ) from exc

    return resolved


def _write_security_report(output_dir: Path, security: SecurityAnalysisResponse) -> Path:
    report_path = output_dir / "SECURITY_FINDINGS_REPORT.md"
    report_path.write_text(security.report_markdown or "", encoding="utf-8")
    return report_path


@app.get("/")
def index() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/export/azure/folders")
def list_export_folders() -> list[str]:
    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return sorted([p.name for p in EXPORTS_DIR.iterdir() if p.is_dir()])


@app.post("/analyze/file", response_model=AnalyzeResponse)
async def analyze_tf_file(
    tf_file: UploadFile = File(..., description="A single Terraform file ending in .tf"),
) -> AnalyzeResponse:
    if not tf_file.filename or not tf_file.filename.endswith(".tf"):
        raise HTTPException(status_code=400, detail="File must end with .tf")

    try:
        content = (await tf_file.read()).decode("utf-8")
        resources = parse_tf_content(content, tf_file.filename)
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded") from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Failed to parse Terraform file: {exc}") from exc

    return _build_response(resources)


@app.post("/analyze/folder", response_model=AnalyzeResponse)
async def analyze_tf_folder(
    tf_folder_zip: UploadFile = File(
        ...,
        description="A .zip file that contains one or more Terraform .tf files",
    ),
) -> AnalyzeResponse:
    if not tf_folder_zip.filename or not tf_folder_zip.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Folder input must be a .zip file")

    try:
        payload = await tf_folder_zip.read()
        resources = parse_tf_from_zip(payload)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Failed to parse zipped folder: {exc}") from exc

    return _build_response(resources)


@app.post("/analyze/local-path", response_model=AnalyzeResponse)
def analyze_local_path(path: str = Form(...)) -> AnalyzeResponse:
    target = Path(path)
    if not target.exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {path}")

    try:
        if target.is_file():
            if target.suffix != ".tf":
                raise HTTPException(status_code=400, detail="Local file input must end in .tf")
            resources = parse_tf_content(target.read_text(encoding="utf-8"), str(target))
        else:
            resources = parse_tf_directory(target)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Failed to parse local path: {exc}") from exc

    return _build_response(resources)


@app.post("/security/file", response_model=AnalyzeWithSecurityResponse)
async def security_tf_file(
    tf_file: UploadFile = File(..., description="A single Terraform file ending in .tf"),
) -> AnalyzeWithSecurityResponse:
    if not tf_file.filename or not tf_file.filename.endswith(".tf"):
        raise HTTPException(status_code=400, detail="File must end with .tf")

    try:
        content = (await tf_file.read()).decode("utf-8")
        resources = parse_tf_content(content, tf_file.filename)
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="File must be UTF-8 encoded") from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Failed to parse Terraform file: {exc}") from exc

    with tempfile.TemporaryDirectory(prefix="tfreader-security-file-") as tmp:
        file_name = tf_file.filename or "uploaded.tf"
        target = Path(tmp) / file_name
        target.write_text(content, encoding="utf-8")
        return _build_security_response(resources, scan_dir=tmp)


@app.post("/security/folder", response_model=AnalyzeWithSecurityResponse)
async def security_tf_folder(
    tf_folder_zip: UploadFile = File(
        ...,
        description="A .zip file that contains one or more Terraform .tf files",
    ),
) -> AnalyzeWithSecurityResponse:
    if not tf_folder_zip.filename or not tf_folder_zip.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Folder input must be a .zip file")

    try:
        payload = await tf_folder_zip.read()
        resources = parse_tf_from_zip(payload)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Failed to parse zipped folder: {exc}") from exc

    with tempfile.TemporaryDirectory(prefix="tfreader-security-zip-") as tmp:
        zip_path = Path(tmp) / "input.zip"
        zip_path.write_bytes(payload)
        with ZipFile(zip_path, "r") as archive:
            archive.extractall(tmp)
        return _build_security_response(resources, scan_dir=tmp)


@app.post("/security/local-path", response_model=AnalyzeWithSecurityResponse)
def security_local_path(path: str = Form(...)) -> AnalyzeWithSecurityResponse:
    target = Path(path)
    if not target.exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {path}")

    try:
        if target.is_file():
            if target.suffix != ".tf":
                raise HTTPException(status_code=400, detail="Local file input must end in .tf")
            resources = parse_tf_content(target.read_text(encoding="utf-8"), str(target))
        else:
            resources = parse_tf_directory(target)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Failed to parse local path: {exc}") from exc

    scan_dir = target if target.is_dir() else target.parent
    return _build_security_response(resources, scan_dir=scan_dir)


@app.post("/security/resources", response_model=SecurityAnalysisResponse)
def security_from_resources(request: SecurityAnalyzeResourcesRequest) -> SecurityAnalysisResponse:
    return SecurityAnalyzer().analyze(request.resources, scan_dir=request.scan_dir)


@app.post("/export/azure", response_model=AzureExportResponse)
def export_azure(request: AzureExportRequest) -> AzureExportResponse:
    print(
        f"[EXPORT] Request at {_utc_now_iso()} "
        f"scope_type={request.scope_type} scope={request.scope} "
        f"output_dir={request.output_dir} append={request.append} "
        f"hcl_only={request.hcl_only} non_interactive={request.non_interactive}"
    )
    az = _resolve_executable("az")
    exporter = _resolve_exporter(request.exporter)

    steps: list[dict] = []
    output_dir = _resolve_output_dir(request.output_dir)
    print(f"[EXPORT] Resolved output directory: {output_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)

    if not request.append:
        has_files = any(output_dir.iterdir())
        if has_files:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Output directory is not empty. Enable append or choose an empty directory."
                ),
            )

    login_performed = False
    login_stdout = ""
    login_stderr = ""
    login_code, _, _ = _run_and_record([az, "account", "show", "-o", "json"], steps, timeout_sec=60)
    if login_code != 0:
        print("[EXPORT] az account show failed; running az login.")
        login_performed = True
        login_cmd = [az, "login"]
        if request.use_device_code:
            login_cmd.append("--use-device-code")
        login_code, login_stdout, login_stderr = _run_and_record(login_cmd, steps, timeout_sec=300)
        if login_code != 0:
            raise HTTPException(
                status_code=401,
                detail={
                    "message": "az login failed.",
                    "stdout": login_stdout,
                    "stderr": login_stderr,
                    "steps": steps,
                },
            )

    if request.subscription_id:
        print(f"[EXPORT] Setting subscription to: {request.subscription_id}")
        set_code, set_out, set_err = _run_and_record(
            [az, "account", "set", "--subscription", request.subscription_id],
            steps,
            timeout_sec=60,
        )
        if set_code != 0:
            raise HTTPException(
                status_code=400,
                detail={
                    "message": "Failed to set subscription.",
                    "stdout": set_out,
                    "stderr": set_err,
                    "steps": steps,
                },
            )

    cmd = [
        exporter,
        request.scope_type,
        "--output-dir",
        str(output_dir),
    ]
    if not request.non_interactive:
        print("[EXPORT] non_interactive=False requested, but API export forces non-interactive mode to avoid hanging prompts.")
    cmd.extend(["--non-interactive", "--plain-ui"])
    if request.hcl_only:
        cmd.append("--hcl-only")
    if request.append:
        cmd.append("--append")
    cmd.extend(["--log-path", str(output_dir / "aztfexport.log"), "--log-level", "INFO"])
    cmd.append(request.scope)

    print(f"[EXPORT] Starting exporter command at {_utc_now_iso()}: {' '.join(cmd)}")
    export_code, export_stdout, export_stderr = _run_and_record(
        cmd,
        steps,
        cwd=BASE_DIR,
        timeout_sec=1800,
    )
    if export_code != 0:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "aztfexport failed.",
                "stdout": export_stdout,
                "stderr": export_stderr,
                "steps": steps,
            },
        )

    print(f"[EXPORT] Export command finished. Parsing output folder: {output_dir}")
    resources = parse_tf_directory(output_dir)
    print(f"[EXPORT] Parsing completed. Parsed resource count: {len(resources)}")
    analyze = _build_response(resources)
    security = SecurityAnalyzer().analyze(resources, scan_dir=output_dir) if request.include_security else None
    if security is not None:
        report_path = _write_security_report(output_dir, security)
        security.report_file = str(report_path)

    return AzureExportResponse(
        steps=steps,
        output_dir=str(output_dir),
        command=cmd,
        login_performed=login_performed,
        login_stdout=login_stdout,
        login_stderr=login_stderr,
        export_stdout=export_stdout,
        export_stderr=export_stderr,
        analyze=analyze,
        security=security,
    )
