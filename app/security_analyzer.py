from __future__ import annotations

import json
import shutil
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.schemas import ResourceRecord, SecurityAnalysisResponse, SecurityFinding, SecurityScore

_SEVERITY_WEIGHT = {
    "low": 2,
    "medium": 6,
    "high": 12,
    "critical": 20,
}

_SCANNERS = ("checkov", "tfsec")
_SEVERITY_ORDER = ("critical", "high", "medium", "low")
_SEVERITY_PRIORITY = {
    "critical": "P0 - Immediate",
    "high": "P1 - This sprint",
    "medium": "P2 - Planned",
    "low": "P3 - Backlog",
}
_SEVERITY_DANGER = {
    "critical": "High likelihood of compromise, data exposure, or major service disruption.",
    "high": "Material risk of unauthorized access, data impact, or outage under realistic conditions.",
    "medium": "Moderate risk that can increase blast radius when combined with other weaknesses.",
    "low": "Limited immediate impact, but weakens long-term security posture if left unresolved.",
}


def _normalize_severity(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"critical", "very_high"}:
        return "critical"
    if text in {"high", "error"}:
        return "high"
    if text in {"medium", "moderate", "warning"}:
        return "medium"
    return "low"


def _safe_json_load(raw: str) -> dict[str, Any]:
    payload = raw.strip()
    if not payload:
        return {}
    try:
        loaded = json.loads(payload)
        return loaded if isinstance(loaded, dict) else {}
    except json.JSONDecodeError:
        start = payload.find("{")
        end = payload.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return {}
        try:
            loaded = json.loads(payload[start : end + 1])
            return loaded if isinstance(loaded, dict) else {}
        except json.JSONDecodeError:
            return {}


def _detect_category(resource_type: str, issue: str) -> str:
    key = f"{resource_type} {issue}".lower()
    if any(x in key for x in ["role", "identity", "rbac", "iam", "principal"]):
        return "identity"
    if any(x in key for x in ["nsg", "network", "inbound", "egress", "firewall", "public ip"]):
        return "network"
    if any(x in key for x in ["storage", "blob", "s3", "bucket"]):
        return "storage"
    if any(x in key for x in ["vm", "compute", "container", "kubernetes", "disk"]):
        return "compute"
    if any(x in key for x in ["monitor", "log", "diagnostic", "alert"]):
        return "monitoring"
    return "general"


@dataclass
class _ScannerResult:
    findings: list[SecurityFinding]
    status: str
    error: str | None = None


class _ResourceMatcher:
    def __init__(self, resources: list[ResourceRecord]) -> None:
        self.resources = resources
        self.by_id = {f"{r.resource_type}.{r.resource_name}": r for r in resources}
        self.by_name: dict[str, list[ResourceRecord]] = defaultdict(list)
        for r in resources:
            self.by_name[r.resource_name].append(r)

    def resolve(
        self,
        raw_resource: str | None,
        raw_file: str | None,
    ) -> tuple[str, str, str, str]:
        raw = str(raw_resource or "").strip()
        file_hint = str(raw_file or "").strip()

        if raw in self.by_id:
            r = self.by_id[raw]
            return raw, r.resource_type, r.resource_name, r.file

        if raw:
            for rid, r in self.by_id.items():
                if raw.endswith(rid):
                    return rid, r.resource_type, r.resource_name, r.file

        if raw and "." in raw:
            parts = [p for p in raw.split(".") if p]
            if len(parts) >= 2:
                maybe_name = parts[-1]
                by_name = self.by_name.get(maybe_name, [])
                if len(by_name) == 1:
                    r = by_name[0]
                    return f"{r.resource_type}.{r.resource_name}", r.resource_type, r.resource_name, r.file

        if raw and raw in self.by_name and len(self.by_name[raw]) == 1:
            r = self.by_name[raw][0]
            return f"{r.resource_type}.{r.resource_name}", r.resource_type, r.resource_name, r.file

        guessed_type = raw.split(".")[0] if "." in raw else "unknown_resource"
        guessed_name = raw.split(".")[-1] if raw else "unmapped"
        rid = raw or f"{guessed_type}.{guessed_name}"
        return rid, guessed_type, guessed_name, file_hint


class SecurityAnalyzer:
    def analyze(self, resources: list[ResourceRecord], scan_dir: str | Path | None = None) -> SecurityAnalysisResponse:
        matcher = _ResourceMatcher(resources)
        resolved_scan_dir = self._resolve_scan_dir(resources, scan_dir)

        scanner_status: dict[str, str] = {name: "skipped" for name in _SCANNERS}
        scanner_errors: list[str] = []
        findings: list[SecurityFinding] = []

        if resolved_scan_dir is None:
            scanner_errors.append(
                "Scan directory was not provided or could not be inferred; external scanners were skipped."
            )
        else:
            checkov = self._run_checkov(resolved_scan_dir, matcher)
            tfsec = self._run_tfsec(resolved_scan_dir, matcher)
            for name, result in [
                ("checkov", checkov),
                ("tfsec", tfsec),
            ]:
                scanner_status[name] = result.status
                findings.extend(result.findings)
                if result.error:
                    scanner_errors.append(result.error)

        findings.sort(
            key=lambda f: (
                ["critical", "high", "medium", "low"].index(f.severity),
                f.source_library,
                f.resource,
            )
        )

        findings_by_resource: dict[str, list[SecurityFinding]] = defaultdict(list)
        for finding in findings:
            findings_by_resource[finding.resource].append(finding)

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in findings:
            severity_counts[finding.severity] += 1

        score = self._calculate_score(severity_counts)
        summary = (
            f"Detected {len(findings)} finding(s) from scanner libraries "
            f"(checkov={scanner_status['checkov']}, tfsec={scanner_status['tfsec']})."
        )
        if scanner_errors:
            summary = f"{summary} Scanner notes: {' | '.join(scanner_errors)}"
        report_markdown = self._build_report(findings, severity_counts, summary)

        return SecurityAnalysisResponse(
            findings_count=len(findings),
            findings=findings,
            findings_by_resource=dict(findings_by_resource),
            score=SecurityScore(score=score, by_severity=severity_counts),
            scanner_status=scanner_status,
            scanner_errors=scanner_errors,
            summary=summary,
            report_markdown=report_markdown,
        )

    def _calculate_score(self, severity_counts: dict[str, int]) -> int:
        penalty = sum(_SEVERITY_WEIGHT[sev] * count for sev, count in severity_counts.items())
        return max(0, min(100, 100 - penalty))

    def _resolve_scan_dir(self, resources: list[ResourceRecord], scan_dir: str | Path | None) -> Path | None:
        if scan_dir:
            target = Path(scan_dir).expanduser().resolve()
            return target if target.exists() and target.is_dir() else None

        parents: set[Path] = set()
        for resource in resources:
            file_path = Path(resource.file)
            if file_path.is_absolute() and file_path.exists():
                parents.add(file_path.parent.resolve())

        if len(parents) == 1:
            return next(iter(parents))
        return None

    def _run_command(self, command: list[str], cwd: Path, timeout_sec: int = 300) -> tuple[int, str, str]:
        try:
            result = subprocess.run(
                command,
                cwd=str(cwd),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_sec,
                check=False,
            )
        except FileNotFoundError:
            return 127, "", f"Command not found: {command[0]}"
        except subprocess.TimeoutExpired:
            return 124, "", f"Command timed out after {timeout_sec}s: {' '.join(command)}"
        return result.returncode, (result.stdout or "").strip(), (result.stderr or "").strip()

    def _run_checkov(self, scan_dir: Path, matcher: _ResourceMatcher) -> _ScannerResult:
        exe = shutil.which("checkov")
        if not exe:
            return _ScannerResult(findings=[], status="unavailable", error="checkov executable not found on PATH.")

        cmd = [exe, "-d", str(scan_dir), "--framework", "terraform", "--output", "json", "--quiet"]
        code, stdout, stderr = self._run_command(cmd, cwd=scan_dir)
        if code not in (0, 1):
            return _ScannerResult(
                findings=[],
                status="error",
                error=f"checkov failed (exit {code}): {stderr or stdout}",
            )

        payload = _safe_json_load(stdout)
        results = payload.get("results", {}) if isinstance(payload, dict) else {}
        failed = results.get("failed_checks", []) if isinstance(results, dict) else []
        findings: list[SecurityFinding] = []
        for item in failed:
            if not isinstance(item, dict):
                continue
            issue = str(item.get("check_name") or item.get("check_id") or "Policy violation")
            recommendation = str(item.get("guideline") or item.get("details") or "Review and remediate this policy violation.")
            rid, rtype, rname, file_name = matcher.resolve(
                raw_resource=str(item.get("resource") or ""),
                raw_file=str(item.get("file_path") or ""),
            )
            findings.append(
                SecurityFinding(
                    resource=rid,
                    resource_type=rtype,
                    resource_name=rname,
                    file=file_name,
                    severity=_normalize_severity(item.get("severity")),
                    category=_detect_category(rtype, issue),  # type: ignore[arg-type]
                    source_library="checkov",
                    issue=issue,
                    recommendation=recommendation,
                    rule_id=str(item.get("check_id") or "CHECKOV.UNKNOWN"),
                    compliance=[],
                )
            )

        status = "ok" if not stderr else "ok"
        return _ScannerResult(findings=findings, status=status)

    def _run_tfsec(self, scan_dir: Path, matcher: _ResourceMatcher) -> _ScannerResult:
        exe = shutil.which("tfsec")
        if not exe:
            return _ScannerResult(findings=[], status="unavailable", error="tfsec executable not found on PATH.")

        cmd = [exe, str(scan_dir), "--format", "json", "--no-color"]
        code, stdout, stderr = self._run_command(cmd, cwd=scan_dir)
        if code not in (0, 1):
            return _ScannerResult(
                findings=[],
                status="error",
                error=f"tfsec failed (exit {code}): {stderr or stdout}",
            )

        payload = _safe_json_load(stdout)
        results = payload.get("results", []) if isinstance(payload, dict) else []
        findings: list[SecurityFinding] = []
        for item in results:
            if not isinstance(item, dict):
                continue
            location = item.get("location", {})
            raw_file = ""
            if isinstance(location, dict):
                raw_file = str(location.get("filename") or "")
            issue = str(item.get("description") or item.get("rule_description") or "Policy violation")
            recommendation = str(item.get("resolution") or "Review and remediate this policy violation.")
            rid, rtype, rname, file_name = matcher.resolve(
                raw_resource=str(item.get("resource") or ""),
                raw_file=raw_file,
            )
            findings.append(
                SecurityFinding(
                    resource=rid,
                    resource_type=rtype,
                    resource_name=rname,
                    file=file_name,
                    severity=_normalize_severity(item.get("severity")),
                    category=_detect_category(rtype, issue),  # type: ignore[arg-type]
                    source_library="tfsec",
                    issue=issue,
                    recommendation=recommendation,
                    rule_id=str(item.get("long_id") or item.get("rule_id") or "TFSEC.UNKNOWN"),
                    compliance=[],
                )
            )

        status = "ok" if not stderr else "ok"
        return _ScannerResult(findings=findings, status=status)

    def _build_report(
        self,
        findings: list[SecurityFinding],
        severity_counts: dict[str, int],
        summary: str,
    ) -> str:
        lines: list[str] = []
        lines.append("# Terraform Security Findings Report")
        lines.append("")
        lines.append("## Executive Summary")
        lines.append(f"- {summary}")
        lines.append(
            "- Findings by severity: "
            + ", ".join(f"{sev}={severity_counts.get(sev, 0)}" for sev in _SEVERITY_ORDER)
        )
        lines.append("")

        if not findings:
            lines.append("## Details")
            lines.append("No findings were detected.")
            lines.append("")
            return "\n".join(lines)

        lines.append("## Remediation Priorities")
        for sev in _SEVERITY_ORDER:
            count = severity_counts.get(sev, 0)
            if count:
                lines.append(f"- {sev.title()} ({count}): {_SEVERITY_PRIORITY[sev]}")
        lines.append("")
        lines.append("## Findings")
        lines.append("")

        for index, finding in enumerate(findings, start=1):
            lines.append(f"### {index}. {finding.rule_id} ({finding.severity.upper()})")
            lines.append(f"- Resource: `{finding.resource}`")
            lines.append(f"- Source: `{finding.source_library}`")
            lines.append(f"- Category: `{finding.category}`")
            lines.append(f"- File: `{finding.file}`")
            lines.append(f"- Issue: {finding.issue}")
            lines.append(f"- Why this matters: {_SEVERITY_DANGER[finding.severity]}")
            lines.append(f"- Fix priority: {_SEVERITY_PRIORITY[finding.severity]}")
            lines.append("- Step-by-step remediation:")
            for step_index, step in enumerate(self._build_remediation_steps(finding.recommendation), start=1):
                lines.append(f"  {step_index}. {step}")
            lines.append("")

        return "\n".join(lines)

    def _build_remediation_steps(self, recommendation: str) -> list[str]:
        raw_parts = [part.strip(" -\t") for part in recommendation.splitlines() if part.strip()]
        parts = raw_parts if raw_parts else [recommendation.strip() or "Apply the policy-compliant configuration."]
        if len(parts) == 1:
            return [
                f"Locate the resource and rule violation in Terraform code. Guidance: {parts[0]}",
                "Update resource configuration to meet policy requirements.",
                "Run `terraform plan` and your security scan tools again to verify remediation.",
            ]
        return parts
