from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ResourceRecord(BaseModel):
    file: str = Field(..., description="Terraform file where the resource was found")
    resource_type: str = Field(..., description="Terraform resource type, e.g. aws_instance")
    resource_name: str = Field(..., description="Terraform resource name")
    config: dict = Field(default_factory=dict, description="Raw resource configuration")


class AnalyzeResponse(BaseModel):
    resource_types: list[str]
    resource_count: int
    resources: list[ResourceRecord]


class SecurityFinding(BaseModel):
    resource: str = Field(..., description="Canonical resource id in <type>.<name> format.")
    resource_type: str = Field(..., description="Terraform resource type.")
    resource_name: str = Field(..., description="Terraform resource name.")
    file: str = Field(..., description="Terraform file where the resource was found.")
    severity: Literal["low", "medium", "high", "critical"]
    category: Literal["identity", "network", "storage", "compute", "monitoring", "general"]
    source_library: Literal["checkov", "tfsec"]
    issue: str
    recommendation: str
    rule_id: str
    compliance: list[str] = Field(
        default_factory=list,
        description="Optional compliance mappings such as CIS/NIST/ISO controls.",
    )


class SecurityScore(BaseModel):
    score: int = Field(..., ge=0, le=100)
    by_severity: dict[str, int] = Field(default_factory=dict)


class SecurityAnalysisResponse(BaseModel):
    findings_count: int
    findings: list[SecurityFinding] = Field(default_factory=list)
    findings_by_resource: dict[str, list[SecurityFinding]] = Field(default_factory=dict)
    score: SecurityScore
    scanner_status: dict[str, str] = Field(default_factory=dict)
    scanner_errors: list[str] = Field(default_factory=list)
    summary: str
    report_markdown: str = Field(
        default="",
        description="Human-readable Markdown report with risk and remediation guidance.",
    )
    report_file: str | None = Field(
        default=None,
        description="Optional path to the exported report document.",
    )


class AnalyzeWithSecurityResponse(BaseModel):
    analyze: AnalyzeResponse
    security: SecurityAnalysisResponse


class SecurityAnalyzeResourcesRequest(BaseModel):
    resources: list[ResourceRecord] = Field(default_factory=list)
    scan_dir: str | None = None


class AzureExportRequest(BaseModel):
    exporter: str | None = Field(
        default=None,
        description="Optional exporter executable name (defaults to aztfexport or aztfexporter).",
    )
    scope_type: Literal["resource-group", "resource"] = Field(
        default="resource-group",
        description="Export scope type: resource-group or resource (resource ID).",
    )
    scope: str = Field(..., description="Resource group name or Azure resource ID.")
    output_dir: str = Field(..., description="Directory to write Terraform files.")
    subscription_id: str | None = Field(
        default=None,
        description="Optional Azure subscription ID or name.",
    )
    append: bool = Field(
        default=False,
        description="Append to an existing Terraform directory if not empty.",
    )
    non_interactive: bool = Field(
        default=True,
        description="Run export in non-interactive mode.",
    )
    hcl_only: bool = Field(
        default=True,
        description="Generate HCL only (skip state import).",
    )
    use_device_code: bool = Field(
        default=False,
        description="Use device code flow for az login.",
    )
    include_security: bool = Field(
        default=False,
        description="Run security analysis on parsed resources and include findings in response.",
    )


class AzureExportResponse(BaseModel):
    steps: list[dict] = Field(
        default_factory=list,
        description="Executed commands with stdout/stderr/exit_code.",
    )
    output_dir: str
    command: list[str]
    login_performed: bool
    login_stdout: str
    login_stderr: str
    export_stdout: str
    export_stderr: str
    analyze: AnalyzeResponse
    security: SecurityAnalysisResponse | None = None
