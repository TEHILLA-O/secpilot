"""Shared Pydantic contracts used across policy, adapters, LLM, and evidence."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class ExecutionMode(StrEnum):
    OBSERVE = "observe"
    AUDIT = "audit"
    LAB = "lab"


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Intensity(StrEnum):
    LIGHT = "light"
    NORMAL = "normal"
    DEEP = "deep"


class PolicyDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class FindingType(StrEnum):
    EXPOSED_SERVICE = "exposed_service"
    WEAK_TLS = "weak_tls"
    MISCONFIGURATION = "misconfiguration"
    INFORMATION = "information"
    HOST_HARDENING = "host_hardening"
    LOG_ANOMALY = "log_anomaly"
    FILE_MATCH = "file_match"
    DNS = "dns"
    HTTP = "http"


class OperationCategory(StrEnum):
    SERVICE_DISCOVERY = "service_discovery"
    SERVICE_VERSION = "service_version"
    DNS_LOOKUP = "dns_lookup"
    WHOIS_LOOKUP = "whois_lookup"
    HTTP_PROBE = "http_probe"
    TLS_INSPECTION = "tls_inspection"
    WEB_FINGERPRINT = "web_fingerprint"
    HOST_AUDIT = "host_audit"
    SERVICE_STATUS = "service_status"
    LOG_REVIEW = "log_review"
    PACKET_CAPTURE = "packet_capture"
    FILE_IDENTIFY = "file_identify"
    YARA_SCAN = "yara_scan"
    STRINGS_EXTRACT = "strings_extract"
    METADATA_EXTRACT = "metadata_extract"


# Capabilities the LLM may request. The adapter layer maps these to argv.
LLM_CAPABILITIES = {item.value for item in OperationCategory}


class AuthorizedScope(BaseModel):
    cidrs: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    notes: str = ""


class SecurityContext(BaseModel):
    user_query: str
    mode: ExecutionMode
    scope: AuthorizedScope
    os_family: str
    os_pretty: str
    username: str
    model_ref: str
    enabled_toolpacks: list[str] = Field(default_factory=list)
    available_tools: list[str] = Field(default_factory=list)
    session_id: str | None = None


class ProposedOperation(BaseModel):
    id: str
    category: OperationCategory
    target: str
    intensity: Intensity = Intensity.NORMAL
    rationale: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)

    @field_validator("target")
    @classmethod
    def strip_target(cls, value: str) -> str:
        return value.strip()


class SecurityPlan(BaseModel):
    target: str
    authorization_notes: str = ""
    operations: list[ProposedOperation] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    risk: RiskLevel = RiskLevel.LOW
    exploitation: bool = False
    summary: str = ""
    in_scope: bool = True


class ToolRequest(BaseModel):
    tool: str
    category: OperationCategory
    target: str
    intensity: Intensity = Intensity.NORMAL
    extra: dict[str, Any] = Field(default_factory=dict)
    session_dir: str | None = None


class ValidationResult(BaseModel):
    allowed: bool
    decision: PolicyDecision
    reasons: list[str] = Field(default_factory=list)
    argv: list[str] = Field(default_factory=list)
    requires_privilege: bool = False
    sanitized_target: str = ""


class ToolResult(BaseModel):
    tool: str
    category: OperationCategory
    target: str
    argv: list[str]
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    parsed: dict[str, Any] = Field(default_factory=dict)
    duration_ms: int = 0
    privileged: bool = False


class Evidence(BaseModel):
    evidence_id: str
    target: str
    tool: str
    command_category: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finding_type: FindingType = FindingType.INFORMATION
    severity: Severity = Severity.INFORMATIONAL
    summary: str
    raw_output_path: str
    parsed_data: dict[str, Any] = Field(default_factory=dict)
    argv: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    title: str
    severity: Severity
    summary: str
    evidence_ids: list[str] = Field(default_factory=list)
    recommendation: str = ""
    target: str = ""


class SecurityAssessment(BaseModel):
    target: str
    executive_summary: str
    exposed_services: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    methodology: list[str] = Field(default_factory=list)


class SessionEvent(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    kind: str
    message: str
    data: dict[str, Any] = Field(default_factory=dict)


class PolicyVerdict(BaseModel):
    decision: PolicyDecision
    reasons: list[str] = Field(default_factory=list)
    blocked_operations: list[str] = Field(default_factory=list)
    approved_operations: list[ProposedOperation] = Field(default_factory=list)


class DetectedTool(BaseModel):
    name: str
    installed: bool
    version: str = ""
    path: str = ""
    adapter: str
    toolpack: str


class OsProfile(BaseModel):
    family: Literal["kali", "parrot", "debian", "ubuntu", "fedora", "arch", "other"]
    pretty: str
    id_like: list[str] = Field(default_factory=list)
    kernel: str = ""
