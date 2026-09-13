from __future__ import annotations

import uuid
from pathlib import Path

from secpilot.models import Evidence, FindingType, Severity, ToolResult


class EvidenceStore:
    def __init__(self, session_dir: Path) -> None:
        self.session_dir = session_dir
        self.raw_dir = session_dir / "raw"
        self.evidence_dir = session_dir / "evidence"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def record(self, result: ToolResult, summary: str | None = None) -> Evidence:
        evidence_id = uuid.uuid4().hex[:12]
        raw_path = self.raw_dir / f"{evidence_id}.txt"
        raw_path.write_text(
            f"$ {' '.join(result.argv)}\n\n{result.stdout}\n{result.stderr}",
            encoding="utf-8",
        )
        finding_type, severity, auto_summary = classify(result)
        evidence = Evidence(
            evidence_id=evidence_id,
            target=result.target,
            tool=result.tool,
            command_category=result.category.value,
            finding_type=finding_type,
            severity=severity,
            summary=summary or auto_summary,
            raw_output_path=str(raw_path),
            parsed_data=result.parsed,
            argv=result.argv,
        )
        (self.evidence_dir / f"{evidence_id}.json").write_text(
            evidence.model_dump_json(indent=2),
            encoding="utf-8",
        )
        return evidence

    def list(self) -> list[Evidence]:
        items: list[Evidence] = []
        for path in sorted(self.evidence_dir.glob("*.json")):
            items.append(Evidence.model_validate_json(path.read_text(encoding="utf-8")))
        return items


def classify(result: ToolResult) -> tuple[FindingType, Severity, str]:
    parsed = result.parsed
    if result.tool == "nmap":
        services = parsed.get("services") or []
        risky = [item for item in services if item.get("port") in {"5432", "3306", "27017", "6379"}]
        if risky:
            ports = ", ".join(f"{item['port']}/{item.get('proto', 'tcp')}" for item in risky)
            return (
                FindingType.EXPOSED_SERVICE,
                Severity.HIGH,
                f"Database or cache service reachable: {ports}",
            )
        if services:
            return (
                FindingType.EXPOSED_SERVICE,
                Severity.INFORMATIONAL,
                f"{len(services)} open service(s) discovered",
            )
    if result.tool == "openssl":
        weak = parsed.get("weak_indicators") or []
        if weak:
            return (
                FindingType.WEAK_TLS,
                Severity.MEDIUM,
                f"TLS configuration includes outdated indicators: {', '.join(weak)}",
            )
        if parsed.get("connected"):
            return (
                FindingType.INFORMATION,
                Severity.LOW,
                f"TLS handshake succeeded ({parsed.get('protocol') or 'unknown protocol'})",
            )
    if result.tool == "curl":
        if parsed.get("https_redirect"):
            return (
                FindingType.HTTP,
                Severity.LOW,
                "HTTP redirects correctly to HTTPS",
            )
        status = parsed.get("final_status")
        if status:
            return FindingType.HTTP, Severity.INFORMATIONAL, f"HTTP final status {status}"
    if result.tool == "lynis":
        count = int(parsed.get("warning_count") or 0)
        if count:
            return (
                FindingType.HOST_HARDENING,
                Severity.MEDIUM,
                f"Lynis reported {count} warning(s)",
            )
    return FindingType.INFORMATION, Severity.INFORMATIONAL, f"{result.tool} completed"
