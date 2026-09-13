from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from secpilot.models import Evidence, Finding, FindingType, SecurityAssessment, Severity
from secpilot.reports.generator import ReportGenerator
from secpilot.sessions.store import SessionRecord


def test_markdown_and_json_reports(sessions, tmp_path: Path) -> None:
    record = SessionRecord(
        session_id="LAB-001",
        label="LAB-001",
        target="10.10.10.24",
        mode="audit",
        created_at=datetime.now(UTC),
        directory=str(tmp_path),
        findings=1,
    )
    assessment = SecurityAssessment(
        target="10.10.10.24",
        executive_summary="PostgreSQL is reachable from the lab network.",
        exposed_services=[{"port": "5432", "proto": "tcp", "service": "postgresql"}],
        findings=[
            Finding(
                title="Exposed PostgreSQL",
                severity=Severity.HIGH,
                summary="5432/tcp accepted connections.",
                recommendation="Restrict the listener.",
                target="10.10.10.24",
            )
        ],
        limitations=["No exploitation was performed."],
        methodology=["service_discovery"],
    )
    evidence = [
        Evidence(
            evidence_id="abc123",
            target="10.10.10.24",
            tool="nmap",
            command_category="service_discovery",
            finding_type=FindingType.EXPOSED_SERVICE,
            severity=Severity.HIGH,
            summary="Database reachable",
            raw_output_path=str(tmp_path / "raw.txt"),
            argv=["nmap", "-sT", "10.10.10.24"],
        )
    ]
    gen = ReportGenerator(sessions)
    md = gen.render(record, assessment, evidence, "markdown")
    js = gen.render(record, assessment, evidence, "json")
    html = gen.render(record, assessment, evidence, "html")
    assert "PostgreSQL" in md
    assert "10.10.10.24" in js
    assert "<html" in html
