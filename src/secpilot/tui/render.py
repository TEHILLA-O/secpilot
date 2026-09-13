from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from secpilot.models import DetectedTool, ProposedOperation, SecurityAssessment, SecurityPlan
from secpilot.sessions.store import SessionEvent, SessionRecord


def render_inventory(console: Console, tools: list[DetectedTool]) -> None:
    table = Table(title="SECURITY TOOL INVENTORY", expand=False)
    table.add_column("Tool")
    table.add_column("Installed")
    table.add_column("Version")
    table.add_column("Toolpack")
    for item in tools:
        table.add_row(
            item.name,
            "[green]Y[/green]" if item.installed else "[red]N[/red]",
            item.version or "",
            item.toolpack,
        )
    console.print(table)
    enabled = sum(1 for item in tools if item.installed)
    console.print(f"\n{enabled} compatible adapters detected.\n")


def render_plan(console: Console, plan: SecurityPlan, operations: list[ProposedOperation]) -> None:
    lines = [
        f"Target:\n{plan.target}\n",
        "Authorization:",
        f"{'Inside configured lab scope' if plan.in_scope else 'OUT OF SCOPE'}\n",
        "Proposed operations:\n",
    ]
    for index, operation in enumerate(operations, start=1):
        lines.append(f"{index}. {operation.category.value.replace('_', ' ')}")
        if operation.rationale:
            lines.append(f"   {operation.rationale}")
    lines.append("\nTools:\n")
    lines.append("\n".join(plan.tools) or "(none)")
    lines.append(f"\nRisk:\n{plan.risk.value}\n")
    lines.append("No exploitation will be performed.")
    console.print(Panel("\n".join(lines), title="PLAN", border_style="green", width=72))


def render_assessment(console: Console, assessment: SecurityAssessment) -> None:
    console.print()
    console.print(Panel("SECURITY ASSESSMENT", style="bold", border_style="cyan"))
    console.print(f"\nTarget\n{assessment.target}\n")
    if assessment.exposed_services:
        console.print("Exposed Services\n")
        for service in assessment.exposed_services:
            port = service.get("port", "?")
            proto = service.get("proto", "tcp")
            name = service.get("service", "")
            console.print(f"{port}/{proto:<8} {name}")
        console.print()
    console.print(assessment.executive_summary)
    console.print()
    for finding in assessment.findings:
        console.print(Text(finding.severity.value.upper(), style="bold"))
        console.print()
        console.print(finding.summary)
        if finding.evidence_ids:
            console.print(f"\nEvidence:\n{', '.join(finding.evidence_ids)}")
        if finding.recommendation:
            console.print(f"\nRecommendation:\n{finding.recommendation}")
        console.print()


def render_replay(console: Console, session: SessionRecord, events: list[SessionEvent]) -> None:
    console.print(f"\nReplay {session.session_id}  target={session.target}\n")
    for event in events:
        stamp = event.timestamp.strftime("%H:%M")
        console.print(f"{stamp} {event.message}")
    console.print()


def render_sessions(console: Console, sessions: list[SessionRecord]) -> None:
    table = Table(title="SESSIONS")
    table.add_column("SESSION")
    table.add_column("TARGET")
    table.add_column("FINDINGS")
    for item in sessions:
        table.add_row(item.session_id, item.target, str(item.findings))
    console.print(table)
