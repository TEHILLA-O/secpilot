from __future__ import annotations

from pathlib import Path

import pytest

from secpilot.agent.workflow import AuditWorkflow
from secpilot.config.settings import Settings
from secpilot.llm.fallback import FallbackPlanner
from secpilot.models import (
    AuthorizedScope,
    ExecutionMode,
    OperationCategory,
    PolicyDecision,
    SecurityContext,
    ToolResult,
    ValidationResult,
)
from secpilot.tools.nmap import NmapAdapter
from secpilot.tools.registry import ToolRegistry


class FakeNmap:
    name = "nmap"
    binary = "nmap"
    toolpack = "network"
    categories = frozenset(
        {OperationCategory.SERVICE_DISCOVERY, OperationCategory.SERVICE_VERSION}
    )
    privileged = False

    def available(self) -> bool:
        return True

    async def validate(self, request, scope):
        return ValidationResult(
            allowed=True,
            decision=PolicyDecision.REQUIRE_APPROVAL,
            argv=["nmap", "-sT", request.target],
            sanitized_target=request.target,
        )

    async def execute(self, request, argv=None):
        stdout = (
            "Host: 10.10.10.24 ()  Ports: "
            "22/open/tcp//ssh///, 80/open/tcp//http///, "
            "443/open/tcp//https///, 5432/open/tcp//postgresql///"
        )
        parsed = NmapAdapter().parse(stdout, "", request)
        return ToolResult(
            tool="nmap",
            category=request.category,
            target=request.target,
            argv=argv or ["nmap", request.target],
            exit_code=0,
            stdout=stdout,
            parsed=parsed,
        )


def _context(scope: AuthorizedScope, query: str) -> SecurityContext:
    return SecurityContext(
        user_query=query,
        mode=ExecutionMode.AUDIT,
        scope=scope,
        os_family="kali",
        os_pretty="Kali Linux",
        username="victrom",
        model_ref="fallback:rules",
        enabled_toolpacks=["network", "web"],
        available_tools=["nmap"],
    )


@pytest.mark.asyncio
async def test_out_of_scope_short_circuits(sessions, settings) -> None:
    context = _context(AuthorizedScope(cidrs=["10.10.10.0/24"]), "Scan 8.8.8.8")
    workflow = AuditWorkflow(settings, FallbackPlanner(), ToolRegistry([]), sessions)

    async def approve(plan, ops):
        return True

    result = await workflow.run(context, approve)
    assert result.denied is not None
    assert "8.8.8.8" in result.denied
    assert "No command executed" in result.denied


@pytest.mark.asyncio
async def test_approved_audit_produces_evidence(sessions, lab_scope) -> None:
    settings = Settings(mode=ExecutionMode.AUDIT, auto_approve=True)
    registry = ToolRegistry([FakeNmap()])
    context = _context(lab_scope, "Find what is exposed on my lab server 10.10.10.24")
    workflow = AuditWorkflow(settings, FallbackPlanner(), registry, sessions)

    async def approve(plan, ops):
        return True

    result = await workflow.run(context, approve)
    assert result.denied is None
    assert result.assessment is not None
    assert result.evidence
    assert any(
        any(svc.get("port") == "5432" for svc in item.parsed_data.get("services", []))
        for item in result.evidence
    )
    assert Path(result.session.directory).exists()
