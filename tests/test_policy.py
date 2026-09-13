from __future__ import annotations

from secpilot.models import (
    ExecutionMode,
    Intensity,
    OperationCategory,
    PolicyDecision,
    ProposedOperation,
    SecurityPlan,
)
from secpilot.policy.engine import PolicyEngine


def _op(target: str = "10.10.10.24", category=OperationCategory.SERVICE_DISCOVERY) -> ProposedOperation:
    return ProposedOperation(
        id="op-1",
        category=category,
        target=target,
        intensity=Intensity.NORMAL,
        rationale="test",
    )


def test_denies_out_of_scope(lab_scope) -> None:
    engine = PolicyEngine(ExecutionMode.AUDIT, lab_scope)
    plan = SecurityPlan(target="8.8.8.8", operations=[_op("8.8.8.8")], exploitation=False)
    verdict = engine.evaluate_plan(plan)
    assert verdict.decision is PolicyDecision.DENY
    assert "outside the authorized security scope" in " ".join(verdict.reasons)


def test_denies_exploitation(lab_scope) -> None:
    engine = PolicyEngine(ExecutionMode.LAB, lab_scope)
    plan = SecurityPlan(target="10.10.10.24", operations=[_op()], exploitation=True)
    verdict = engine.evaluate_plan(plan)
    assert verdict.decision is PolicyDecision.DENY


def test_observe_cannot_execute(lab_scope) -> None:
    engine = PolicyEngine(ExecutionMode.OBSERVE, lab_scope)
    plan = SecurityPlan(target="10.10.10.24", operations=[_op()], exploitation=False)
    verdict = engine.evaluate_plan(plan)
    assert verdict.decision is PolicyDecision.DENY


def test_packet_capture_lab_only(lab_scope) -> None:
    engine = PolicyEngine(ExecutionMode.AUDIT, lab_scope)
    allowed, reason = engine.evaluate_operation(
        _op(category=OperationCategory.PACKET_CAPTURE)
    )
    assert allowed is False
    assert "lab" in reason

    lab = PolicyEngine(ExecutionMode.LAB, lab_scope)
    allowed, _ = lab.evaluate_operation(_op(category=OperationCategory.PACKET_CAPTURE))
    assert allowed is True


def test_audit_allows_discovery(lab_scope) -> None:
    engine = PolicyEngine(ExecutionMode.AUDIT, lab_scope)
    plan = SecurityPlan(target="10.10.10.24", operations=[_op()], exploitation=False)
    verdict = engine.evaluate_plan(plan)
    assert verdict.decision is PolicyDecision.REQUIRE_APPROVAL
    assert len(verdict.approved_operations) == 1
