from __future__ import annotations

from secpilot.models import (
    AuthorizedScope,
    ExecutionMode,
    PolicyDecision,
    PolicyVerdict,
    ProposedOperation,
    SecurityPlan,
)
from secpilot.policy.permissions import DENIED_ALWAYS, PermissionMatrix
from secpilot.policy.scope import parse_target, target_in_scope


class PolicyEngine:
    """Decide whether a plan, or a single operation, may proceed."""

    def __init__(self, mode: ExecutionMode, scope: AuthorizedScope) -> None:
        self.mode = mode
        self.scope = scope
        self.permissions = PermissionMatrix()

    def evaluate_plan(self, plan: SecurityPlan) -> PolicyVerdict:
        reasons: list[str] = []
        blocked: list[str] = []
        approved: list[ProposedOperation] = []

        if plan.exploitation:
            return PolicyVerdict(
                decision=PolicyDecision.DENY,
                reasons=["plan requested exploitation, which SecPilot never performs"],
                blocked_operations=[op.id for op in plan.operations],
            )

        if not self.permissions.execution_enabled(self.mode):
            return PolicyVerdict(
                decision=PolicyDecision.DENY,
                reasons=["observe mode can inspect and recommend, but cannot execute"],
                blocked_operations=[op.id for op in plan.operations],
            )

        if not plan.operations:
            return PolicyVerdict(
                decision=PolicyDecision.DENY,
                reasons=["plan contained no operations"],
            )

        for operation in plan.operations:
            allowed, reason = self.evaluate_operation(operation)
            if allowed:
                approved.append(operation)
            else:
                blocked.append(operation.id)
                reasons.append(f"{operation.id}: {reason}")

        if not approved:
            return PolicyVerdict(
                decision=PolicyDecision.DENY,
                reasons=reasons or ["no operations survived policy evaluation"],
                blocked_operations=blocked,
            )
        return PolicyVerdict(
            decision=PolicyDecision.REQUIRE_APPROVAL,
            reasons=reasons,
            blocked_operations=blocked,
            approved_operations=approved,
        )

    def evaluate_operation(self, operation: ProposedOperation) -> tuple[bool, str]:
        category = operation.category.value
        if category in DENIED_ALWAYS:
            return False, "category is permanently denied"

        permitted, reason = self.permissions.allowed(self.mode, operation.category)
        if not permitted:
            return False, reason

        try:
            target = parse_target(operation.target)
        except ValueError as exc:
            return False, str(exc)

        if not target_in_scope(target, self.scope):
            return False, "target is outside the authorized security scope"

        extra = operation.extra or {}
        if extra.get("destructive") or extra.get("exploit"):
            return False, "destructive or exploit extras are permanently denied"
        return True, "allowed"

    def deny_out_of_scope(self, target: str) -> str:
        return (
            f"EXECUTION DENIED\n\nTarget:\n{target}\n\n"
            "Reason:\nTarget is outside the authorized security scope.\n\n"
            "No command executed."
        )
