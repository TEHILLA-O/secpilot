from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path

from secpilot.agent.analyser import Analyser
from secpilot.agent.planner import Planner
from secpilot.config.settings import Settings
from secpilot.evidence.store import EvidenceStore
from secpilot.llm.base import LLMProvider
from secpilot.models import (
    Evidence,
    PolicyDecision,
    ProposedOperation,
    SecurityAssessment,
    SecurityContext,
    SecurityPlan,
    SessionEvent,
    ToolRequest,
    ToolResult,
)
from secpilot.policy.engine import PolicyEngine
from secpilot.policy.scope import extract_targets, parse_target, target_in_scope
from secpilot.privileged.client import PrivilegedHelper
from secpilot.sessions.store import SessionRecord, SessionStore
from secpilot.tools.registry import ToolRegistry

ApproveFn = Callable[[SecurityPlan, list[ProposedOperation]], Awaitable[bool]]


@dataclass
class WorkflowResult:
    session: SessionRecord
    plan: SecurityPlan
    evidence: list[Evidence] = field(default_factory=list)
    assessment: SecurityAssessment | None = None
    denied: str | None = None


class AuditWorkflow:
    """Scope → plan → policy → approval → execute → parse → correlate."""

    def __init__(
        self,
        settings: Settings,
        provider: LLMProvider,
        registry: ToolRegistry,
        sessions: SessionStore,
        helper: PrivilegedHelper | None = None,
    ) -> None:
        self.settings = settings
        self.planner = Planner(provider)
        self.analyser = Analyser(provider)
        self.registry = registry
        self.sessions = sessions
        self.helper = helper or PrivilegedHelper(settings.helper_path)

    async def run(
        self,
        context: SecurityContext,
        approve: ApproveFn,
    ) -> WorkflowResult:
        targets = extract_targets(context.user_query)
        engine = PolicyEngine(context.mode, context.scope)

        if targets:
            out_of_scope = [
                item for item in targets if not target_in_scope(parse_target(item), context.scope)
            ]
            if out_of_scope and not any(
                target_in_scope(parse_target(item), context.scope) for item in targets
            ):
                denied = engine.deny_out_of_scope(out_of_scope[0])
                session = self._new_session(out_of_scope[0], context)
                self._event(session, "denied", denied)
                return WorkflowResult(
                    session=session,
                    plan=SecurityPlan(target=out_of_scope[0], in_scope=False),
                    denied=denied,
                )

        plan = await self.planner.plan(context)
        session = self._new_session(plan.target, context)
        self._event(session, "planned", plan.summary or "plan created", plan.model_dump(mode="json"))

        verdict = engine.evaluate_plan(plan)
        if verdict.decision is PolicyDecision.DENY:
            message = "\n".join(verdict.reasons) or "plan denied"
            self._event(session, "denied", message)
            return WorkflowResult(session=session, plan=plan, denied=message)

        approved_ops = verdict.approved_operations
        accepted = await approve(plan, approved_ops)
        if not accepted:
            self._event(session, "rejected", "operator declined execution")
            return WorkflowResult(session=session, plan=plan, denied="Operator declined execution.")
        self._event(session, "approved", f"{len(approved_ops)} operation(s) approved")

        store = EvidenceStore(Path(session.directory))
        evidence: list[Evidence] = []

        for operation in approved_ops:
            result = await self._execute(operation, context, engine)
            if result is None:
                self._event(session, "skipped", f"{operation.id} had no adapter")
                continue
            item = store.record(result)
            evidence.append(item)
            self._event(
                session,
                "executed",
                f"{result.tool} adapter executed",
                {"argv": result.argv, "exit_code": result.exit_code},
            )

        assessment = await self.analyser.analyse(evidence, context)
        (Path(session.directory) / "assessment.json").write_text(
            assessment.model_dump_json(indent=2),
            encoding="utf-8",
        )
        self.sessions.set_findings(session.session_id, len(assessment.findings))
        self._event(session, "assessed", f"{len(assessment.findings)} finding(s) generated")
        return WorkflowResult(
            session=session,
            plan=plan,
            evidence=evidence,
            assessment=assessment,
        )

    async def _execute(
        self,
        operation: ProposedOperation,
        context: SecurityContext,
        engine: PolicyEngine,
    ) -> ToolResult | None:
        adapter = self.registry.resolve(operation.category, context.enabled_toolpacks)
        if adapter is None or not adapter.available():
            return None
        request = ToolRequest(
            tool=adapter.name,
            category=operation.category,
            target=operation.target,
            intensity=operation.intensity,
            extra=operation.extra,
        )
        validation = await adapter.validate(request, context.scope)
        if not validation.allowed:
            return None
        allowed, _reason = engine.evaluate_operation(operation)
        if not allowed:
            return None
        if validation.requires_privilege and self.settings.require_helper_for_privileged:
            if self.helper.available():
                return await self.helper.run(validation.argv, operation.category.value)
            return None
        try:
            return await adapter.execute(request, validation.argv)
        except OSError:
            return None

    def _new_session(self, target: str, context: SecurityContext) -> SessionRecord:
        label = f"LAB-{uuid.uuid4().hex[:3].upper()}"
        return self.sessions.create(
            session_id=label,
            label=label,
            target=target,
            mode=context.mode.value,
        )

    def _event(self, session: SessionRecord, kind: str, message: str, data: dict | None = None) -> None:
        self.sessions.append_event(
            session.directory,
            SessionEvent(kind=kind, message=message, data=data or {}),
        )
