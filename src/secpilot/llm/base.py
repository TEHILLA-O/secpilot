from __future__ import annotations

from typing import Protocol, runtime_checkable

from secpilot.models import Evidence, SecurityAssessment, SecurityContext, SecurityPlan


@runtime_checkable
class LLMProvider(Protocol):
    name: str
    model: str

    async def plan(self, context: SecurityContext) -> SecurityPlan: ...

    async def analyse(self, evidence: list[Evidence], context: SecurityContext) -> SecurityAssessment: ...
