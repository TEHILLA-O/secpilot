from __future__ import annotations

from secpilot.llm.base import LLMProvider
from secpilot.llm.fallback import FallbackPlanner
from secpilot.models import SecurityContext, SecurityPlan


class Planner:
    def __init__(self, provider: LLMProvider) -> None:
        self.provider = provider
        self.fallback = FallbackPlanner()

    async def plan(self, context: SecurityContext) -> SecurityPlan:
        try:
            plan = await self.provider.plan(context)
        except Exception:
            plan = await self.fallback.plan(context)
        if plan.exploitation:
            plan = await self.fallback.plan(context)
            plan.authorization_notes += " Exploitation requests were discarded."
        return plan
