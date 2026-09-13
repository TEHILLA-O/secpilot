from __future__ import annotations

from secpilot.llm.base import LLMProvider
from secpilot.llm.fallback import FallbackPlanner
from secpilot.models import Evidence, SecurityAssessment, SecurityContext


class Analyser:
    def __init__(self, provider: LLMProvider) -> None:
        self.provider = provider
        self.fallback = FallbackPlanner()

    async def analyse(
        self, evidence: list[Evidence], context: SecurityContext
    ) -> SecurityAssessment:
        try:
            return await self.provider.analyse(evidence, context)
        except Exception:
            return await self.fallback.analyse(evidence, context)
