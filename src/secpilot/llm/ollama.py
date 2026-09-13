from __future__ import annotations

import json

import httpx

from secpilot.config.settings import ModelConfig
from secpilot.llm.jsonutil import extract_json_object
from secpilot.llm.prompts import ANALYSE_SYSTEM, PLAN_SYSTEM, analyse_user_prompt, plan_user_prompt
from secpilot.models import Evidence, SecurityAssessment, SecurityContext, SecurityPlan


class OllamaProvider:
    name = "ollama"

    def __init__(self, config: ModelConfig) -> None:
        self.config = config
        self.model = config.name

    async def plan(self, context: SecurityContext) -> SecurityPlan:
        payload = await self._chat(
            PLAN_SYSTEM,
            plan_user_prompt(
                context.user_query,
                context.mode.value,
                _scope_text(context),
                context.available_tools,
            ),
        )
        return SecurityPlan.model_validate(payload)

    async def analyse(
        self, evidence: list[Evidence], context: SecurityContext
    ) -> SecurityAssessment:
        blob = json.dumps([item.model_dump(mode="json") for item in evidence], default=str)
        payload = await self._chat(
            ANALYSE_SYSTEM,
            analyse_user_prompt(evidence[0].target if evidence else "unknown", blob),
        )
        return SecurityAssessment.model_validate(payload)

    async def _chat(self, system: str, user: str) -> dict:
        url = self.config.base_url.rstrip("/") + "/api/chat"
        body = {
            "model": self.model,
            "stream": False,
            "format": "json",
            "options": {"temperature": self.config.temperature},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
            response = await client.post(url, json=body)
            response.raise_for_status()
            content = response.json()["message"]["content"]
        return extract_json_object(content)


def _scope_text(context: SecurityContext) -> str:
    cidrs = ", ".join(context.scope.cidrs) or "(none)"
    hosts = ", ".join(context.scope.hosts) or "(none)"
    return f"CIDRs: {cidrs}\nHosts: {hosts}"
