from __future__ import annotations

import json
import os

import httpx

from secpilot.config.settings import ModelConfig
from secpilot.llm.jsonutil import extract_json_object
from secpilot.llm.prompts import ANALYSE_SYSTEM, PLAN_SYSTEM, analyse_user_prompt, plan_user_prompt
from secpilot.models import Evidence, SecurityAssessment, SecurityContext, SecurityPlan


class APIProvider:
    """OpenAI-compatible and Anthropic chat completions."""

    name = "api"

    def __init__(self, config: ModelConfig, vendor: str = "openai") -> None:
        self.config = config
        self.vendor = vendor
        self.model = config.name

    async def plan(self, context: SecurityContext) -> SecurityPlan:
        payload = await self._complete(
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
        payload = await self._complete(
            ANALYSE_SYSTEM,
            analyse_user_prompt(evidence[0].target if evidence else "unknown", blob),
        )
        return SecurityAssessment.model_validate(payload)

    async def _complete(self, system: str, user: str) -> dict:
        api_key = os.environ.get(self.config.api_key_env, "")
        if self.vendor == "anthropic":
            return await self._anthropic(system, user, api_key)
        return await self._openai(system, user, api_key)

    async def _openai(self, system: str, user: str, api_key: str) -> dict:
        base = self.config.base_url.rstrip("/")
        if "openai.com" not in base and not base.endswith("/v1"):
            url = base + "/v1/chat/completions"
        elif base.endswith("/v1"):
            url = base + "/chat/completions"
        else:
            url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {api_key}"}
        body = {
            "model": self.model,
            "temperature": self.config.temperature,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
            response = await client.post(url, headers=headers, json=body)
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
        return extract_json_object(content)

    async def _anthropic(self, system: str, user: str, api_key: str) -> dict:
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        body = {
            "model": self.model,
            "max_tokens": 2000,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
            response = await client.post(url, headers=headers, json=body)
            response.raise_for_status()
            content = response.json()["content"][0]["text"]
        return extract_json_object(content)


def _scope_text(context: SecurityContext) -> str:
    cidrs = ", ".join(context.scope.cidrs) or "(none)"
    hosts = ", ".join(context.scope.hosts) or "(none)"
    return f"CIDRs: {cidrs}\nHosts: {hosts}"
