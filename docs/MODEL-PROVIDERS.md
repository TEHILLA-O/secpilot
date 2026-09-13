# Model providers

The application talks to models through one protocol:

```python
class LLMProvider(Protocol):
    async def plan(self, context: SecurityContext) -> SecurityPlan: ...
    async def analyse(self, evidence: list[Evidence]) -> SecurityAssessment: ...
```

CLI:

```
secpilot model list
secpilot model use ollama:qwen3
secpilot model use ollama:llama
secpilot model use api:openai
secpilot model use api:anthropic
secpilot model use llamacpp:local
secpilot model use fallback:rules
```

| Provider | Default endpoint | Notes |
| --- | --- | --- |
| Ollama | `http://127.0.0.1:11434` | Local, preferred for labs |
| API | OpenAI or Anthropic | Keys via `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` |
| llama.cpp | `http://127.0.0.1:8080` | OpenAI-compatible server |
| fallback | none | Deterministic planner for demos and CI |

If a live provider errors or returns invalid JSON, SecPilot falls back to the rule-based planner. Policy evaluation still runs.

The planner is instructed to emit JSON capabilities only. Even a jailbroken completion cannot become a shell command: adapters ignore unknown fields and the policy engine rejects `exploitation: true`.
