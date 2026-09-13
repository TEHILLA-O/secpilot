from __future__ import annotations

from secpilot.llm.factory import parse_model_ref
from secpilot.llm.jsonutil import extract_json_object


def test_parse_model_refs() -> None:
    assert parse_model_ref("ollama:qwen3") == ("ollama", "", "qwen3")
    assert parse_model_ref("api:openai")[0] == "api"
    assert parse_model_ref("api:anthropic")[1] == "anthropic"


def test_extract_json_from_fenced_text() -> None:
    blob = '```json\n{"target": "10.10.10.24", "risk": "LOW"}\n```'
    assert extract_json_object(blob)["target"] == "10.10.10.24"
