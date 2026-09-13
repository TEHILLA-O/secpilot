from __future__ import annotations

from secpilot.config.settings import Settings
from secpilot.llm.api import APIProvider
from secpilot.llm.base import LLMProvider
from secpilot.llm.fallback import FallbackPlanner
from secpilot.llm.llama_cpp import LlamaCppProvider
from secpilot.llm.ollama import OllamaProvider


def parse_model_ref(ref: str) -> tuple[str, str, str]:
    """Parse 'ollama:qwen3', 'api:openai', 'api:anthropic', 'llamacpp:model'."""
    if ":" not in ref:
        raise ValueError("model reference must look like provider:name")
    provider, rest = ref.split(":", 1)
    provider = provider.lower()
    vendor = ""
    name = rest
    if provider == "api":
        if rest in {"openai", "anthropic"}:
            vendor = rest
            name = "gpt-4o-mini" if rest == "openai" else "claude-sonnet-4-5"
        elif "/" in rest:
            vendor, name = rest.split("/", 1)
        else:
            vendor = "openai"
            name = rest
    return provider, vendor, name


def create_provider(settings: Settings, prefer_fallback: bool = False) -> LLMProvider:
    if prefer_fallback or settings.model.provider == "fallback":
        return FallbackPlanner()
    config = settings.model
    if config.provider == "ollama":
        return OllamaProvider(config)
    if config.provider == "llamacpp":
        return LlamaCppProvider(config)
    if config.provider == "api":
        vendor = "anthropic" if "claude" in config.name or "anthropic" in config.name else "openai"
        return APIProvider(config, vendor=vendor)
    return FallbackPlanner()


def apply_model_ref(settings: Settings, ref: str) -> Settings:
    provider, vendor, name = parse_model_ref(ref)
    model = settings.model.model_copy()
    model.provider = "api" if provider == "api" else provider
    model.name = name
    if provider == "ollama":
        model.base_url = "http://127.0.0.1:11434"
    elif provider == "llamacpp":
        model.base_url = "http://127.0.0.1:8080"
    elif provider == "api" and vendor == "openai":
        model.base_url = "https://api.openai.com/v1"
        model.api_key_env = "OPENAI_API_KEY"
    elif provider == "api" and vendor == "anthropic":
        model.base_url = "https://api.anthropic.com"
        model.api_key_env = "ANTHROPIC_API_KEY"
        if name.startswith("openai") or name == "gpt-4o-mini":
            model.name = "claude-sonnet-4-5"
    settings.model = model
    return settings
