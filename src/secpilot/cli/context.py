from __future__ import annotations

from dataclasses import dataclass

from rich.console import Console

from secpilot.config.settings import AppPaths, Settings, load_settings
from secpilot.llm.factory import create_provider
from secpilot.platform import current_username, detect_os
from secpilot.policy.scope import ScopeStore
from secpilot.sessions.store import SessionStore
from secpilot.tools.detect import ToolDetector
from secpilot.tools.registry import ToolRegistry, default_registry
from secpilot.tools.toolpacks import ToolpackStore


@dataclass
class Runtime:
    console: Console
    paths: AppPaths
    settings: Settings
    scope: ScopeStore
    sessions: SessionStore
    registry: ToolRegistry
    detector: ToolDetector
    toolpacks: ToolpackStore

    @classmethod
    def load(cls) -> Runtime:
        paths = AppPaths()
        settings = load_settings(paths)
        registry = default_registry()
        return cls(
            console=Console(),
            paths=paths,
            settings=settings,
            scope=ScopeStore(paths),
            sessions=SessionStore(paths),
            registry=registry,
            detector=ToolDetector(registry),
            toolpacks=ToolpackStore(),
        )

    def provider(self, fallback: bool = False):
        return create_provider(self.settings, prefer_fallback=fallback)

    def username(self) -> str:
        return current_username()

    def os_profile(self):
        return detect_os()
