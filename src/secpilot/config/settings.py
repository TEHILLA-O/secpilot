from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from platformdirs import user_config_dir, user_data_dir
from pydantic import BaseModel, Field

from secpilot.models import ExecutionMode

APP_NAME = "secpilot"


class ModelConfig(BaseModel):
    provider: str = "ollama"
    name: str = "qwen3"
    base_url: str = "http://127.0.0.1:11434"
    api_key_env: str = "SECPILOT_API_KEY"
    temperature: float = 0.1
    timeout_seconds: float = 120.0


class Settings(BaseModel):
    mode: ExecutionMode = ExecutionMode.AUDIT
    model: ModelConfig = Field(default_factory=ModelConfig)
    enabled_toolpacks: list[str] = Field(
        default_factory=lambda: ["network", "web", "host-audit"]
    )
    auto_approve: bool = False
    max_replans: int = 2
    helper_path: str = ""
    require_helper_for_privileged: bool = True


class AppPaths:
    def __init__(self, root: Path | None = None) -> None:
        if root is not None:
            self.config_dir = root / "config"
            self.data_dir = root / "data"
        elif os.environ.get("SECPILOT_HOME"):
            home = Path(os.environ["SECPILOT_HOME"])
            self.config_dir = home / "config"
            self.data_dir = home / "data"
        else:
            self.config_dir = Path(user_config_dir(APP_NAME, appauthor=False))
            self.data_dir = Path(user_data_dir(APP_NAME, appauthor=False))
        self.config_file = self.config_dir / "config.yaml"
        self.scope_file = self.config_dir / "scope.yaml"
        self.sessions_dir = self.data_dir / "sessions"
        self.db_path = self.data_dir / "secpilot.sqlite3"

    def ensure(self) -> None:
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.sessions_dir.mkdir(parents=True, exist_ok=True)


def load_settings(paths: AppPaths | None = None) -> Settings:
    paths = paths or AppPaths()
    paths.ensure()
    if not paths.config_file.exists():
        settings = Settings()
        save_settings(settings, paths)
        return settings
    raw: dict[str, Any] = yaml.safe_load(paths.config_file.read_text(encoding="utf-8")) or {}
    return Settings.model_validate(raw)


def save_settings(settings: Settings, paths: AppPaths | None = None) -> None:
    paths = paths or AppPaths()
    paths.ensure()
    paths.config_file.write_text(
        yaml.safe_dump(settings.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )
