from __future__ import annotations

from pathlib import Path

import pytest

from secpilot.config.settings import AppPaths, Settings
from secpilot.models import AuthorizedScope, ExecutionMode
from secpilot.policy.scope import ScopeStore
from secpilot.sessions.store import SessionStore


@pytest.fixture
def tmp_paths(tmp_path: Path) -> AppPaths:
    paths = AppPaths(root=tmp_path)
    paths.ensure()
    return paths


@pytest.fixture
def settings() -> Settings:
    return Settings(mode=ExecutionMode.AUDIT, auto_approve=True)


@pytest.fixture
def lab_scope(tmp_paths: AppPaths) -> AuthorizedScope:
    store = ScopeStore(tmp_paths)
    store.add("10.10.10.0/24")
    store.add("192.168.56.0/24")
    store.add("lab.example.com")
    return store.load()


@pytest.fixture
def sessions(tmp_paths: AppPaths) -> SessionStore:
    return SessionStore(tmp_paths)
