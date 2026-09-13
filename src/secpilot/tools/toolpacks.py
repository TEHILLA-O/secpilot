from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

_HERE = Path(__file__).resolve()
BUNDLED_TOOLPACKS = _HERE.parent / "data" / "toolpacks"


def _repo_toolpacks() -> Path:
    for parent in _HERE.parents:
        candidate = parent / "toolpacks"
        if candidate.is_dir():
            return candidate
    return Path("/nonexistent-secpilot-toolpacks")


PACKAGE_TOOLPACKS = _repo_toolpacks()


class ToolpackManifest(BaseModel):
    name: str
    description: str = ""
    adapters: list[str] = Field(default_factory=list)


BUILTIN = [
    ToolpackManifest(
        name="network",
        description="Host and service discovery using nmap, dig, ip, and ss",
        adapters=["nmap", "dig", "ip", "ss"],
    ),
    ToolpackManifest(
        name="web",
        description="HTTP probing, TLS inspection, and technology identification",
        adapters=["curl", "openssl", "whatweb"],
    ),
    ToolpackManifest(
        name="host-audit",
        description="Defensive local host auditing",
        adapters=["lynis", "systemctl", "journalctl"],
    ),
    ToolpackManifest(
        name="network-analysis",
        description="Limited local packet inspection (lab mode only)",
        adapters=["tshark", "tcpdump"],
    ),
    ToolpackManifest(
        name="forensics",
        description="Local file identification and rule matching",
        adapters=["file", "strings", "exiftool", "yara"],
    ),
    ToolpackManifest(
        name="osint",
        description="Public registration metadata for in-scope names",
        adapters=["whois", "dig"],
    ),
]


class ToolpackStore:
    def __init__(self, extra_dir: Path | None = None) -> None:
        self.extra_dir = extra_dir

    def list_manifests(self) -> list[ToolpackManifest]:
        found: dict[str, ToolpackManifest] = {item.name: item for item in BUILTIN}
        for directory in self._dirs():
            if not directory.exists():
                continue
            for path in sorted(directory.glob("*.yaml")):
                raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
                manifest = ToolpackManifest.model_validate(raw)
                found[manifest.name] = manifest
        return list(found.values())

    def names(self) -> list[str]:
        return [item.name for item in self.list_manifests()]

    def _dirs(self) -> list[Path]:
        dirs = [PACKAGE_TOOLPACKS, BUNDLED_TOOLPACKS]
        if self.extra_dir:
            dirs.append(self.extra_dir)
        return dirs
