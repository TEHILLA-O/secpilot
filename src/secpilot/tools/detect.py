from __future__ import annotations

import asyncio
import shutil

from secpilot.models import DetectedTool, OsProfile
from secpilot.tools.registry import ToolRegistry


class ToolDetector:
    def __init__(self, registry: ToolRegistry) -> None:
        self.registry = registry

    def inventory(self, os_profile: OsProfile | None = None) -> list[DetectedTool]:
        results: list[DetectedTool] = []
        for adapter in self.registry.all():
            path = shutil.which(adapter.binary) or ""
            results.append(
                DetectedTool(
                    name=adapter.name,
                    installed=bool(path),
                    version=adapter.version() if path else "",
                    path=path,
                    adapter=adapter.__class__.__name__,
                    toolpack=adapter.toolpack,
                )
            )
        return results

    async def probe_version(self, binary: str) -> str:
        path = shutil.which(binary)
        if not path:
            return ""
        try:
            proc = await asyncio.create_subprocess_exec(
                path,
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=3)
            first = out.decode("utf-8", errors="replace").splitlines()
            return first[0].strip() if first else ""
        except (TimeoutError, OSError):
            return ""
