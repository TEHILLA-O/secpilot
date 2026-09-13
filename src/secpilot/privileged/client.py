from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path

from secpilot.models import ToolResult


class PrivilegedHelper:
    """Talks to the optional Rust helper over stdin/stdout JSON."""

    def __init__(self, helper_path: str = "") -> None:
        self.helper_path = helper_path or shutil.which("secpilot-helper") or ""

    def available(self) -> bool:
        return bool(self.helper_path and Path(self.helper_path).exists())

    async def run(self, argv: list[str], operation: str) -> ToolResult:
        if not self.available():
            raise RuntimeError("privileged helper is not installed")
        payload = json.dumps({"op": operation, "argv": argv})
        proc = await asyncio.create_subprocess_exec(
            self.helper_path,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_b, stderr_b = await proc.communicate(payload.encode("utf-8"))
        if proc.returncode != 0:
            raise RuntimeError(stderr_b.decode("utf-8", errors="replace") or "helper failed")
        data = json.loads(stdout_b.decode("utf-8"))
        return ToolResult.model_validate(data)
