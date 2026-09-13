from __future__ import annotations

from secpilot.models import OperationCategory, ToolRequest
from secpilot.tools.base import SecurityTool

_ALLOWED_UNITS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-@_")


class JournalctlAdapter(SecurityTool):
    name = "journalctl"
    binary = "journalctl"
    toolpack = "host-audit"
    categories = frozenset({OperationCategory.LOG_REVIEW})

    def build_argv(self, request: ToolRequest, target: str) -> list[str]:
        unit = str(request.extra.get("unit", "")).strip()
        since = str(request.extra.get("since", "1 hour ago"))
        argv = [
            self.binary,
            "--no-pager",
            "-n",
            "200",
            "--since",
            since,
            "-p",
            "warning",
        ]
        if unit:
            if not unit or any(char not in _ALLOWED_UNITS for char in unit):
                raise ValueError("invalid journal unit")
            argv.extend(["-u", unit])
        return argv

    def parse(self, stdout: str, stderr: str, request: ToolRequest) -> dict:
        lines = [line for line in stdout.splitlines() if line.strip()]
        return {"entries": lines[-100:], "count": len(lines)}
