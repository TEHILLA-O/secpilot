from __future__ import annotations

from secpilot.models import OperationCategory, ToolRequest
from secpilot.tools.base import SecurityTool

_ALLOWED_SYSTEMCTL = frozenset(
    {
        "is-active",
        "is-enabled",
        "is-failed",
        "status",
        "list-units",
        "list-unit-files",
        "show",
    }
)


class LynisAdapter(SecurityTool):
    name = "lynis"
    binary = "lynis"
    toolpack = "host-audit"
    categories = frozenset({OperationCategory.HOST_AUDIT})

    def build_argv(self, request: ToolRequest, target: str) -> list[str]:
        # Audit the local host only. Remote lynis is not supported.
        return [self.binary, "audit", "system", "--quick", "--no-colors", "--quiet"]

    def parse(self, stdout: str, stderr: str, request: ToolRequest) -> dict:
        warnings = [line.strip() for line in stdout.splitlines() if "Warning" in line]
        suggestions = [line.strip() for line in stdout.splitlines() if "Suggestion" in line]
        return {
            "warnings": warnings[:50],
            "suggestions": suggestions[:50],
            "warning_count": len(warnings),
            "suggestion_count": len(suggestions),
        }


class SystemctlAdapter(SecurityTool):
    name = "systemctl"
    binary = "systemctl"
    toolpack = "host-audit"
    categories = frozenset({OperationCategory.SERVICE_STATUS})

    def build_argv(self, request: ToolRequest, target: str) -> list[str]:
        action = str(request.extra.get("action", "is-active"))
        if action not in _ALLOWED_SYSTEMCTL:
            action = "is-active"
        unit = str(request.extra.get("unit", "")).strip()
        argv = [self.binary, "--no-pager", "--plain", action]
        if action in {"status", "is-active", "is-enabled", "is-failed", "show"}:
            if not unit or not _safe_unit(unit):
                raise ValueError("systemctl status requires a safe unit name")
            argv.append(unit)
        elif action in {"list-units", "list-unit-files"}:
            argv.extend(["--type=service", "--state=running"])
        return argv

    def parse(self, stdout: str, stderr: str, request: ToolRequest) -> dict:
        return {"output": stdout.strip(), "lines": stdout.splitlines()}


def _safe_unit(unit: str) -> bool:
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-@_")
    return bool(unit) and all(char in allowed for char in unit) and ".." not in unit
