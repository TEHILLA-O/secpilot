from __future__ import annotations

import asyncio
import shutil
import time
from abc import ABC, abstractmethod
from pathlib import Path

from secpilot.models import (
    AuthorizedScope,
    Intensity,
    OperationCategory,
    ToolRequest,
    ToolResult,
    ValidationResult,
)
from secpilot.policy.scope import parse_target, target_in_scope


class SecurityTool(ABC):
    name: str
    binary: str
    toolpack: str
    categories: frozenset[OperationCategory]
    privileged: bool = False

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def version(self) -> str:
        return ""

    async def validate(self, request: ToolRequest, scope: AuthorizedScope) -> ValidationResult:
        try:
            target = parse_target(request.target)
        except ValueError as exc:
            return ValidationResult(
                allowed=False,
                decision="deny",
                reasons=[str(exc)],
            )
        if not target_in_scope(target, scope):
            return ValidationResult(
                allowed=False,
                decision="deny",
                reasons=["target is outside the authorized security scope"],
                sanitized_target=target.raw,
            )
        if request.category not in self.categories:
            return ValidationResult(
                allowed=False,
                decision="deny",
                reasons=[f"{self.name} cannot satisfy {request.category.value}"],
                sanitized_target=target.raw,
            )
        argv = self.build_argv(request, target.raw)
        return ValidationResult(
            allowed=True,
            decision="require_approval",
            argv=argv,
            requires_privilege=self.privileged,
            sanitized_target=target.raw,
        )

    @abstractmethod
    def build_argv(self, request: ToolRequest, target: str) -> list[str]:
        """Construct a concrete argv list. Never interpolate into a shell string."""

    async def execute(self, request: ToolRequest, argv: list[str] | None = None) -> ToolResult:
        command = argv or self.build_argv(request, request.target)
        started = time.perf_counter()
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_b, stderr_b = await proc.communicate()
        duration_ms = int((time.perf_counter() - started) * 1000)
        stdout = stdout_b.decode("utf-8", errors="replace")
        stderr = stderr_b.decode("utf-8", errors="replace")
        return ToolResult(
            tool=self.name,
            category=request.category,
            target=request.target,
            argv=command,
            exit_code=proc.returncode or 0,
            stdout=stdout,
            stderr=stderr,
            parsed=self.parse(stdout, stderr, request),
            duration_ms=duration_ms,
            privileged=self.privileged,
        )

    def parse(self, stdout: str, stderr: str, request: ToolRequest) -> dict:
        return {"stdout_lines": len(stdout.splitlines()), "stderr_lines": len(stderr.splitlines())}

    def which(self) -> str:
        return shutil.which(self.binary) or ""


def intensity_ports(intensity: Intensity) -> str:
    if intensity is Intensity.LIGHT:
        return "21,22,25,53,80,110,143,443,445,3306,3389,5432,8080"
    if intensity is Intensity.DEEP:
        return "1-10000"
    return "1-1024,3306,3389,5432,5900,6379,8080,8443,9200"


def assert_safe_path(value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError("file targets must be absolute paths")
    resolved = path.resolve()
    blocked_prefixes = ("/etc/shadow", "/etc/sudoers", "/root/.ssh")
    candidates = {value.replace("\\", "/"), str(resolved).replace("\\", "/")}
    for text in candidates:
        if any(text == item or text.startswith(f"{item}/") or text.endswith(item) for item in blocked_prefixes):
            raise ValueError("refusing to inspect a protected credential path")
    return resolved
