from __future__ import annotations

from secpilot.models import OperationCategory, ToolRequest
from secpilot.tools.base import SecurityTool, assert_safe_path


class FileAdapter(SecurityTool):
    name = "file"
    binary = "file"
    toolpack = "forensics"
    categories = frozenset({OperationCategory.FILE_IDENTIFY})

    def build_argv(self, request: ToolRequest, target: str) -> list[str]:
        path = assert_safe_path(target)
        return [self.binary, "--brief", "--mime", str(path)]

    def parse(self, stdout: str, stderr: str, request: ToolRequest) -> dict:
        return {"description": stdout.strip()}


class StringsAdapter(SecurityTool):
    name = "strings"
    binary = "strings"
    toolpack = "forensics"
    categories = frozenset({OperationCategory.STRINGS_EXTRACT})

    def build_argv(self, request: ToolRequest, target: str) -> list[str]:
        path = assert_safe_path(target)
        return [self.binary, "-n", "8", str(path)]

    def parse(self, stdout: str, stderr: str, request: ToolRequest) -> dict:
        lines = [line for line in stdout.splitlines() if line.strip()]
        return {"sample": lines[:80], "count": len(lines)}


class ExifToolAdapter(SecurityTool):
    name = "exiftool"
    binary = "exiftool"
    toolpack = "forensics"
    categories = frozenset({OperationCategory.METADATA_EXTRACT})

    def build_argv(self, request: ToolRequest, target: str) -> list[str]:
        path = assert_safe_path(target)
        return [self.binary, "-json", str(path)]

    def parse(self, stdout: str, stderr: str, request: ToolRequest) -> dict:
        return {"json": stdout.strip()}


class YaraAdapter(SecurityTool):
    name = "yara"
    binary = "yara"
    toolpack = "forensics"
    categories = frozenset({OperationCategory.YARA_SCAN})

    def build_argv(self, request: ToolRequest, target: str) -> list[str]:
        rules = str(request.extra.get("rules", "")).strip()
        if not rules:
            raise ValueError("yara requires an explicit rules file in extra.rules")
        rules_path = assert_safe_path(rules)
        path = assert_safe_path(target)
        return [self.binary, str(rules_path), str(path)]

    def parse(self, stdout: str, stderr: str, request: ToolRequest) -> dict:
        matches = [line.strip() for line in stdout.splitlines() if line.strip()]
        return {"matches": matches, "count": len(matches)}
