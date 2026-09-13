from __future__ import annotations

import re

from secpilot.models import OperationCategory, ToolRequest
from secpilot.tools.base import SecurityTool
from secpilot.tools.tls import _split_host_port


class CurlAdapter(SecurityTool):
    name = "curl"
    binary = "curl"
    toolpack = "web"
    categories = frozenset({OperationCategory.HTTP_PROBE})

    def build_argv(self, request: ToolRequest, target: str) -> list[str]:
        url = _as_url(target, request)
        return [
            self.binary,
            "-sS",
            "-D",
            "-",
            "-o",
            "/dev/null",
            "-L",
            "--max-redirs",
            "5",
            "--max-time",
            "15",
            "-A",
            "SecPilot/0.1 authorized-audit",
            url,
        ]

    def parse(self, stdout: str, stderr: str, request: ToolRequest) -> dict:
        statuses = re.findall(r"HTTP/\S+\s+(\d+)", stdout)
        locations = re.findall(r"(?i)^location:\s*(.+)$", stdout, flags=re.MULTILINE)
        server = ""
        match = re.search(r"(?im)^server:\s*(.+)$", stdout)
        if match:
            server = match.group(1).strip()
        return {
            "status_history": statuses,
            "final_status": statuses[-1] if statuses else "",
            "locations": [item.strip() for item in locations],
            "server": server,
            "https_redirect": any(item.strip().lower().startswith("https://") for item in locations),
        }


class WhatWebAdapter(SecurityTool):
    name = "whatweb"
    binary = "whatweb"
    toolpack = "web"
    categories = frozenset({OperationCategory.WEB_FINGERPRINT})

    def build_argv(self, request: ToolRequest, target: str) -> list[str]:
        url = _as_url(target, request)
        return [self.binary, "--color=never", "-a", "1", url]

    def parse(self, stdout: str, stderr: str, request: ToolRequest) -> dict:
        return {"fingerprint": stdout.strip(), "lines": len(stdout.splitlines())}


def _as_url(target: str, request: ToolRequest) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    scheme = str(request.extra.get("scheme", "https"))
    if scheme not in {"http", "https"}:
        scheme = "https"
    host, port = _split_host_port(target, default_port=443 if scheme == "https" else 80)
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"
