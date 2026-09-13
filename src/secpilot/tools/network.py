from __future__ import annotations

from secpilot.models import OperationCategory, ToolRequest
from secpilot.tools.base import SecurityTool


class DigAdapter(SecurityTool):
    name = "dig"
    binary = "dig"
    toolpack = "network"
    categories = frozenset({OperationCategory.DNS_LOOKUP})

    def build_argv(self, request: ToolRequest, target: str) -> list[str]:
        record = str(request.extra.get("record", "A"))
        allowed = {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"}
        if record.upper() not in allowed:
            record = "A"
        return [self.binary, "+noall", "+answer", target, record.upper()]

    def parse(self, stdout: str, stderr: str, request: ToolRequest) -> dict:
        answers = [line.strip() for line in stdout.splitlines() if line.strip()]
        return {"answers": answers, "count": len(answers)}


class WhoisAdapter(SecurityTool):
    name = "whois"
    binary = "whois"
    toolpack = "osint"
    categories = frozenset({OperationCategory.WHOIS_LOOKUP})

    def build_argv(self, request: ToolRequest, target: str) -> list[str]:
        return [self.binary, target]

    def parse(self, stdout: str, stderr: str, request: ToolRequest) -> dict:
        keys = ("OrgName", "netname", "Country", "country", "Registrant", "nserver")
        fields: dict[str, str] = {}
        for line in stdout.splitlines():
            for key in keys:
                if line.lower().startswith(key.lower() + ":"):
                    fields[key] = line.split(":", 1)[1].strip()
        return {"fields": fields, "lines": len(stdout.splitlines())}


class SsAdapter(SecurityTool):
    name = "ss"
    binary = "ss"
    toolpack = "network"
    categories = frozenset({OperationCategory.SERVICE_DISCOVERY})

    def build_argv(self, request: ToolRequest, target: str) -> list[str]:
        # Local listening sockets only. Target must already have passed scope checks.
        return [self.binary, "-lntup"]

    def parse(self, stdout: str, stderr: str, request: ToolRequest) -> dict:
        listeners = []
        for line in stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                listeners.append({"proto": parts[0], "local": parts[4]})
        return {"listeners": listeners}


class IpAdapter(SecurityTool):
    name = "ip"
    binary = "ip"
    toolpack = "network"
    categories = frozenset({OperationCategory.SERVICE_DISCOVERY})

    def build_argv(self, request: ToolRequest, target: str) -> list[str]:
        return [self.binary, "-br", "addr"]

    def parse(self, stdout: str, stderr: str, request: ToolRequest) -> dict:
        return {"interfaces": [line.strip() for line in stdout.splitlines() if line.strip()]}
