from __future__ import annotations

from secpilot.models import OperationCategory, ToolRequest
from secpilot.tools.base import SecurityTool


class TsharkAdapter(SecurityTool):
    name = "tshark"
    binary = "tshark"
    toolpack = "network-analysis"
    categories = frozenset({OperationCategory.PACKET_CAPTURE})
    privileged = True

    def build_argv(self, request: ToolRequest, target: str) -> list[str]:
        interface = str(request.extra.get("interface", "any"))
        if not _safe_iface(interface):
            raise ValueError("invalid capture interface")
        count = min(int(request.extra.get("count", 50)), 200)
        return [
            self.binary,
            "-i",
            interface,
            "-c",
            str(count),
            "-n",
            "-q",
            "-z",
            "conv,ip",
        ]


class TcpdumpAdapter(SecurityTool):
    name = "tcpdump"
    binary = "tcpdump"
    toolpack = "network-analysis"
    categories = frozenset({OperationCategory.PACKET_CAPTURE})
    privileged = True

    def build_argv(self, request: ToolRequest, target: str) -> list[str]:
        interface = str(request.extra.get("interface", "any"))
        if not _safe_iface(interface):
            raise ValueError("invalid capture interface")
        count = min(int(request.extra.get("count", 20)), 100)
        host = target
        return [
            self.binary,
            "-i",
            interface,
            "-c",
            str(count),
            "-nn",
            "host",
            host,
        ]


def _safe_iface(value: str) -> bool:
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")
    return bool(value) and all(char in allowed for char in value)
