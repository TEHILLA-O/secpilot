from __future__ import annotations

from collections.abc import Iterable

from secpilot.models import OperationCategory
from secpilot.tools.base import SecurityTool
from secpilot.tools.capture import TcpdumpAdapter, TsharkAdapter
from secpilot.tools.files import ExifToolAdapter, FileAdapter, StringsAdapter, YaraAdapter
from secpilot.tools.logs import JournalctlAdapter
from secpilot.tools.network import DigAdapter, IpAdapter, SsAdapter, WhoisAdapter
from secpilot.tools.nmap import NmapAdapter
from secpilot.tools.system import LynisAdapter, SystemctlAdapter
from secpilot.tools.tls import OpenSSLAdapter
from secpilot.tools.web import CurlAdapter, WhatWebAdapter

# Capability the LLM may name → preferred adapter
CAPABILITY_ADAPTERS: dict[OperationCategory, str] = {
    OperationCategory.SERVICE_DISCOVERY: "nmap",
    OperationCategory.SERVICE_VERSION: "nmap",
    OperationCategory.DNS_LOOKUP: "dig",
    OperationCategory.WHOIS_LOOKUP: "whois",
    OperationCategory.HTTP_PROBE: "curl",
    OperationCategory.TLS_INSPECTION: "openssl",
    OperationCategory.WEB_FINGERPRINT: "whatweb",
    OperationCategory.HOST_AUDIT: "lynis",
    OperationCategory.SERVICE_STATUS: "systemctl",
    OperationCategory.LOG_REVIEW: "journalctl",
    OperationCategory.PACKET_CAPTURE: "tshark",
    OperationCategory.FILE_IDENTIFY: "file",
    OperationCategory.YARA_SCAN: "yara",
    OperationCategory.STRINGS_EXTRACT: "strings",
    OperationCategory.METADATA_EXTRACT: "exiftool",
}


class ToolRegistry:
    def __init__(self, adapters: Iterable[SecurityTool] | None = None) -> None:
        self._adapters: dict[str, SecurityTool] = {}
        for adapter in adapters or _builtin_adapters():
            self.register(adapter)

    def register(self, adapter: SecurityTool) -> None:
        self._adapters[adapter.name] = adapter

    def get(self, name: str) -> SecurityTool | None:
        return self._adapters.get(name)

    def all(self) -> list[SecurityTool]:
        return list(self._adapters.values())

    def enabled(self, toolpacks: list[str]) -> list[SecurityTool]:
        allowed = set(toolpacks)
        return [item for item in self._adapters.values() if item.toolpack in allowed]

    def resolve(self, category: OperationCategory, toolpacks: list[str]) -> SecurityTool | None:
        preferred = CAPABILITY_ADAPTERS.get(category)
        enabled = {item.name: item for item in self.enabled(toolpacks)}
        if preferred and preferred in enabled:
            return enabled[preferred]
        for adapter in enabled.values():
            if category in adapter.categories:
                return adapter
        return None


def _builtin_adapters() -> list[SecurityTool]:
    return [
        NmapAdapter(),
        DigAdapter(),
        WhoisAdapter(),
        IpAdapter(),
        SsAdapter(),
        CurlAdapter(),
        OpenSSLAdapter(),
        WhatWebAdapter(),
        LynisAdapter(),
        SystemctlAdapter(),
        JournalctlAdapter(),
        TsharkAdapter(),
        TcpdumpAdapter(),
        FileAdapter(),
        StringsAdapter(),
        ExifToolAdapter(),
        YaraAdapter(),
    ]


def default_registry() -> ToolRegistry:
    return ToolRegistry()
