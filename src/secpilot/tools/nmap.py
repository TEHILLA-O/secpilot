from __future__ import annotations

import re

from secpilot.models import Intensity, OperationCategory, ToolRequest
from secpilot.tools.base import SecurityTool, intensity_ports


class NmapAdapter(SecurityTool):
    name = "nmap"
    binary = "nmap"
    toolpack = "network"
    categories = frozenset(
        {OperationCategory.SERVICE_DISCOVERY, OperationCategory.SERVICE_VERSION}
    )

    def version(self) -> str:
        return "7.x"

    def build_argv(self, request: ToolRequest, target: str) -> list[str]:
        ports = intensity_ports(request.intensity)
        argv = [self.binary, "-Pn", "-n", "--reason", "-T3"]
        if request.category is OperationCategory.SERVICE_VERSION:
            argv.extend(["-sV", "--version-light"])
        else:
            argv.append("-sT")
        if request.intensity is Intensity.LIGHT:
            argv.extend(["-p", ports])
        elif request.intensity is Intensity.DEEP:
            argv.extend(["-p", ports])
        else:
            argv.extend(["-p", ports])
        argv.extend(["-oG", "-"])
        argv.append(target)
        return argv

    def parse(self, stdout: str, stderr: str, request: ToolRequest) -> dict:
        services: list[dict[str, str]] = []
        for match in re.finditer(r"(\d+)/open/(tcp|udp)//([^/]*)", stdout):
            services.append(
                {
                    "port": match.group(1),
                    "proto": match.group(2),
                    "service": match.group(3).strip() or "unknown",
                    "state": "open",
                }
            )
        if not services:
            for match in re.finditer(
                r"(\d+)/(tcp|udp)\s+open(?:/[^,\s]*)?\s*([^\s,]*)",
                stdout,
            ):
                services.append(
                    {
                        "port": match.group(1),
                        "proto": match.group(2),
                        "service": match.group(3).strip() or "unknown",
                        "state": "open",
                    }
                )
        return {"services": services, "host": request.target}
