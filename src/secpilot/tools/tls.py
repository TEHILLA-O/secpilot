from __future__ import annotations

import re

from secpilot.models import OperationCategory, ToolRequest
from secpilot.tools.base import SecurityTool

_WEAK_HINTS = (
    "TLSv1\n",
    "TLSv1.0",
    "TLSv1.1",
    "SSLv2",
    "SSLv3",
    "RC4",
    "DES-CBC",
    "NULL-SHA",
    "EXP-",
)


class OpenSSLAdapter(SecurityTool):
    name = "openssl"
    binary = "openssl"
    toolpack = "web"
    categories = frozenset({OperationCategory.TLS_INSPECTION})

    def build_argv(self, request: ToolRequest, target: str) -> list[str]:
        host, port = _split_host_port(target, default_port=443)
        # s_client reads stdin; we close it immediately via execute() stdin=None.
        return [
            self.binary,
            "s_client",
            "-connect",
            f"{host}:{port}",
            "-servername",
            host,
            "-brief",
        ]

    async def execute(self, request: ToolRequest, argv: list[str] | None = None):
        import asyncio
        import time

        from secpilot.models import ToolResult

        command = argv or self.build_argv(request, request.target)
        started = time.perf_counter()
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        assert proc.stdin is not None
        proc.stdin.close()
        try:
            stdout_b, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
        except TimeoutError:
            proc.kill()
            stdout_b, _ = await proc.communicate()
        duration_ms = int((time.perf_counter() - started) * 1000)
        stdout = stdout_b.decode("utf-8", errors="replace")
        return ToolResult(
            tool=self.name,
            category=request.category,
            target=request.target,
            argv=command,
            exit_code=proc.returncode or 0,
            stdout=stdout,
            parsed=self.parse(stdout, "", request),
            duration_ms=duration_ms,
        )

    def parse(self, stdout: str, stderr: str, request: ToolRequest) -> dict:
        protocol = ""
        cipher = ""
        proto_match = re.search(r"Protocol\s*:\s*(\S+)", stdout)
        cipher_match = re.search(r"Ciphersuite\s*:\s*(\S+)", stdout) or re.search(
            r"Cipher\s*:\s*(\S+)", stdout
        )
        if proto_match:
            protocol = proto_match.group(1)
        if cipher_match:
            cipher = cipher_match.group(1)
        weak = [hint.strip() for hint in _WEAK_HINTS if hint.strip() in stdout or hint in protocol]
        if protocol in {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"}:
            weak.append(protocol)
        return {
            "protocol": protocol,
            "cipher": cipher,
            "weak_indicators": sorted(set(weak)),
            "connected": "CONNECTED" in stdout or bool(protocol),
        }


def _split_host_port(target: str, default_port: int) -> tuple[str, int]:
    if target.count(":") == 1 and not target.startswith("["):
        host, port_s = target.split(":", 1)
        try:
            return host, int(port_s)
        except ValueError:
            return target, default_port
    return target, default_port
