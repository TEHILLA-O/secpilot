from __future__ import annotations

import pytest

from secpilot.models import AuthorizedScope, Intensity, OperationCategory, ToolRequest
from secpilot.tools.files import FileAdapter
from secpilot.tools.nmap import NmapAdapter
from secpilot.tools.tls import OpenSSLAdapter
from secpilot.tools.web import CurlAdapter


@pytest.mark.asyncio
async def test_nmap_builds_argv_not_a_shell_string(lab_scope) -> None:
    adapter = NmapAdapter()
    request = ToolRequest(
        tool="nmap",
        category=OperationCategory.SERVICE_DISCOVERY,
        target="10.10.10.24",
        intensity=Intensity.NORMAL,
    )
    result = await adapter.validate(request, lab_scope)
    assert result.allowed
    assert result.argv[0] == "nmap"
    assert "10.10.10.24" in result.argv
    assert not any(";" in part or "|" in part or "`" in part for part in result.argv)
    assert "-oG" in result.argv


@pytest.mark.asyncio
async def test_adapter_rejects_out_of_scope() -> None:
    adapter = NmapAdapter()
    request = ToolRequest(
        tool="nmap",
        category=OperationCategory.SERVICE_DISCOVERY,
        target="8.8.8.8",
    )
    result = await adapter.validate(request, AuthorizedScope(cidrs=["10.10.10.0/24"]))
    assert result.allowed is False


def test_openssl_and_curl_argv() -> None:
    tls = OpenSSLAdapter().build_argv(
        ToolRequest(
            tool="openssl",
            category=OperationCategory.TLS_INSPECTION,
            target="10.10.10.24",
        ),
        "10.10.10.24",
    )
    assert tls[:2] == ["openssl", "s_client"]
    assert "10.10.10.24:443" in tls

    curl = CurlAdapter().build_argv(
        ToolRequest(
            tool="curl",
            category=OperationCategory.HTTP_PROBE,
            target="10.10.10.24",
            extra={"scheme": "http"},
        ),
        "10.10.10.24",
    )
    assert curl[0] == "curl"
    assert "http://10.10.10.24" in curl


def test_file_adapter_blocks_shadow() -> None:
    adapter = FileAdapter()
    with pytest.raises(ValueError):
        adapter.build_argv(
            ToolRequest(
                tool="file",
                category=OperationCategory.FILE_IDENTIFY,
                target="/etc/shadow",
            ),
            "/etc/shadow",
        )


def test_nmap_parses_greppable_output() -> None:
    adapter = NmapAdapter()
    stdout = (
        "Host: 10.10.10.24 ()  Ports: "
        "22/open/tcp//ssh///, 80/open/tcp//http///, "
        "443/open/tcp//https///, 5432/open/tcp//postgresql///"
    )
    parsed = adapter.parse(
        stdout,
        "",
        ToolRequest(
            tool="nmap",
            category=OperationCategory.SERVICE_DISCOVERY,
            target="10.10.10.24",
        ),
    )
    ports = {item["port"] for item in parsed["services"]}
    assert ports == {"22", "80", "443", "5432"}
