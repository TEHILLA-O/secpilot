from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from secpilot.config.settings import AppPaths
from secpilot.models import AuthorizedScope

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
_LOCAL_NAMES = {"localhost", "localhost.localdomain"}


class TargetRef(BaseModel):
    raw: str
    kind: str
    ip: str | None = None
    network: str | None = None
    hostname: str | None = None


class ScopeStore:
    def __init__(self, paths: AppPaths | None = None) -> None:
        self.paths = paths or AppPaths()
        self.paths.ensure()

    def load(self) -> AuthorizedScope:
        if not self.paths.scope_file.exists():
            return AuthorizedScope()
        raw = yaml.safe_load(self.paths.scope_file.read_text(encoding="utf-8")) or {}
        return AuthorizedScope.model_validate(raw)

    def save(self, scope: AuthorizedScope) -> None:
        self.paths.scope_file.write_text(
            yaml.safe_dump(scope.model_dump(mode="json"), sort_keys=False),
            encoding="utf-8",
        )

    def add(self, entry: str) -> AuthorizedScope:
        target = parse_target(entry)
        scope = self.load()
        if target.kind == "cidr":
            if target.raw not in scope.cidrs:
                scope.cidrs.append(target.raw)
        elif target.kind in {"ipv4", "ipv6"}:
            host = ipaddress.ip_address(target.ip or target.raw)
            prefix = 32 if host.version == 4 else 128
            cidr = f"{host}/{prefix}"
            if cidr not in scope.cidrs:
                scope.cidrs.append(cidr)
        else:
            name = (target.hostname or target.raw).lower()
            if name not in scope.hosts:
                scope.hosts.append(name)
        self.save(scope)
        return scope

    def remove(self, entry: str) -> AuthorizedScope:
        scope = self.load()
        lowered = entry.lower()
        scope.cidrs = [item for item in scope.cidrs if item != entry]
        scope.hosts = [item for item in scope.hosts if item != lowered]
        self.save(scope)
        return scope

    def contains(self, entry: str) -> bool:
        return target_in_scope(parse_target(entry), self.load())


def parse_target(value: str) -> TargetRef:
    raw = value.strip()
    if not raw:
        raise ValueError("empty target")
    if "/" in raw and _looks_like_cidr(raw):
        network = ipaddress.ip_network(raw, strict=False)
        return TargetRef(raw=str(network), kind="cidr", network=str(network))
    try:
        host = ipaddress.ip_address(raw)
        return TargetRef(raw=str(host), kind=f"ipv{host.version}", ip=str(host))
    except ValueError:
        pass
    hostname = raw.rstrip(".").lower()
    if hostname in _LOCAL_NAMES or _HOSTNAME_RE.match(hostname):
        return TargetRef(raw=hostname, kind="hostname", hostname=hostname)
    raise ValueError(f"unrecognised target: {value}")


def target_in_scope(target: TargetRef, scope: AuthorizedScope) -> bool:
    networks = [_safe_network(item) for item in scope.cidrs]
    networks = [item for item in networks if item is not None]
    if target.kind in {"ipv4", "ipv6"} and target.ip:
        address = ipaddress.ip_address(target.ip)
        return any(address in network for network in networks)
    if target.kind == "cidr" and target.network:
        candidate = ipaddress.ip_network(target.network, strict=False)
        return any(_network_covered(candidate, network) for network in networks)
    if target.kind == "hostname" and target.hostname:
        name = target.hostname.lower()
        if name in {item.lower() for item in scope.hosts}:
            return True
        return any(name == item.lower() or name.endswith(f".{item.lower()}") for item in scope.hosts)
    return False


def _network_covered(candidate: ipaddress.IPv4Network | ipaddress.IPv6Network, parent) -> bool:
    return candidate.version == parent.version and candidate.subnet_of(parent)


def _safe_network(value: str):
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _looks_like_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def extract_targets(text: str) -> list[str]:
    """Pull IPs, CIDRs, and obvious hostnames from a user request."""
    found: list[str] = []
    cidr_hits = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b", text)
    ip_hits = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    host_hits = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", text)
    for item in [*cidr_hits, *ip_hits, *host_hits, "localhost"]:
        if item == "localhost" and "localhost" not in text.lower():
            continue
        try:
            parsed = parse_target(item)
        except ValueError:
            continue
        if parsed.raw not in found:
            found.append(parsed.raw)
    return found


class ScopeFile(BaseModel):
    path: Path
    scope: AuthorizedScope = Field(default_factory=AuthorizedScope)
