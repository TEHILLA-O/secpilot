from __future__ import annotations

import os
import platform
from pathlib import Path

from secpilot.models import OsProfile

_FAMILY_MAP = {
    "kali": "kali",
    "parrot": "parrot",
    "parrotsecurity": "parrot",
    "ubuntu": "ubuntu",
    "debian": "debian",
    "fedora": "fedora",
    "arch": "arch",
    "manjaro": "arch",
}


def detect_os() -> OsProfile:
    os_release = _read_os_release()
    ident = (os_release.get("ID") or "").lower()
    id_like = [part for part in (os_release.get("ID_LIKE") or "").lower().split() if part]
    pretty = os_release.get("PRETTY_NAME") or platform.platform()
    family = _FAMILY_MAP.get(ident)
    if family is None:
        for like in id_like:
            family = _FAMILY_MAP.get(like)
            if family:
                break
    if family is None:
        family = "other"
    return OsProfile(
        family=family,  # type: ignore[arg-type]
        pretty=pretty,
        id_like=id_like,
        kernel=platform.release(),
    )


def current_username() -> str:
    return os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"


def _read_os_release() -> dict[str, str]:
    path = Path("/etc/os-release")
    if not path.exists():
        return {}
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw = line.split("=", 1)
        values[key] = raw.strip().strip('"')
    return values
