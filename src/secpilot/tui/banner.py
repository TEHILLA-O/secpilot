from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from secpilot.config.settings import Settings
from secpilot.models import DetectedTool, OsProfile


def render_banner(
    console: Console,
    os_profile: OsProfile,
    username: str,
    settings: Settings,
    scope_lines: list[str],
    tools: list[DetectedTool],
) -> None:
    installed = sum(1 for item in tools if item.installed)
    body = Table.grid(padding=(0, 2))
    body.add_column(style="dim")
    body.add_column()
    body.add_row("OS", os_profile.pretty)
    body.add_row("User", username)
    body.add_row("Model", f"{settings.model.provider}:{settings.model.name}")
    body.add_row("Mode", settings.mode.value.upper().replace("AUDIT", "AUTHORIZED-AUDIT"))
    body.add_row("Scope", ", ".join(scope_lines) or "(none configured)")
    body.add_row("Detected security tools", str(installed))
    title = Text("SECPILOT", style="bold cyan")
    console.print()
    console.print(Panel(body, title=title, border_style="cyan", width=62))
    console.print()
