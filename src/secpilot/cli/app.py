from __future__ import annotations

import typer
from rich.prompt import Confirm

from secpilot import __version__
from secpilot.agent.workflow import AuditWorkflow
from secpilot.cli.context import Runtime
from secpilot.config.settings import save_settings
from secpilot.evidence.store import EvidenceStore
from secpilot.llm.factory import apply_model_ref
from secpilot.models import ExecutionMode, SecurityContext
from secpilot.privileged.client import PrivilegedHelper
from secpilot.reports.generator import ReportGenerator
from secpilot.tui.banner import render_banner
from secpilot.tui.render import (
    render_assessment,
    render_inventory,
    render_plan,
    render_replay,
    render_sessions,
)

app = typer.Typer(
    name="secpilot",
    help="LLM-powered security operations terminal. The model plans; the policy engine decides.",
    no_args_is_help=False,
    add_completion=False,
)
model_app = typer.Typer(help="Select and inspect LLM providers.")
scope_app = typer.Typer(help="Manage authorized security scope.")
tools_app = typer.Typer(help="Detect and list security tool adapters.")
toolpack_app = typer.Typer(help="Enable capability packs.")
sessions_app = typer.Typer(help="List and replay audit sessions.")

app.add_typer(model_app, name="model")
app.add_typer(scope_app, name="scope")
app.add_typer(tools_app, name="tools")
app.add_typer(toolpack_app, name="toolpack")
app.add_typer(sessions_app, name="sessions")


def _runtime() -> Runtime:
    return Runtime.load()


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    mode: ExecutionMode | None = typer.Option(None, help="observe | audit | lab"),
    fallback: bool = typer.Option(False, help="Use the deterministic planner instead of an LLM."),
    version: bool = typer.Option(False, "--version", help="Show version and exit."),
) -> None:
    if version:
        typer.echo(__version__)
        raise typer.Exit()
    if ctx.invoked_subcommand is not None:
        return
    runtime = _runtime()
    if mode is not None:
        runtime.settings.mode = mode
        save_settings(runtime.settings, runtime.paths)
    _repl(runtime, fallback=fallback)


@app.command()
def ask(
    query: str = typer.Argument(..., help="Natural-language security request"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Approve execution without a prompt"),
    fallback: bool = typer.Option(False, help="Use the deterministic planner"),
) -> None:
    runtime = _runtime()
    if yes:
        runtime.settings.auto_approve = True
    _run_query(runtime, query, fallback=fallback)


@model_app.command("list")
def model_list() -> None:
    runtime = _runtime()
    current = f"{runtime.settings.model.provider}:{runtime.settings.model.name}"
    runtime.console.print("Available providers:\n")
    runtime.console.print("  ollama:<model>      Local Ollama")
    runtime.console.print("  llamacpp:<model>    llama.cpp server")
    runtime.console.print("  api:openai          OpenAI-compatible API")
    runtime.console.print("  api:anthropic       Anthropic API")
    runtime.console.print("  fallback:rules      Deterministic planner (no LLM)")
    runtime.console.print(f"\nCurrent: {current}")


@model_app.command("use")
def model_use(ref: str = typer.Argument(..., help="provider:name")) -> None:
    runtime = _runtime()
    runtime.settings = apply_model_ref(runtime.settings, ref)
    save_settings(runtime.settings, runtime.paths)
    runtime.console.print(
        f"Model set to {runtime.settings.model.provider}:{runtime.settings.model.name}"
    )


@scope_app.command("add")
def scope_add(entry: str = typer.Argument(...)) -> None:
    runtime = _runtime()
    scope = runtime.scope.add(entry)
    runtime.console.print("AUTHORIZED SECURITY SCOPE\n")
    _print_scope(runtime, scope)


@scope_app.command("remove")
def scope_remove(entry: str = typer.Argument(...)) -> None:
    runtime = _runtime()
    scope = runtime.scope.remove(entry)
    _print_scope(runtime, scope)


@scope_app.command("list")
def scope_list() -> None:
    runtime = _runtime()
    runtime.console.print("AUTHORIZED SECURITY SCOPE\n")
    _print_scope(runtime, runtime.scope.load())


@tools_app.command("detect")
def tools_detect() -> None:
    runtime = _runtime()
    render_inventory(runtime.console, runtime.detector.inventory(runtime.os_profile()))


@toolpack_app.command("enable")
def toolpack_enable(name: str = typer.Argument(...)) -> None:
    runtime = _runtime()
    known = runtime.toolpacks.names()
    if name not in known:
        runtime.console.print(f"Unknown toolpack '{name}'. Known: {', '.join(known)}")
        raise typer.Exit(code=1)
    if name not in runtime.settings.enabled_toolpacks:
        runtime.settings.enabled_toolpacks.append(name)
        save_settings(runtime.settings, runtime.paths)
    runtime.console.print(f"Enabled toolpack: {name}")


@toolpack_app.command("list")
def toolpack_list() -> None:
    runtime = _runtime()
    enabled = set(runtime.settings.enabled_toolpacks)
    for manifest in runtime.toolpacks.list_manifests():
        mark = "on" if manifest.name in enabled else "off"
        runtime.console.print(f"{manifest.name:20} {mark:4}  {manifest.description}")


@sessions_app.callback(invoke_without_command=True)
def sessions_root(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is not None:
        return
    runtime = _runtime()
    render_sessions(runtime.console, runtime.sessions.list())


@app.command()
def replay(session_id: str = typer.Argument(...)) -> None:
    runtime = _runtime()
    record = runtime.sessions.get(session_id)
    if record is None:
        runtime.console.print(f"Unknown session {session_id}")
        raise typer.Exit(code=1)
    render_replay(runtime.console, record, runtime.sessions.events(record.directory))


@app.command()
def report(
    session_id: str = typer.Argument(...),
    fmt: str = typer.Option("markdown", "--format", help="markdown | html | json"),
) -> None:
    if fmt not in {"markdown", "html", "json"}:
        raise typer.BadParameter("format must be markdown, html, or json")
    runtime = _runtime()
    record = runtime.sessions.get(session_id)
    if record is None:
        runtime.console.print(f"Unknown session {session_id}")
        raise typer.Exit(code=1)
    from pathlib import Path

    assessment_path = Path(record.directory) / "assessment.json"
    if not assessment_path.exists():
        runtime.console.print("Session has no stored assessment.")
        raise typer.Exit(code=1)
    from secpilot.models import SecurityAssessment

    assessment = SecurityAssessment.model_validate_json(assessment_path.read_text(encoding="utf-8"))
    evidence = EvidenceStore(Path(record.directory)).list()
    path = ReportGenerator(runtime.sessions).write(record, assessment, evidence, fmt)
    runtime.console.print(f"Wrote {path}")


@app.command()
def mode(value: ExecutionMode = typer.Argument(...)) -> None:
    runtime = _runtime()
    runtime.settings.mode = value
    save_settings(runtime.settings, runtime.paths)
    runtime.console.print(f"Mode set to {value.value}")


def _print_scope(runtime: Runtime, scope) -> None:
    entries = [*scope.cidrs, *scope.hosts]
    if not entries:
        runtime.console.print("(empty)")
        return
    for item in entries:
        runtime.console.print(item)


def _scope_lines(runtime: Runtime) -> list[str]:
    scope = runtime.scope.load()
    return [*scope.cidrs, *scope.hosts]


def _repl(runtime: Runtime, fallback: bool) -> None:
    tools = runtime.detector.inventory(runtime.os_profile())
    render_banner(
        runtime.console,
        runtime.os_profile(),
        runtime.username(),
        runtime.settings,
        _scope_lines(runtime),
        tools,
    )
    while True:
        try:
            query = runtime.console.input("[bold cyan]secpilot >[/bold cyan] ").strip()
        except (EOFError, KeyboardInterrupt):
            runtime.console.print()
            return
        if not query or query in {"exit", "quit"}:
            return
        if query == "tools detect":
            render_inventory(runtime.console, tools)
            continue
        if query == "scope list":
            _print_scope(runtime, runtime.scope.load())
            continue
        _run_query(runtime, query, fallback=fallback)


def _run_query(runtime: Runtime, query: str, fallback: bool) -> None:
    scope = runtime.scope.load()
    tools = [item.name for item in runtime.detector.inventory() if item.installed]
    context = SecurityContext(
        user_query=query,
        mode=runtime.settings.mode,
        scope=scope,
        os_family=runtime.os_profile().family,
        os_pretty=runtime.os_profile().pretty,
        username=runtime.username(),
        model_ref=f"{runtime.settings.model.provider}:{runtime.settings.model.name}",
        enabled_toolpacks=runtime.settings.enabled_toolpacks,
        available_tools=tools or [item.name for item in runtime.registry.all()],
    )

    async def approve(plan, operations) -> bool:
        render_plan(runtime.console, plan, operations)
        if runtime.settings.auto_approve:
            return True
        return Confirm.ask("Execute?", default=False)

    workflow = AuditWorkflow(
        runtime.settings,
        runtime.provider(fallback=fallback or runtime.settings.model.provider == "fallback"),
        runtime.registry,
        runtime.sessions,
        PrivilegedHelper(runtime.settings.helper_path),
    )
    import asyncio

    result = asyncio.run(workflow.run(context, approve))
    if result.denied:
        runtime.console.print()
        runtime.console.print(result.denied)
        return
    if result.assessment:
        render_assessment(runtime.console, result.assessment)
        runtime.console.print(f"Evidence stored:\n{result.session.directory}\n")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
