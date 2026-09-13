# Architecture

SecPilot is an LLM-powered security operations terminal for authorized audits on Kali Linux, Parrot OS, Debian, and similar hosts. The model proposes work. A local policy engine decides what is executable. Adapters construct argv lists. The model never reaches a shell.

## Product purpose

Operators describe a defensive goal in natural language (for example: find what is exposed on a lab host and explain anything unusual). SecPilot classifies the request, plans capabilities, checks mode and authorized scope, asks for confirmation, runs allowlisted tools, stores structured evidence, and produces a report.

## Main components

| Component | Role |
| --- | --- |
| CLI / TUI | Typer commands and a Rich REPL (`src/secpilot/cli`, `src/secpilot/tui`) |
| LLM providers | `plan()` and `analyse()` only: Ollama, API, llama.cpp, or deterministic fallback |
| Policy engine | Mode (`observe` / `audit` / `lab`), authorized scope, permanent deny list |
| Tool registry | Capability name maps to an adapter that builds a fixed argv vector |
| Evidence store | JSON plus raw stdout/stderr on disk |
| Sessions | SQLite index and replay log |
| Reports | Markdown, HTML, and JSON exporters |
| Privileged helper | Optional Rust binary (`privileged-helper`) for allowlisted root ops |

## Data and control flow

```
You
 |
 v
SecPilot CLI / TUI
 |
 v
LLM Planner          (Ollama | API | llama.cpp | fallback)
 |
 v
Policy Engine        (mode + scope + deny-list)
 |
 v
Human approval (y/N)
 |
 v
Tool Registry        (capability -> adapter -> argv)
 |
 v
Structured evidence
 |
 v
LLM Analyst
 |
 v
Findings + report
```

`AuditWorkflow` implements this as an explicit state machine over Pydantic contracts. The planner emits a capability such as `service_discovery`, never a free-form command string. Out-of-scope hosts are refused before any argv is built.

## Why this is not shelling out LLM text

1. The planner emits a capability, never a command string.
2. `PolicyEngine` rejects out-of-scope targets and exploitation.
3. The matching adapter builds a fixed argv vector.
4. Execution uses `asyncio.create_subprocess_exec(*argv)`. `shell=True` is never used.
5. Privileged work, if needed, goes to a small Rust helper with its own allowlist.

## Package map

```
src/secpilot/
  cli/          Typer entrypoints
  tui/          Rich banner and report rendering
  llm/          Provider protocol + Ollama / API / llama.cpp / fallback
  agent/        Planner, analyser, workflow
  policy/       Engine, scope, permissions
  tools/        Adapters and registry
  evidence/     Structured store
  reports/      Markdown / HTML / JSON
  sessions/     SQLite + replay
  privileged/   Helper client
  config/       YAML settings
policies/       Policy definitions
toolpacks/      network, web, host-audit, forensics, osint, ...
tests/          pytest suite
```

## Related docs

- [Security model](SECURITY-MODEL.md)
- [Tool sandbox](TOOL-SANDBOX.md)
- [Authorized scope](AUTHORIZED-SCOPE.md)
- [Model providers](MODEL-PROVIDERS.md)
