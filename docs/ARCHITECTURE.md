# Architecture

SecPilot is an LLM-powered security operations terminal. The model proposes work. A local policy engine decides what is executable. Adapters construct argv lists. The model never reaches a shell.

```
You
 │
 ▼
SecPilot CLI / TUI
 │
 ▼
LLM Planner          (Ollama | API | llama.cpp | fallback)
 │
 ▼
Policy Engine        (mode + scope + deny-list)
 │
 ▼
Human approval
 │
 ▼
Tool Registry        (capability → adapter → argv)
 │
 ▼
Structured evidence
 │
 ▼
LLM Analyst
 │
 ▼
Findings + report
```

## Layers

| Layer | Responsibility |
| --- | --- |
| CLI / TUI | Typer commands and a Rich REPL |
| LLM providers | `plan()` and `analyse()` only |
| Policy | Mode, authorized scope, permanent denials |
| Adapters | Validate target + build argv + parse stdout |
| Evidence | JSON + raw output on disk |
| Sessions | SQLite index and replay log |
| Privileged helper | Optional Rust binary for allowlisted root ops |

## Why this is not `os.system(llm_response)`

1. The planner emits a capability (`service_discovery`), never a command string.
2. `PolicyEngine` rejects out-of-scope targets and exploitation.
3. The matching adapter builds a fixed argv vector.
4. `asyncio.create_subprocess_exec(*argv)` is used. `shell=True` is never used.
5. Privileged work, if needed, goes to a small Rust helper with its own allowlist.

## Workflow

```
USER → Scope Validator → Planner → Policy → Tool Selection
     → Human Approval → Execute → Parse
     → more evidence? → Replan : Correlate → Report
```

`AuditWorkflow` implements this as an explicit state machine. LangGraph is optional later if you want graph persistence; the contracts are already Pydantic models.

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
```
