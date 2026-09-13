# Contributing

Thanks for helping with SecPilot. Keep changes honest, small, and reviewable.

## Prerequisites

- Python 3.11 or newer
- Linux recommended for live tool adapters (parsers and most unit tests still run elsewhere)
- Optional: Rust toolchain if you touch `privileged-helper`
- Optional host tools for integration-style checks: nmap, curl, openssl, whatweb, lynis, dnsutils

## Setup

```bash
python -m pip install -e ".[dev]"
# or
uv sync
```

Set `SECPILOT_HOME` if you want config and sessions under a project directory instead of the user profile.

## Run

```bash
secpilot --help
# or
uv run secpilot --help
```

Useful smoke commands:

```bash
secpilot tools detect
secpilot model list
secpilot scope list
```

## Test

```bash
pytest
# or
uv run pytest
```

`pyproject.toml` sets `asyncio_mode = auto`, `testpaths = ["tests"]`, and `pythonpath = ["src"]`.

Lint:

```bash
ruff check src tests
```

## Privileged helper (optional)

```bash
cd privileged-helper
cargo build --release
```

Do not install the helper system-wide unless you understand the allowlist in that crate.

## Guidelines

- Prefer adapter argv builders over shell strings.
- Do not weaken permanent denials for exploitation, persistence, credential theft, or destructive actions.
- Document authorized-use assumptions in PR descriptions when behaviour changes.
- Keep commit messages short and human. No co-author trailers required.
