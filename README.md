# SecPilot

LLM-powered security operations terminal for Kali Linux, Parrot OS, Debian, and similar systems.

The model plans. **Your policy engine decides what actually runs.**

```
You
 │
 ▼
┌─────────────────────────────┐
│        SecPilot CLI/TUI     │
└──────────────┬──────────────┘
               │
               ▼
        LLM Planner
               │
               ▼
        Policy Engine
       Is target allowed?
       Is tool allowed?
       Is action safe?
               │
               ▼
      Execution Approval
               │
               ▼
        Tool Registry
     nmap · openssl · curl · lynis · …
               │
               ▼
       Structured Evidence
               │
               ▼
    Findings + Explanation
```

This is not `os.system(llm_response)`.

## What using it looks like

```
$ secpilot scope add 10.10.10.0/24
$ secpilot

╭──────────────────── SECPILOT ────────────────────╮
│ OS        Kali Linux                             │
│ User      victrom                                │
│ Model     qwen3 via Ollama                       │
│ Mode      AUTHORIZED-AUDIT                       │
│ Scope     10.10.10.0/24                          │
│ Detected security tools: 18                      │
╰──────────────────────────────────────────────────╯

secpilot > Find what is exposed on my lab server 10.10.10.24
           and explain anything unusual.
```

SecPilot answers with a plan, waits for `y/N`, then stores structured evidence and a report. Out-of-scope hosts such as `8.8.8.8` are refused before any command is built.

## Install

```bash
# from a clone
pipx install .

# or with uv
uv sync
uv run secpilot --help
```

Set `SECPILOT_HOME` to keep config and sessions in a project directory instead of the user profile.

On Kali / Debian / Parrot:

```bash
sudo apt install nmap curl openssl whatweb lynis dnsutils
pipx install .
secpilot tools detect
```

Optional privileged helper (Rust):

```bash
cd privileged-helper
cargo build --release
sudo install -m 0755 target/release/secpilot-helper /usr/local/bin/secpilot-helper
```

The Python process stays a normal user. The helper only executes an allowlisted argv list.

## Model support

```
secpilot model list
secpilot model use ollama:qwen3
secpilot model use ollama:llama
secpilot model use api:openai
secpilot model use api:anthropic
secpilot model use fallback:rules
```

The rest of SecPilot does not care which provider is selected. If the model is offline, the deterministic planner still produces a defensive plan and the policy engine still gates it.

## Modes

| Mode | Executes tools? | Typical use |
| --- | --- | --- |
| `observe` | No | Explain output, recommend commands |
| `audit` | Approved recon + local defensive checks | Authorized assessments |
| `lab` | Audit plus limited capture / file matching | Your VMs and lab ranges |

```
secpilot mode lab
```

Even in lab mode, exploitation, persistence, credential theft, and destructive actions are permanently denied.

## Scope

```
secpilot scope add 10.10.10.0/24
secpilot scope add lab.example.com
secpilot scope list
```

## Toolpacks

```
secpilot toolpack list
secpilot toolpack enable network
secpilot toolpack enable web
secpilot toolpack enable host-audit
secpilot toolpack enable forensics
```

| Toolpack | Example adapters |
| --- | --- |
| network | nmap, dig, ip, ss |
| web | curl, openssl, whatweb |
| host-audit | lynis, systemctl, journalctl |
| network-analysis | tshark, tcpdump (lab) |
| forensics | file, strings, exiftool, yara |
| osint | whois, dig |

## Sessions and reports

```
secpilot sessions
secpilot replay LAB-A1B
secpilot report LAB-A1B --format markdown
secpilot report LAB-A1B --format html
secpilot report LAB-A1B --format json
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY-MODEL.md)
- [Tool sandbox](docs/TOOL-SANDBOX.md)
- [Authorized scope](docs/AUTHORIZED-SCOPE.md)
- [Model providers](docs/MODEL-PROVIDERS.md)

## Development

```bash
python -m pip install -e ".[dev]"
pytest
```

## Legal

Only use SecPilot against systems you own or have explicit authorization to assess. Unauthorized scanning or access is illegal.
