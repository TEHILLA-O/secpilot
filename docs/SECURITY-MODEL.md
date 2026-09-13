# Security model

SecPilot is designed for authorized defensive work on systems you own or have written permission to assess.

## Permanent denials

These never execute, in any mode, even with operator approval in the TUI:

- Exploitation and payload delivery
- Persistence
- Credential exfiltration
- Data destruction
- Unrestricted autonomous attacking
- Password guessing
- Passing model text to a shell

## Execution modes

| Mode | LLM may | LLM may not |
| --- | --- | --- |
| **observe** | Read supplied output, recommend commands, explain tools | Execute anything |
| **audit** | Approved reconnaissance, TLS/HTTP inspection, local defensive host audit, log review | Packet capture, YARA, anything outside scope |
| **lab** | Audit plus limited capture/file matching on an explicit scope | Destructive, persistent, or exploit actions |

Lab mode is for local VMs, lab networks, and ranges you are authorized to test. It is not a license to attack the public Internet.

## Privilege separation

The Python application is intended to run as a normal user.

```
SecPilot (unprivileged)
        │
        │ approved privileged request
        ▼
secpilot-helper (Rust)
        │
        ▼
allowlisted argv only
```

The helper:

- Reads one JSON object from stdin
- Accepts only `nmap`, `tshark`, `tcpdump`, `journalctl`, `lynis`
- Executes argv, never a shell string
- Returns structured JSON

Do not `chmod +s` the Python package. If you install the helper setuid or with file capabilities, keep the allowlist small and review it.

## Operator duties

- Configure scope before any network test: `secpilot scope add 10.10.10.0/24`
- Keep the default approval prompt enabled
- Treat session directories as sensitive (they contain tool output)
- Do not point SecPilot at hosts you are not authorized to test
