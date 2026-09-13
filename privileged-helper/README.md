# secpilot-helper

Small Rust binary that the unprivileged Python process can call for operations that need extra Linux capabilities.

## Protocol

stdin: one JSON object

```json
{"op": "service_discovery", "argv": ["nmap", "-sT", "-p", "22", "10.10.10.24"]}
```

stdout: a `ToolResult`-shaped JSON object.

Allowed binaries: `nmap`, `tshark`, `tcpdump`, `journalctl`, `lynis`.

No shell. No free-form command strings.
