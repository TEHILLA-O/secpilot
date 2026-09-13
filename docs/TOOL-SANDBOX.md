# Tool sandbox

Adapters own the command line. The model only asks for a capability.

```json
{
  "tool": "service_discovery",
  "target": "10.10.10.24",
  "intensity": "normal"
}
```

`NmapAdapter.build_argv()` turns that into something like:

```
nmap -Pn -n --reason -T3 -sT -p 1-1024,3306,3389,5432,5900,6379,8080,8443,9200 -oG - 10.10.10.24
```

## Rules every adapter follows

- Build `list[str]` argv. Never interpolate into `sh -c`.
- Re-check scope inside `validate()`.
- Reject protected paths (`/etc/shadow`, SSH keys).
- Cap intensity (port ranges, packet counts, redirect hops).
- Parse stdout into a small dict the analyst can reason over.

## Built-in adapters

| Adapter | Capability | Toolpack |
| --- | --- | --- |
| NmapAdapter | service discovery / versions | network |
| DigAdapter | DNS lookup | network |
| WhoisAdapter | registration metadata | osint |
| CurlAdapter | HTTP headers / redirects | web |
| OpenSSLAdapter | TLS handshake inspection | web |
| WhatWebAdapter | technology identification | web |
| LynisAdapter | local host audit | host-audit |
| SystemctlAdapter | read-only unit status | host-audit |
| JournalctlAdapter | recent warning logs | host-audit |
| TsharkAdapter / TcpdumpAdapter | limited capture (lab) | network-analysis |
| File / Strings / ExifTool / Yara | local file review | forensics |

## Custom adapters

Drop a YAML toolpack in `~` or next to the repo `toolpacks/` directory, then register a `SecurityTool` subclass on `ToolRegistry`. The rest of SecPilot does not change.
