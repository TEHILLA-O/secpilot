# Authorized scope

Network tests require an explicit allowlist.

```
secpilot scope add 10.10.10.0/24
secpilot scope add 192.168.56.0/24
secpilot scope add lab.example.com
secpilot scope list
```

```
AUTHORIZED SECURITY SCOPE

10.10.10.0/24
192.168.56.0/24
lab.example.com
```

## Enforcement

If a plan or operator request names `8.8.8.8` and that address is not inside a configured CIDR:

```
EXECUTION DENIED

Target:
8.8.8.8

Reason:
Target is outside the authorized security scope.

No command executed.
```

Hostnames match exactly or as a subdomain of a scoped name. Single IPs added with `scope add` are stored as `/32` or `/128` networks.

## Localhost

`localhost` and loopback addresses are still subject to scope. Add `127.0.0.1/32` or `localhost` before auditing the local host.
