# Security Policy

## Authorized systems only

SecPilot is for defensive security work on systems you own or have explicit written authorization to assess. Unauthorized scanning, access, or testing is illegal. The project ships with an authorized-scope model and permanent denials for exploitation-class actions for that reason.

## Supported versions

This repository is under active development. Security fixes land on the default branch (`main`).

## Reporting a vulnerability

Please open a private GitHub security advisory on this repository, or email the maintainer listed on the GitHub profile, with:

- Affected component (policy engine, adapter, helper, CLI)
- Steps to reproduce on an authorized lab host
- Impact assessment (policy bypass, scope bypass, privilege escalation, data exposure)

Do not file public issues that include working exploit details against the helper or policy gate.

## Responsible use

- Keep `SECPILOT_HOME` and session/evidence directories on trusted storage.
- Treat model providers and API keys as secrets. Never commit them.
- The optional Rust privileged helper must remain allowlist-only. Do not broaden it for convenience.
- Lab mode still denies exploitation, persistence, credential theft, and destructive actions.

## Scope of this policy

This document covers the SecPilot codebase and packaging. It does not authorize offensive use against third-party networks or services.
