# Security Policy

## Scope

SLHF generates **offline synthetic log data only**. It does not:
- Execute malware or exploit code
- Make outbound network connections (other than ctfcli uploading to your own CTFd instance)
- Access or exfiltrate real system logs
- Require elevated privileges

All generated content is fabricated. Event IDs, hostnames, IP addresses, process names, and user accounts are synthetic and do not correspond to real infrastructure.

## Reporting a vulnerability

If you discover a security issue in SLHF itself (e.g. a path traversal in the output writer, unsafe YAML parsing, or a dependency vulnerability), please report it by opening a **private security advisory** on the GitHub repository rather than a public issue.

Include:
- A description of the vulnerability
- Steps to reproduce
- Your assessment of the impact

We will respond within 5 business days.

## Dependencies

SLHF's runtime dependency surface is intentionally minimal:

| Package | Use | Notes |
|---|---|---|
| `pyyaml` | Playbook loading and CTFd export | Use `yaml.safe_load` only — never `yaml.load` |
| `ctfcli` | Optional: uploading challenges to CTFd | Not imported by SLHF; invoked as a CLI tool |

`pyyaml` is the only third-party package imported at runtime. All playbook YAML is loaded with `yaml.safe_load`, which does not execute arbitrary Python constructors.

## Generated content

The synthetic logs produced by SLHF are designed for blue-team training. They contain:
- Fictitious attack patterns referencing real MITRE ATT&CK technique IDs
- Realistic-looking process names, user account names, and Windows event structures
- No real credentials, no real IP addresses, no real hostnames from production systems

Do not use generated datasets as inputs to production security tooling without clearly labelling them as synthetic.
