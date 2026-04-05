# Security policy

## Supported versions

| Version | Supported |
|--------|-----------|
| 0.1.x  | Yes       |

## Reporting a vulnerability

If you believe you have found a **security vulnerability in the SecAgents CLI or its packaging** (not findings it produces about other projects), please report it responsibly:

1. **Do not** open a public issue for undisclosed vulnerabilities.
2. Use GitHub **Private vulnerability reporting** (if enabled on the repository), or contact the maintainers through a private channel they publish in the repository README or org profile.

Include: affected version, reproduction steps, and impact.

## Scope and safe use

SecAgents is designed to run **offensive-style automation** inside a **Docker sandbox**. Misconfiguration or running it against systems you do not own or lack permission to test can cause harm or legal exposure.

- Run only on **authorized** codebases and endpoints.
- Treat LLM-generated commands and “findings” as **untrusted**; review transcripts before acting.
- **Secrets** in CI: prefer repository **secrets** and **environments** with restricted access; never commit API keys.

## Supply chain

- Pin dependencies in production CI where possible (`pip install secagents==x.y.z` or lock files).
- Review Dependabot PRs for `pyproject.toml` and GitHub Actions updates.
