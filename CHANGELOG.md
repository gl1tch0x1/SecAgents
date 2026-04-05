# Changelog

All notable changes to this project are documented here.

## [0.1.1] — 2026-04-05

- GitHub: split **CI** workflow (ruff + pytest) from **SecAgents Scan** workflow; pip cache; `python -m secagents` in Actions; concurrency groups; optional `SECAGENTS_PARALLEL_SPECIALISTS` repo variable.
- **Dependabot** for Actions and pip.
- **SECURITY.md**, **CONTRIBUTING.md**, **py.typed** (PEP 561).
- **Wiki-style docs** under `docs/wiki/` (Installation, Usage, GitHub integration, Operations).
- CLI: **`version`** command.
- Tests: `tests/` smoke suite for config, package version, knowledge graph.

## [0.1.0] — Initial public shape

- Multi-agent red-team CLI, Docker sandbox, Ollama/OpenAI/Anthropic, reports and knowledge graph.
