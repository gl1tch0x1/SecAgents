# Usage

This page describes **commands**, **targets**, **LLM backends**, and **report outputs**.

---

## Command reference

Run with `python -m secagents <command>` (recommended) or `secagents <command>` if your `PATH` includes the Scripts directory.

| Command | Purpose |
|--------|---------|
| `version` | Print installed version |
| `doctor` | Verify Docker CLI + daemon |
| `setup-ollama` | Pull Ollama image, start container, pull a model |
| `scan <target>` | Full multi-agent scan (local path, git URL, or HTTPS URL) |
| `ci <path>` | CI mode: write artifacts + exit non-zero on severity threshold |

Use `--help` on any command:

```bash
python -m secagents scan --help
```

---

## Scan targets

| Kind | Example | Notes |
|------|---------|--------|
| Local | `python -m secagents scan ./myapp` | Directory on disk |
| Git repo | `python -m secagents scan https://github.com/org/repo --kind repo` | Cloned to a temp dir |
| Live URL | `python -m secagents scan https://example.com --kind url` | Probe + synthetic workspace; often needs `--allow-network` |

`--kind auto` guesses from the target string.

---

## LLM providers

### OpenAI

```bash
export OPENAI_API_KEY=sk-...
python -m secagents scan ./app --provider openai --model gpt-4o-mini --out-dir ./reports
```

### Anthropic

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python -m secagents scan ./app --provider anthropic --model claude-3-5-sonnet-latest --out-dir ./reports
```

### Ollama (local)

```bash
python -m secagents setup-ollama --model llama3.2
python -m secagents scan ./app --provider ollama --model llama3.2 --setup-local-ai --out-dir ./reports
```

Override base URL if needed:

```bash
python -m secagents scan ./app --provider ollama --ollama-url http://127.0.0.1:11434
```

---

## Team mode and parallel specialists

- **`--team` / `--no-team`:** Multi-agent pipeline vs single-orchestrator fast path.
- **`--parallel-specialists`:** `1` = no parallel opening; `2` = Code + OSINT; **`3+`** adds **Infra/Config** in parallel (opening phase).

Example:

```bash
python -m secagents scan ./app --team --parallel-specialists 3 --max-turns 28 --out-dir ./reports
```

---

## Sandbox and timeouts

- **`--sandbox-timeout`** — seconds for each sandbox command (default 300).
- **`--sandbox-shm`** — Docker `--shm-size` (default `1g`; helps Chromium).

---

## Outputs (`--out-dir`)

| File | Content |
|------|---------|
| `report.md` | Human-readable report, Mermaid orchestration, findings |
| `report.json` | Machine-readable full payload |
| `knowledge_graph.json` | Nodes/edges for findings and agents |
| `autofix.md` | Aggregated patches when remediation ran |

---

## CI gate

```bash
python -m secagents ci . --fail-on high --out-dir secagents-report
```

Exit code **1** if any finding is at or above `--fail-on` severity.

---

## Environment variables

Prefix **`SECAGENTS_`** maps to `AppConfig` (see `src/secagents/config.py`). Common examples:

- `SECAGENTS_MODEL`
- `SECAGENTS_MAX_AGENT_TURNS`
- `SECAGENTS_PARALLEL_SPECIALISTS`

Standard keys **`OPENAI_API_KEY`** and **`ANTHROPIC_API_KEY`** are also read.

---

## Next

[GitHub integration](GitHub-Integration.md) · [Operations](Operations.md)
