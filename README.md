# SecAgents

[![CI](https://github.com/YOUR_ORG/secagents/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_ORG/secagents/actions/workflows/ci.yml)

Python CLI that runs **autonomous multi-agent red teams** against your code—built for developers and security teams who want **fast, PoC-backed testing** without full manual pentest overhead or static-analysis noise.

**Full documentation (wiki-style):** [docs/wiki/Home.md](docs/wiki/Home.md) — installation, usage, GitHub Actions, operations. Replace `YOUR_ORG/secagents` in badge URLs and in `pyproject.toml` `[project.urls]` after you create the repository.

**Pipeline (default):** **Parallel specialists** (Code analyst + OSINT; with `--parallel-specialists 3+`, **Infra/Config** joins the same parallel wave) → **Recon** → **Exploit/PoC** → **Validator** → **Remediator**. Outputs merge into a **knowledge graph** (`knowledge_graph.json`, Mermaid in `report.md`) for shared attack documentation.

### Architectural Workflow

```mermaid
flowchart TD
    subgraph Config
        AppConfig[Config & CLI Arguments]
        Payloads[Sandbox Payloads / XSS, SQLi, etc.]
    end

    subgraph Agents["Parallel Specialists"]
        CA[Code Analyst]
        OS[OSINT Surface]
        IC[Infra/Config]
        IA[Intel Agent]
        IDOR[IDOR Agent]
        OA[OAuth Agent]
        RC[Race Cond Agent]
        LLM[LLM Feature Agent]
    end

    AppConfig --> Agents
    AppConfig --> Payloads
    Payloads -.-> Agents

    Agents --> Recon[Recon Agent]
    Recon --> Exploit[Exploit / PoC]
    Exploit --> Validator[Validator]
    Validator --> Remediator[Remediator]
    
    Exploit --> KB[(Knowledge Graph)]
    Validator --> KB
```

- **Agentic toolkit (sandbox image):** **HTTP proxy** (mitmproxy when install succeeds + `/opt/secagents/bin/mitm_sniff.sh`), **headless Chromium** (`secagents-chrome` per URL / “tab”), **batch shells**, **Python + bandit**, `rg`/`find`/`nmap`/`curl`/`openssl`/`nc`/`socat`, plus JRE/Node/Ruby/Go. Read-only `/workspace`; **no network** by default (enable for URL targets). **Rebuild** the image after upgrades: `docker rmi secagents-sandbox:latest` then run a scan.
- **PoC validation:** Findings separate into **validated** (command/output evidence) vs **needs triage** to reduce false positives.
- **Targets:** local folder, Git URL, or live `https://` URL (probe + optional network-backed checks).
- **LLMs:** OpenAI, Anthropic, or **Ollama**. Tune `--temperature`, `--top-p`, `--max-tokens`, `--max-turns`, `--recon-turns`, `--validation-turns`.
- **CLI:** `--team` / `--no-team`, `--parallel-specialists` (`1` off, `2` code+OSINT, **`3+` adds Infra/Config** in parallel), `--sandbox-timeout`, `--sandbox-shm`, `--remediation` / `--no-remediation`, CI via `secagents ci` + `.github/workflows/secagents.yml`.
- **Coverage:** Access control, injection, server-side (SSRF/XXE/deserialization), client-side (XSS/prototype pollution/DOM), business logic, auth/session, infrastructure misconfig (see prompts / model behavior).

> **Safety:** This tool runs attacker-style automation. Use only on code you own or are authorized to test. Review sandbox commands in transcripts; tune `--max-turns` and policies for your org.

## Quick start

1. Install [Docker](https://docs.docker.com/get-docker/) (daemon running).
2. Python 3.11+

```bash
cd sec
pip install -e .
python -m secagents doctor
# or, if Scripts/ is on PATH: secagents doctor
```

### Local Ollama (Docker pulls image + model)

```bash
secagents setup-ollama --model llama3.2
secagents scan ./my-app --provider ollama --model llama3.2 --setup-local-ai
```

### OpenAI / Anthropic

```bash
export OPENAI_API_KEY=sk-...
secagents scan ./my-app --provider openai --model gpt-4o-mini -f markdown --out-dir ./reports
```

## Commands

| Command | Purpose |
|--------|---------|
| `secagents version` | Print package version. |
| `secagents doctor` | Verify Docker is installed and the daemon responds. |
| `secagents setup-ollama` | `docker pull ollama/ollama`, start `secagents-ollama`, `ollama pull <model>`. |
| `secagents scan <target>` | Full scan (`--kind auto|local|repo|url`, `--team`, `--out-dir` → `report.md`, `report.json`, `autofix.md`). |
| `secagents ci <path>` | CI mode: same artifacts + exit code gate (`--fail-on high` default). |

### Scan examples

```bash
secagents scan ./src --provider ollama --model mistral --temperature 0.2 --max-turns 32
secagents scan https://github.com/org/repo --kind repo --branch main
secagents scan https://example.com --kind url --allow-network
```

## Configuration

Environment variables use the `SECAGENTS_` prefix (see `secagents.config.AppConfig`), plus standard `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`.

## GitHub deployment

- **`.github/workflows/ci.yml`** — Ruff + pytest on every push/PR (no Docker/LLM).
- **`.github/workflows/secagents.yml`** — PR scan with Docker + Ollama (or cloud LLM if secrets are set).
- **`.github/dependabot.yml`** — weekly dependency updates.

Optional repository **variables**: `SECAGENTS_OLLAMA_MODEL`, `SECAGENTS_PARALLEL_SPECIALISTS`.  
**Secrets**: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`.

Step-by-step: [docs/wiki/GitHub-Integration.md](docs/wiki/GitHub-Integration.md).

## Limitations

- Fully automated “hacking” is bounded by sandbox policy, turn limits, and LLM quality; **human review** remains essential.
- Installing Docker itself is not embedded (OS-specific); the CLI verifies availability and prints install hints.
- Large monorepos: context is **sampled**; increase `SECAGENTS_MAX_FILE_BYTES` / `SECAGENTS_MAX_FILES_IN_CONTEXT` with care.

## License

MIT — see [LICENSE](LICENSE). Security disclosures: [SECURITY.md](SECURITY.md). Contributing: [CONTRIBUTING.md](CONTRIBUTING.md). Changelog: [CHANGELOG.md](CHANGELOG.md).
