# 🎮 Operational Command Guide

Execute and orchestrate your SecAgents squad. This guide covers **commands**, **target vectors**, **LLM intelligence**, and **mission outputs**.

---

## 🛠️ Command Reference

Execute commands using the `secagents` CLI or `python -m secagents` (recommended for environment consistency).

| Command | Protocol | Action |
| :--- | :--- | :--- |
| **`version`** | `secagents version` | Display current build and orchestration version. |
| **`doctor`** | `secagents doctor` | Systems diagnostic for Docker and environment health. |
| **`setup-ollama`** | `secagents setup-ollama` | Provision a local Ollama instance for private AI. |
| **`scan`** | `secagents scan <target>` | Launch a full multi-agent red-team operation. |
| **`ci`** | `secagents ci <path>` | Execute a gatekeeper scan for CI/CD pipelines. |

> [!TIP]
> Use the `--help` flag on any command for detailed parameter documentation:
> ```bash
> secagents scan --help
> ```

---

## 🎯 Target Vectors

SecAgents can engage targets across multiple environments:

| Vector | Command Example | Deployment Notes |
| :--- | :--- | :--- |
| **Local Path** | `secagents scan ./myapp` | Direct file-system engagement. |
| **Git Repository** | `secagents scan <git-url> --kind repo` | Clones to a high-speed temporary workspace. |
| **Live URL** | `secagents scan <url> --kind url` | Probe-based engagement; usually requires `--allow-network`. |

---

## 🧠 LLM Intelligence Engines

Configure your squad's cognitive backend:

### 🔵 OpenAI (Global Intelligence)
```bash
export OPENAI_API_KEY=sk-...
secagents scan ./app --provider openai --model gpt-4o-mini
```

### 🟠 Anthropic (Advanced Reasoning)
```bash
export ANTHROPIC_API_KEY=sk-ant-...
secagents scan ./app --provider anthropic --model claude-3-5-sonnet-latest
```

### 🟢 Ollama (Private Operations)
```bash
secagents setup-ollama --model llama3.2
secagents scan ./app --provider ollama --model llama3.2 --setup-local-ai
```

---

## ⚡ Team Orchestration

- **`--team` / `--no-team`**: Switch between the full **multi-agent pipeline** and a single-orchestrator operation.
- **`--parallel-specialists`**: Adjust the intensity of the opening phase.
  - `1`: Serial engagement.
  - `2`: **Code Analyst** + **OSINT Surface**.
  - `3+`: Adds **Infra/Config** and beyond in a parallel wave.

```bash
secagents scan ./app --team --parallel-specialists 6 --max-turns 32
```

---

## 📊 Mission Outputs (`--out-dir`)

Findings are gathered into a structured intelligence package:

| Artifact | Intelligence Type | Contents |
| :--- | :--- | :--- |
| **`report.md`** | **Debrief** | Human-readable report, Mermaid flows, and VRT mappings. |
| **`report.json`** | **Data** | Full machine-readable payload for downstream tools. |
| **`knowledge_graph.json`** | **Relations** | Relational map of agents, assets, and findings. |
| **`autofix.md`** | **Neutralization** | Aggregated, battle-tested unified diff patches. |

---

## ⛓️ CI/CD Gatekeeper

Use the `ci` command to enforce security standards in your automation:

```bash
secagents ci . --fail-on high --out-dir sec_scan_results
```

- Returns **Exit Code 1** if findings at or above `--fail-on` (default: high) are discovered.

---

## 🏁 Next Protocol

- **[GitHub Integration](GitHub-Integration.md)**: Automate your squad.
- **[Operations & Hardening](Operations.md)**: Secure your environment.

<div align="center">
  <sub>SecAgents Operational Command</sub>
</div>
