<div align="center">

```text
 🎮 OPERATIONAL COMMAND
```

**Execution Protocols & Mission Controls.**

*Command your squad, choose your targets, and orchestrate the engagement.*

</div>

---

## 🛠️ COMMAND CONSOLE

Initialize commands using the `secagents` binary or `python -m secagents`.

| COMMAND | MISSION ROLE |
| :--- | :--- |
| **`version`** | Display current build and orchestration version. |
| **`doctor`** | Diagnostic run for Docker and environment health. |
| **`setup-ollama`** | Provision a local Ollama instance for private AI. |
| **`scan <target>`** | Launch a full multi-agent red-team operation. |
| **`ci <path>`** | Execute a gatekeeper scan for CI/CD pipelines. |

> [!TIP]
> **INTELLIGENCE HELP**: Use `--help` on any command for a deep dive into available tactical flags.
> ```bash
> secagents scan --help
> ```

---

## 🎯 TARGET VECTORING

SecAgents can engage across multiple threat vectors:

| VECTOR | PROTOCOL | MISSION NOTES |
| :--- | :--- | :--- |
| **Local Path** | `secagents scan ./myapp` | Targeted filesystem engagement. |
| **Git Repository** | `secagents scan <url> --kind repo` | High-speed cloning to temporary workspace. |
| **Live URL** | `secagents scan <url> --kind url` | Synthesized workspace via probe probes. |

---

## 🧠 LLM INTELLIGENCE TIERS

Configure the cognitive backend of your squad:

### 🔵 OPENAI (GLOBAL REACH)
```bash
export OPENAI_API_KEY=sk-...
secagents scan ./app --provider openai --model gpt-4o-mini
```

### 🟠 ANTHROPIC (REASONING SPECIALIST)
```bash
export ANTHROPIC_API_KEY=sk-ant-...
secagents scan ./app --provider anthropic --model claude-3-5-sonnet-latest
```

### 🟢 OLLAMA (SOVEREIGN PRIVATE)
```bash
secagents setup-ollama --model llama3.2
secagents scan ./app --provider ollama --model llama3.2 --setup-local-ai
```

---

## ⚡ TEAM ORCHESTRATION

- **`--team`**: Deploy the full **multi-agent pipeline** (Recon → Exploit → Validator → Remediator).
- **`--parallel-specialists`**: Scale the intensity of the opening intelligence wave.
  - `2`: **GHOST-ANALYST** + **SURFACE-MAP**.
  - `3+`: Parallel activation of **INFRA-BASE** and specialized hunters.

```bash
secagents scan ./app --team --parallel-specialists 6 --max-turns 32
```

---

## 📊 INTELLIGENCE PACKAGE (`--out-dir`)

Findings are consolidated into an actionable mission debrief:

- **`report.md`**: Human-readable intelligence, Mermaid attack flows, and VRT platform mappings.
- **`report.json`**: Machine-readable data for external security aggregators.
- **`autofix.md`**: Aggregated, battle-tested unified diff patches for rapid remediation.
- **`knowledge_graph.json`**: Relational map of discovered assets and vulnerability nodes.

---

## 🏁 NEXT COMMAND

- Automate your squad in **[GitHub Automation](GitHub-Integration.md)**.
- Secure the command center in **[Operations & Hardening](Operations.md)**.

<div align="center">
  <sub>SECAGENTS OPERATIONAL MANUAL</sub>
</div>
