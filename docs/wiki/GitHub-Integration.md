# 🔗 GitHub Automation Protocol

Deploy and orchestrate SecAgents within your CI/CD lifecycle. This guide covers **workflow deployment**, **secret management**, and **automated security gates**.

---

## 🏗️ Phase 1: Workflow Deployment

Provision your repository with the following automation blocks. Copy these from the core repo:

| Lifecycle Block | Security Role | Trigger |
| :--- | :--- | :--- |
| **`.github/workflows/ci.yml`** | **Lint & Unit Tests** | Every Push / PR |
| **`.github/workflows/secagents.yml`** | **Autonomous Security Scan** | PR / Manual |
| **`.github/dependabot.yml`** | **Dependency Hardening** | Weekly |

> [!IMPORTANT]
> Ensure all workflow files are committed to your default branch (usually `main`) to activate the automated security pipeline.

---

## 🛡️ Phase 2: Security & Intelligence

Choose your intelligence tier for the automated scanner:

### 🔑 Secret Management
Configure these in **Settings → Secrets and variables → Actions**:

| Interface | Purpose | Strategy |
| :--- | :--- | :--- |
| `OPENAI_API_KEY` | **Cloud Intelligence** | Bypasses local Ollama pull for high-speed scanning. |
| `ANTHROPIC_API_KEY` | **Deep Reasoning** | Bypasses local Ollama pull for complex scenarios. |

- If **no keys** are detected, the pipeline automatically spins up a local **Ollama** instance inside the runner.

### ⚙️ Operational Variables (Optional)
Configure these in **Settings → Secrets and variables → Actions → Variables**:

| Variable | Intelligence Control | Default |
| :--- | :--- | :--- |
| `SECAGENTS_OLLAMA_MODEL` | Local model tag for `ollama pull`. | `llama3.2` |
| `SECAGENTS_PARALLEL_SPECIALISTS` | Concurrent specialist count (`3+` for Infra). | `2` |

---

## ⚡ Phase 3: Gatekeeper Configuration

Enforce a "Secure by Default" merge strategy:

1.  Navigate to **Settings → Branches → Branch protection**.
2.  Target your protected branch (e.g., `main`).
3.  Enable **"Require status checks to pass before merging"**.
4.  Mandate these checks:
    - `CI / lint-test`: Ensures codebase integrity.
    - `SecAgents Scan / scan`: Blocks PRs with unresolved high-severity findings.

---

## 📦 Phase 4: Intelligence Artifacts

Every mission generates a **`secagents-report`** package. Access it from the **Actions** execution page:

- **`report.md`**: Human-readable debrief for reviewers.
- **`report.json`**: Machine-readable data for external aggregators.
- **`autofix.md`**: Unified diffs for rapid remediation.

---

## 🏁 Next Protocol

- **[Operations & Hardening](Operations.md)**: Advance your deployment.
- **[Installation](Installation.md)**: Rebuild your environment.

<div align="center">
  <sub>SecAgents Automation Command</sub>
</div>
