# 🔒 Security Protocol

The security of the SecAgents framework is our highest priority. We follow a strict protocol for vulnerability disclosure and defensive operations.

---

## 🏛️ Supported Intelligence Versions

| Generation | Active | Status |
| :--- | :---: | :--- |
| **0.1.x** | ✅ | Maintained & Monitored |

---

## 🛰️ Vulnerability Reporting

If you identify a **vulnerability within the SecAgents framework** (CLI, Orchestrator, or Sandbox), please follow these protocols:

1.  **Strict Confidentiality**: Do **not** open a public issue for undisclosed vulnerabilities.
2.  **Reporting Channels**: Use GitHub's **Private Vulnerability Reporting** feature.
3.  **Intelligence Package**: Include the affected version, detailed reproduction steps, and potential mission impact.

---

## 🛡️ Operational Scope & Safety

SecAgents executes **offensive automation** within a **fortified Docker sandbox**. Misconfiguration or unauthorized deployment can result in technical or legal consequences.

- **Authorization**: Only engage targets within your **explicitly authorized** perimeter.
- **Verification**: Treat all LLM-generated commands as **untrusted intelligence**. Review all transcripts.
- **Secret Hygiene**: Always use repository **secrets** and **environments**. Never commit API keys to version control.

---

## ⛓️ Supply Chain Hardening

- **Pinning**: In production environments, always pin your deployment: `pip install secagents==x.y.z`.
- **Auditing**: Review all Dependabot pull requests for `pyproject.toml` and GitHub Action updates.

<div align="center">
  <sub>SecAgents Security Command</sub>
</div>
