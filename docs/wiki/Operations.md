# 🛡️ Operations & Hardening Protocol

Production-grade deployment and maintenance strategies for SecAgents. Ensure your squad operates at peak efficiency while maintaining a secure infrastructure.

---

## 🔐 Threat Model & Scope

- **Sandbox Fortification**: All LLM-driven commands are executed within a **hardened Docker sandbox**.
- **Isolation Strategy**: The target workspace is mounted **read-only** by default to prevent accidental data mutation.
- **Network Policy**: Outbound network access is **disabled** by default. Mission-critical URL targets require the `--allow-network` override.

> [!CAUTION]
> Treat SecAgents as a high-impact offensive tool. Only deploy against assets within your **authorized testing perimeter**.

---

## 💸 Optimization & Latency

Scale your intelligence based on your operational budget:

- **Cloud Intelligence (SaaS)**: Every mission consumes API tokens. Optimize by adjusting `--max-turns` or choosing cost-effective models like `gpt-4o-mini`.
- **Local Intelligence (Ollama)**: Requires significant GPU/CPU resources. Ensure your runners are provisioned for high-compute tasks.
- **Sandbox Build**: The initial build of `secagents-sandbox` is resource-heavy. We recommend caching this image on self-hosted runners.

---

## 🏗️ Rebuilding the Bastion

Update your sandbox environment after every core upgrade or `Dockerfile.sandbox` modification:

```bash
# Purge the old construct
docker rmi secagents-sandbox:latest

# The next mission will automatically initialize a fresh build.
```

---

## 📋 Troubleshooting Matrix

| Symptom | Intelligence Check | Resolution |
| :--- | :--- | :--- |
| `docker not found` | Environment PATH | Install Docker and verify binary availability. |
| `daemon connection failure` | Service Status | Ensure Docker Desktop or the system service is active. |
| `module not found` | Python Context | Execute via `python -m secagents` within your active venv. |
| `Ollama timeout` | Network / Firewall | Verify `SECAGENTS_OLLAMA_BASE_URL` and container status. |
| `Parse syntax errors` | Model Reasoning | Upgrade to a higher-tier model or reduce `--temperature`. |

---

## 📂 Data Retention & Secrecy

- **Artifact Sensitivity**: Engagement reports may contain sensitive code snippets and command logs.
- **Access Control**: Treat all reports as **Internal/Confidential** data.
- **Retention Policy**: Configure your repository's Action settings to automatically purge artifacts based on your organization's compliance requirements.

---

## 🔄 Upgrade Protocol

Follow these steps to synchronize with the latest SecAgents intelligence:

1.  **Pull** the latest core intelligence: `git pull origin main`.
2.  **Synchronize** dependencies: `pip install -e .`.
3.  **Refresh** the bastion: `docker rmi secagents-sandbox:latest`.
4.  **Validate** systems: `python -m pytest tests/ -q`.

---

## 🏁 Missions Completed

- **[Main README](../../README.md)**: Return to Command Center.
- **[Home Guide](Home.md)**: Explore the Wiki.

<div align="center">
  <sub>SecAgents Operations Command</sub>
</div>
