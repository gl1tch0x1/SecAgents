<div align="center">

```text
 🛡️ HARDENING & OPERATIONS
```

**Strategic Maintenance & Environment Security.**

*Maximize your squad's efficiency while preserving infrastructure integrity.*

</div>

---

## 🔐 THREAT MODEL & ISOLATION

- **Sandbox Policy**: All AI-driven commands are strictly executed within a **fortified Docker container**.
- **Data Integrity**: The target workspace is mounted as **read-only** by default.
- **Network Control**: Outbound traffic is **disabled** unless explicitly authorized via `--allow-network`.

> [!CAUTION]
> **PERIMETER SECURITY**: Treat SecAgents as a powerful offensive asset. Only deploy against systems within your **authorized testing perimeter**.

---

## 💸 ECONOMIC & LATENCY TUNING

Scale your intelligence based on mission-specific resource budgets:

- **SaaS Intelligence**: Every mission consumes API tokens. Optimize by reducing `--max-turns` or selecting mid-tier models (e.g., `gpt-4o-mini`).
- **Local Intelligence**: High compute requirement. Ensure your runner instances are provisioned with sufficient GPU/CPU headroom.
- **Image Persistence**: The `secagents-sandbox` image is a heavy asset. Cache this image on self-hosted runners to bypass rebuild latency.

---

## 🏗️ BASTION REFRESH PROTOCOL

Execute a full reconstruction of the sandbox environment after core updates:

```bash
# Purge the legacy construct
docker rmi secagents-sandbox:latest

# The next mission will automatically trigger a fresh, high-fidelity build.
```

---

## 📋 TROUBLESHOOTING MATRIX

| SYMPTOM | DIAGNOSTIC | RESOLUTION |
| :--- | :--- | :--- |
| `docker not found` | PATH Integrity | Install Docker and verify availability in the active shell. |
| `daemon failure` | Service State | Ensure Docker Desktop or the system service is active. |
| `module missing` | Python Context | Execute via `python -m secagents` within the active venv. |
| `Ollama timeout` | Network Bridge | Verify container logs and `SECAGENTS_OLLAMA_BASE_URL`. |

---

## 📂 DATA SECRECY

Engagement reports are high-sensitivity artifacts. They often contain source code snippets and command output that detail internal system logic. Treat all mission outputs as **Internal Restricted** data.

---

## 🏁 NEXT COMMAND

- Return to the **[Installation Protocols](Installation.md)**.
- Master the **[Usage Protocols](Usage.md)**.

<div align="center">
  <sub>SECAGENTS HARDENING MANUAL</sub>
</div>
