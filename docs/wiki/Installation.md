<div align="center">

```text
 🚀 DEPLOYMENT PROTOCOLS
```

**SecAgents Initialization & Setup.**

*Deploy the squad, fortify the sandbox, and prepare for tactical engagement.*

</div>

---

## 🏗️ PHASE 1: REQUISITE STACK

Execute these procedures to ensure the tactical environment is initialized.

### 🐳 STEP 1: DOCKER VIRTUALIZATION
SecAgents utilizes Docker for sandboxed execution and private AI instantiation.
- **Protocol**: Install **[Docker Engine](https://docs.docker.com/engine/install/)** or **[Docker Desktop](https://docs.docker.com/desktop/)**.
- **Verification**: `docker version` must return active system status.
- **Permission**: Ensure the current user has `docker` group escalation (Linux).

### 🐍 STEP 2: PYTHON COGNITIVE ENGINE
- **Protocol**: Install **Python 3.11 or newer** from **[python.org](https://www.python.org/downloads/)**.
- **Verification**: `python --version` must confirm v3.11+.

---

## ⚡ PHASE 2: SQUAD DEPLOYMENT

### 📂 STEP 3: CLONING THE NEXUS
```bash
git clone https://github.com/gl1tch0x1/SecAgents.git
cd SecAgents
```

### 🛡️ STEP 4: VIRTUAL ISOLATION
We recommend a dedicated virtual environment for all offensive operations:
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
```

### ⚙️ STEP 5: FRAMEWORK INITIALIZATION
```bash
# Core Installation
pip install -e .

# Optional: Advanced Development Hooks
pip install -e ".[dev]"
```

---

## 🩺 PHASE 3: SYSTEMS DIAGNOSTICS

Validate the integrity of your deployment:

```bash
secagents version
secagents doctor
```

> [!IMPORTANT]
> **DOCTOR REPORT**: If `secagents doctor` fails to reach the Docker daemon, all scan operations will be locked. Resolve Docker connectivity before proceeding.

---

## 🟢 OPTIONAL: PRIVATE AI COMMAND (OLLAMA)

For full data sovereignty, deploy a local LLM instance:

1.  **Initialize**: `secagents setup-ollama --model llama3.2`
2.  **Logic**: This provisions a local container, pulls model weights, and exposes the intelligence API to the framework.

---

## 🏁 NEXT MISSION PROTOCOL

- Learn to command the squad in **[Usage Protocols](Usage.md)**.
- Scale your operations in **[GitHub Automation](GitHub-Integration.md)**.

<div align="center">
  <sub>SECAGENTS DEPLOYMENT MANUAL</sub>
</div>
