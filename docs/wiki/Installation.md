# 🚀 Installation Operation

Follow these protocols **in sequence** to deploy your SecAgents environment. SecAgents requires **Python 3.11+** and a high-performance **Docker** daemon.

---

## 🏗️ Phase 1: Core Dependencies

### 🐳 Step 1: Docker Infrastructure
SecAgents relies on Docker for its fortification (sandbox) and local intelligence (Ollama).
1.  Install **[Docker Engine](https://docs.docker.com/engine/install/)** or **[Docker Desktop](https://docs.docker.com/desktop/)**.
2.  Initialize the daemon and verify:
    ```bash
    docker version
    ```
3.  **Linux Users**: Ensure your user is in the `docker` group to avoid `sudo` conflicts.

### 🐍 Step 2: Python Environment
1.  Install **Python 3.11 or newer** from **[python.org](https://www.python.org/downloads/)**.
2.  Confirm deployment:
    ```bash
    python --version
    ```

---

## ⚡ Phase 2: Deployment

### 📂 Step 3: Clone the Nexus
Clone the repository to your local operations center:
```bash
git clone https://github.com/gl1tch0x1/SecAgents.git
cd SecAgents
```

### 🛡️ Step 4: Virtual Fortification
We highly recommend using a virtual environment to isolate your security tools:
```bash
python -m venv .venv

# Activate (Linux / macOS)
source .venv/bin/activate

# Activate (Windows)
.venv\Scripts\activate
```

### ⚙️ Step 5: Install SecAgents
Deploy the agentic framework in editable mode:
```bash
pip install -e .

# Optional: Development Toolkit (Lint + Tests)
pip install -e ".[dev]"
```

---

## 🩺 Phase 3: Systems Verification

Validate your installation using the built-in diagnostic tools:

```bash
secagents version
secagents doctor
```

- **`version`**: Confirms the package build.
- **`doctor`**: High-level diagnostic for Docker connectivity and environment health.

---

## 🏗️ Phase 4: Sandbox Initialization

The first operation will automatically **build** the `secagents-sandbox:latest` image. This is a one-time intensive process.

> [!TIP]
> **Rebuild Protocol**: If you update the core codebase or payload library, force a sandbox refresh:
> ```bash
> docker rmi secagents-sandbox:latest
> ```

---

## 🟢 Optional: Local Private AI (Ollama)

For air-gapped or private missions, deploy a local LLM:
1.  Ensure Docker is active.
2.  Provision the instance:
    ```bash
    secagents setup-ollama --model llama3.2
    ```
3.  This command handles image pulling, container lifecycle, and model weight ingestion.

---

## 🏁 Next Mission

- Learn to execute scans in **[Usage Guide](Usage.md)**.
- Automate your security and CI/CD in **[GitHub Integration](GitHub-Integration.md)**.

<div align="center">
  <sub>SecAgents Deployment Manual</sub>
</div>
