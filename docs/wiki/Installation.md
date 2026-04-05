# Installation

Follow these steps **in order**. SecAgents requires **Python 3.11+** and a working **Docker** daemon (for the sandbox and optional Ollama).

---

## Step 1 — Install Docker

1. Install [Docker Engine](https://docs.docker.com/engine/install/) or [Docker Desktop](https://docs.docker.com/desktop/) for your OS.
2. Start the daemon and confirm it runs:
   ```bash
   docker version
   ```
3. On Linux, ensure your user can run Docker (e.g. `docker` group) without sudo if you use a non-root setup.

---

## Step 2 — Install Python

1. Install **Python 3.11 or newer** from [python.org](https://www.python.org/downloads/) or your OS package manager.
2. Confirm:
   ```bash
   python --version
   ```
   or `python3 --version`.

---

## Step 3 — Clone the repository (GitHub deployment)

1. Clone **your** fork or the upstream repo:
   ```bash
   git clone https://github.com/YOUR_ORG/secagents.git
   cd secagents
   ```
2. (Recommended) Create a virtual environment:
   ```bash
   python -m venv .venv
   ```
3. Activate it:
   - **Linux / macOS:** `source .venv/bin/activate`
   - **Windows (cmd):** `.venv\Scripts\activate.bat`
   - **Windows (PowerShell):** `.venv\Scripts\Activate.ps1`

---

## Step 4 — Install SecAgents

From the repository root (where `pyproject.toml` lives):

```bash
python -m pip install -U pip
python -m pip install -e .
```

For development (lint + tests):

```bash
python -m pip install -e ".[dev]"
```

---

## Step 5 — Verify the CLI

Because `secagents` may not be on `PATH` on all systems, prefer the module form:

```bash
python -m secagents version
python -m secagents doctor
```

- **`version`** — prints the package version.
- **`doctor`** — checks that the Docker CLI can talk to the daemon. If this fails, fix Docker before scanning.

---

## Step 6 — First sandbox image build

The first scan **builds** the local image `secagents-sandbox:latest` from `src/secagents/data/Dockerfile.sandbox`. That can take several minutes.

To force a rebuild after upgrading SecAgents:

```bash
docker rmi secagents-sandbox:latest
```

Then run any command that triggers a scan.

---

## Optional — Ollama (local LLM in Docker)

1. Ensure Docker is running.
2. Run:
   ```bash
   python -m secagents setup-ollama --model llama3.2
   ```
3. This pulls `ollama/ollama`, starts a container, and pulls model weights.

---

## PyPI / private index (future)

When you publish to an index, consumers will use:

```bash
pip install secagents
```

Until then, **`pip install -e .` from a git clone** is the supported install path for this project layout.

---

## Next

Continue to [Usage](Usage.md) and [GitHub integration](GitHub-Integration.md).
