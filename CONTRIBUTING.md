# 🤝 Contributing Protocol

Join the SecAgents development squad. Help us build the next generation of autonomous offensive AI.

---

## 🛠️ Development Environment

Initialize your local workstation for agentic development:

```bash
# Provision workspace
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Intelligence Synchronization
pip install -U pip
pip install -e ".[dev]"

# Static Analysis & Validation
python -m ruff check src/secagents tests
python -m pytest tests/ -q
```

---

## 🚀 Pull Request Protocol

1.  **Fork** and create a feature branch from `main`.
2.  **Focus**: Keep changes granular and high-impact.
3.  **Style**: Adhere to `ruff` linting and use type hints where applicable.
4.  **Verification**: Update or add tests in `tests/` for all behavioral changes.
5.  **Documentation**: Synchronize `docs/wiki/` if user-facing protocols change.

---

## 📦 Release Operations

**Maintainer Instructions**: 
- Increment `version` in `pyproject.toml` and `src/secagents/__init__.py`.
- Apply git tags and execute your organization's release pipeline.

<div align="center">
  <sub>SecAgents Development Command</sub>
</div>
