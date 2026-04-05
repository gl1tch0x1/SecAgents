# Contributing

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -U pip
pip install -e ".[dev]"
python -m ruff check src/secagents tests
python -m pytest tests/ -q
```

## Pull requests

1. Fork and branch from `main`.
2. Keep changes focused; match existing style (ruff, types where used).
3. Add or update tests under `tests/` when behavior changes.
4. Update `docs/wiki/` if user-facing behavior or installation steps change.

## Releases

Maintainers: bump `version` in `pyproject.toml` and `src/secagents/__init__.py`, tag, and publish per your org’s release process.
