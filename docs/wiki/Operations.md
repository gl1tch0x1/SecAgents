# Operations

Production-oriented notes for running SecAgents **safely** and **efficiently**.

---

## Threat model and scope

- SecAgents runs **LLM-driven** commands inside a **Docker sandbox** with the workspace mounted **read-only**.
- **Network** is **off** by default; URL targets may require `--allow-network`.
- Treat the tool as **powerful**: only run against assets you are **authorized** to test.

---

## Cost and latency

- **Cloud LLMs** (OpenAI/Anthropic): every scan is billable; reduce `--max-turns`, `--parallel-specialists`, or run `ci` with lower limits.
- **Ollama**: GPU/CPU and disk for models; CI jobs pull models per runner unless cached (ephemeral runners often re-pull).
- **Docker image build**: First `secagents-sandbox` build is slow; cache on self-hosted runners if needed.

---

## Rebuilding the sandbox image

After upgrading SecAgents or changing `Dockerfile.sandbox`:

```bash
docker rmi secagents-sandbox:latest
```

Next scan rebuilds the image.

---

## Monorepos and context limits

Large trees are **sampled** for LLM context. Tune (environment):

- `SECAGENTS_MAX_FILE_BYTES`
- `SECAGENTS_MAX_FILES_IN_CONTEXT`

Increase gradually; very high values increase token cost and failure rates.

---

## Troubleshooting

| Symptom | Check |
|---------|--------|
| `docker: command not found` | Install Docker; add to PATH |
| `Cannot connect to Docker daemon` | Start Docker Desktop / service |
| `No module named secagents` | Use `python -m secagents` from venv where you ran `pip install -e .` |
| Ollama connection errors | `setup-ollama`, firewall, `SECAGENTS_OLLAMA_BASE_URL` |
| Empty or parse errors in transcript | Model too small or strict JSON; try stronger model or lower temperature |

---

## Logging and retention

- Reports may contain **snippets of code** and **command output**; treat artifacts as **internal**.
- Set artifact **retention** in repository Actions settings if required by policy.

---

## Roadmap (enterprise hardening)

Common next steps for larger orgs: **SARIF** export for GitHub Code Scanning, **OIDC** for cloud model auth, **SBOM** generation for releases, **signed tags** and **provenance** (SLSA). This OSS baseline focuses on a clear sandbox boundary and auditable reports.

---

## Upgrades

1. Pull latest `main`.
2. `pip install -e ".[dev]"` again if dependencies changed.
3. Rebuild sandbox image (see above).
4. Run `python -m pytest tests/ -q` locally.

---

## Back to

[Home](Home.md) · [GitHub integration](GitHub-Integration.md)
