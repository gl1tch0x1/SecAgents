# GitHub integration

Use this guide to deploy SecAgents **CI scanning** on GitHub and keep it **maintainable and secure**.

---

## Step 1 — Add workflow files to your repo

Copy from this project into **your** repository:

| File | Role |
|------|------|
| `.github/workflows/ci.yml` | **Lint + pytest** on every push/PR (no Docker/LLM) |
| `.github/workflows/secagents.yml` | **Security scan** job (Docker + Ollama or cloud LLM) |
| `.github/dependabot.yml` | Weekly updates for Actions + pip |

Commit to `main` (or your default branch).

---

## Step 2 — Configure branch protection (recommended)

1. Repository **Settings → Branches → Branch protection** for `main`.
2. Enable **Require status checks to pass** before merge.
3. Select required checks, e.g.:
   - `CI / lint-test` (from `ci.yml`)
   - Optionally `SecAgents Scan / scan` if you want PRs blocked on findings (can be noisy).

---

## Step 3 — Secrets and variables

### Secrets (Settings → Secrets and variables → Actions)

| Secret | When to set |
|--------|-------------|
| `OPENAI_API_KEY` | Prefer cloud OpenAI in CI (skips local Ollama pull for the scan step logic) |
| `ANTHROPIC_API_KEY` | Prefer Anthropic in CI |

If **neither** is set, the workflow uses **Ollama** inside the job (Docker).

### Variables (optional)

| Variable | Purpose |
|----------|---------|
| `SECAGENTS_OLLAMA_MODEL` | Model tag for `ollama pull` (default `llama3.2` in script) |
| `SECAGENTS_PARALLEL_SPECIALISTS` | `2` or `3` (adds Infra/Config parallel track when `3+`) |

### Cloud model IDs (workflow env)

You can set in the workflow file or as env:

- `SECAGENTS_OPENAI_MODEL` (default `gpt-4o-mini` in workflow)
- `SECAGENTS_ANTHROPIC_MODEL` (default `claude-3-5-sonnet-latest` in workflow)

---

## Step 4 — Fork pull requests

Secrets from the **base** repository are **not** exposed to workflows from **fork** PRs the same way as internal PRs. Expect:

- Fork PRs may run **without** cloud keys → falls back to **Ollama** path (still needs Docker in the job).
- For sensitive keys, use **environments** with **required reviewers** or run scans only on `push` to default branch.

Adjust triggers in `secagents.yml` if you want `pull_request_target` (advanced; understand the security implications before using it).

---

## Step 5 — Artifacts

Each run uploads **`secagents-report`** as a workflow artifact (even on failure when configured). Download from the Actions run page for `report.md` / `report.json`.

---

## Step 6 — Publish URLs in `pyproject.toml`

Replace placeholders:

```toml
[project.urls]
Homepage = "https://github.com/YOUR_ORG/secagents"
```

with your real GitHub path so PyPI and tooling show correct links after release.

---

## Step 7 — Enable private vulnerability reporting (optional)

Repository **Settings → Security** → enable **Private vulnerability reporting** and point reporters to `SECURITY.md`.

---

## Next

[Operations](Operations.md) · [Installation](Installation.md)
