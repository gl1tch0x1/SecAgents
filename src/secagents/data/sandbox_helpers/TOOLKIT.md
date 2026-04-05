# SecAgents sandbox toolkit

All paths are inside the container. Workspace: `/workspace` (read-only).

## HTTP proxy (mitmproxy)

- **mitmdump** / **mitmproxy** (if installed): intercept and record HTTP(S) when network is enabled.
- One-shot helper: `/opt/secagents/bin/mitm_sniff.sh '<URL>'` — starts a local proxy, curls via it, prints headers and a flow hex preview.
- Manual: `mitmdump -p 8899 -w /tmp/flows.mitm &` then `curl -x http://127.0.0.1:8899 -sk '<URL>'`.

## Browser automation (Chromium)

- Headless DOM capture (isolated user-data dir per run ≈ “tab”):  
  `/opt/secagents/bin/secagents-chrome '<URL>'`
- For auth/XSS/CSRF flows: chain multiple invocations with different URLs/cookies; use `curl -c -b` for cookie jars when needed.

## Terminal

- Non-interactive batch shell only (`sh -lc '...'`). Use for rg, find, interpreters, bandit, etc.

## Python runtime

- `python3`, `pip` (where installed). Run ad-hoc validators: `python3 -c '...'`.
- **bandit** (if installed): `bandit -r . -ll -q` for Python static checks.

## Reconnaissance / OSINT (safe, in-scope)

- `nmap`, `dig`/`nslookup`, `openssl s_client`, `curl`, `nc`, `socat`, `rg`, `file`, `strings`.

## Code analysis

- Static: `rg`, `bandit`, read sources under `/workspace`.
- Dynamic: run tests/scripts via `python3`, `node`, `go test`, etc., always non-destructive.

## Knowledge output

- Agents should reference file paths and commands in findings so the host can merge them into `knowledge_graph` / reports.
