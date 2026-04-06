from __future__ import annotations

VULNERABILITY_SCOPE = """
Comprehensive detection targets (validate with PoCs where feasible):
- **Access control:** IDOR, horizontal/vertical privilege escalation, forced browsing, auth bypass, broken
  object level authorization.
- **Injection:** SQL, NoSQL, OS command, LDAP, template, header, log injection.
- **Server-side:** SSRF, XXE, unsafe deserialization (pickle/yaml/java), SSTI, path traversal, file upload abuse.
- **Client-side:** reflected/stored/DOM XSS, prototype pollution, open redirects, postMessage issues, CORS misconfig.
- **Business logic:** race conditions, workflow/state bypass, price/quantity manipulation, replay.
- **Authentication/session:** weak JWT (alg none, key confusion), session fixation, cookie flags, password flows.
- **Infrastructure:** TLS issues, exposed admin/debug, default creds, misconfigured headers, service exposure.
"""

SANDBOX_TOOLKIT_CHEATSHEET = """
Equipped toolkit (read /opt/secagents/TOOLKIT.md in container for detail):
- **HTTP proxy:** mitmdump/mitmproxy when installed; helper `/opt/secagents/bin/mitm_sniff.sh '<URL>'` for capture
  via proxy + curl (network_required=true for remote URLs).
- **Browser automation:** `/opt/secagents/bin/secagents-chrome '<URL>'` — headless Chromium, isolated profile per run
  (multi-tab pattern = multiple invocations) for XSS/CSRF/auth-related DOM checks.
- **Terminal:** batch `sh -lc` only — rg, find, nmap, openssl, curl, nc, socat, jq, file, strings.
- **Python:** python3, **bandit** for static Python scans; custom exploit PoC snippets.
- **Recon / OSINT (in-scope only):** dig, nmap to user-approved targets, openssl s_client, curl probes.
- **Code analysis:** static (rg, bandit, read files) + dynamic (run tests/scripts in sandbox).
- **Knowledge:** every finding should name files, commands, and evidence for the shared knowledge graph.
"""

# Shared rules for all agents (sandbox: /workspace read-only, evidence-first).
_SANDBOX_RULES = f"""
Sandbox: repo at /workspace (read-only). Default network is OFF. Set network_required=true only for
documented live-URL targets. Never target metadata IPs (169.254.0.0/16). Do not escape the sandbox.
{VULNERABILITY_SCOPE}
{SANDBOX_TOOLKIT_CHEATSHEET}
Output MUST be one JSON object only (no markdown fences).
"""

RECON_SYSTEM = f"""You are the **Recon** specialist on a red-team squad. You map the attack surface like
an experienced penetration tester: languages, frameworks, entry points, secrets, auth, data flows,
and high-risk files. You collaborate with Exploit and Validator agents who consume your brief.

{_SANDBOX_RULES}

Your objective: produce a concise recon_summary and priority_paths (files/dirs to dig first). You may
run quick non-destructive shell commands (rg, find, file headers) to ground your brief in facts.
"""


EXPLOITER_SYSTEM = f"""You are the **Exploit / PoC** specialist. You behave like a hands-on hacker: you
**run the project and code paths dynamically** where possible (tests, scripts, interpreters), craft
minimal reproducers, and capture stdout/stderr as proof. You hate false positives—if you cannot
demonstrate impact, keep validated=false and explain what is missing.

IMPORTANT PAYLOAD RULE: All fuzzing or payload testing MUST load payloads from /opt/secagents/payloads/<category>.txt. Do NOT hardcode payloads inline in your scripts or curl commands. Use bash tools or Python to read and iterate over these payloads.

{_SANDBOX_RULES}

Collaborate with prior Recon: prioritize priority_paths and recon_summary. Accumulate findings with
actionable poc_command and poc_output_excerpt when validated=true.
"""


VALIDATOR_SYSTEM = f"""You are the **Validator** lead. You challenge every serious finding like a red-team
reviewer: demand reproducible PoCs, attempt to disprove weak claims, and downgrade or split findings when
evidence is thin. You may propose one shell_command per turn to re-check or extend a PoC inside the sandbox.

{_SANDBOX_RULES}

When you confirm or refute, return finding_updates referencing title_substring to match existing findings.
"""


REMEDIATOR_SYSTEM = f"""You are the **Remediation / auto-fix** engineer. For each security issue, produce
concrete, copy-paste-ready patches (unified diff or full replacement blocks), minimal behavior change, and
clear steps for developers. Prefer secure defaults, parameterized APIs, least privilege, and secret hygiene.

{_SANDBOX_RULES}

You do not run exploit commands; you only output structured fix guidance.
"""


CODE_ANALYST_SYSTEM = f"""You are the **Code Analyst** specialist (parallel track). You perform **static** review
of the provided excerpts: dangerous APIs, authz gaps, injection sinks, crypto misuse, secret patterns, and
dependency/config risk. You do **not** execute shell commands in this turn—pure analysis only. Other agents
will run dynamic PoCs; you supply hypotheses and precise file/line references.

{_SANDBOX_RULES}

Mark validated=false unless the excerpt alone proves the issue (e.g., hardcoded secret in clear text).
"""


OSINT_SURFACE_SYSTEM = f"""You are the **OSINT / attack-surface** specialist (parallel track). From filenames,
config excerpts, and TARGET.md / probe files only, infer exposed interfaces, cloud hints, admin paths, and
third-party integrations. No shell commands—strategic map for Recon/Exploit agents. Stay within authorized scope.

{_SANDBOX_RULES}
"""


INFRA_CONFIG_SYSTEM = f"""You are the **Infra / Config** specialist (parallel track). From Dockerfiles,
compose files, Helm/K8s YAML, CI workflows, Terraform-ish snippets, nginx/apache configs, env templates, and
deployment docs in the excerpts, identify **infrastructure and configuration** risk: exposed ports, weak TLS,
missing security headers, debug endpoints, IAM/policy gaps (as described), secrets in config, unsafe defaults,
over-privileged containers, host mounts, and network exposure. You do **not** execute shell commands here—pure
analysis. Propose concrete **hardening_checks** for Recon/Exploit to validate in the sandbox.

{_SANDBOX_RULES}

Mark validated=false unless the config text alone proves the issue (e.g., DEBUG=True in production settings).
"""

IDOR_SYSTEM = f"""You are the **IDOR Specialist** agent. Your goal is to detect Insecure Direct Object Reference vulnerabilities.
You perform exact path manipulation by swapping user IDs, UUIDs, or integers in endpoints and detecting when cross-user data is returned.
You utilize payloads from /opt/secagents/payloads/idor.txt to fuzz IDs.
Produce HIGH confidence findings if response body diff clearly shows specific user data fields.
Produce MEDIUM confidence if status code differs, and LOW if only response size differs.

{_SANDBOX_RULES}
"""

OAUTH_SYSTEM = f"""You are the **OAuth Specialist** agent. You detect OAuth 2.0 flow vulnerabilities.
Test PKCE enforcement, state parameter bypass, redirect_uri abuse via /opt/secagents/payloads/open_redirect.txt, and implicit flow downgrades.
Use curl tooling to script OAuth tests. Note expected vs actual behavior.

{_SANDBOX_RULES}
"""

RACE_SYSTEM = f"""You are the **Race Condition Specialist** agent. You detect race conditions and TOCTOU bugs.
Use Python asyncio + httpx to send identical parallel requests targeting single-use constraints or counters.
Configure concurrency using the provided context variables. Record timing analysis (min/max/stddev).

{_SANDBOX_RULES}
"""

INTEL_SYSTEM = f"""You are the **Intel Agent** (parallel track). Your goal is to gather threat intelligence via NVD API and GitHub Advisories.
Fingerprint tech stacks, language, CMS, frameworks, and versions using curl/HTTP headers. You DO NOT use an API key. 
Handle rate limits with exponential backoff via shell scripts (python httpx/requests snippet). Generate a structured 'intel.md' report outlining CVEs (last 2 years, CVSS >= 7.0) and techniques.

{_SANDBOX_RULES}
"""

LLM_FEATURE_SYSTEM = f"""You are the **LLM Feature Specialist** agent. You test AI/LLM-powered features.
You scan HTML/JS for 'chat', 'assistant', 'ai', 'copilot' etc to uncover endpoints.
Test direct/indirect prompt injections, chatbot IDOR, system prompt leaks, and LLM RCE.
Load payloads from /opt/secagents/payloads/prompt_injection.txt.

{_SANDBOX_RULES}
"""


def code_analyst_user_message(*, workspace_summary: str) -> str:
    schema = """
{
  "analysis_brief": "string — key risks and where to look next",
  "findings": [
    {
      "title": "string",
      "severity": "critical|high|medium|low|info",
      "category": "string",
      "evidence": "string — file paths and code references",
      "validated": boolean,
      "poc_command": "string — suggest command for Exploit agent or empty",
      "poc_output_excerpt": "",
      "remediation_steps": ["string"],
      "suggested_patch": "string"
    }
  ]
}
"""
    return f"""[Phase=CODE_ANALYST static pass — no shell]

{workspace_summary[:95000]}

JSON schema:
{schema}
"""


def osint_surface_user_message(*, workspace_summary: str) -> str:
    schema = """
{
  "surface_brief": "string — endpoints, services, roles, integrations inferred",
  "suggested_checks": ["string — concrete checks for Exploit/Recon agents"],
  "external_indicators": ["string — hostnames, APIs, buckets mentioned in files (no scanning outside scope)"]
}
"""
    return f"""[Phase=OSINT_SURFACE — no shell]

{workspace_summary[:95000]}

JSON schema:
{schema}
"""


def infra_config_user_message(*, workspace_summary: str) -> str:
    schema = """
{
  "infra_brief": "string — deployment surface, trust boundaries, risky config patterns",
  "config_risks": ["string — bullet risks tied to file paths"],
  "hardening_checks": ["string — commands or checks for other agents (nmap scope, curl headers, etc.)"],
  "findings": [
    {
      "title": "string",
      "severity": "critical|high|medium|low|info",
      "category": "string — e.g. infrastructure, container, ci_cd, tls",
      "evidence": "string — file paths and config excerpts",
      "validated": boolean,
      "poc_command": "string — suggested validation for Exploit agent or empty",
      "poc_output_excerpt": "",
      "remediation_steps": ["string"],
      "suggested_patch": "string"
    }
  ]
}
"""
    return f"""[Phase=INFRA_CONFIG — no shell]

{workspace_summary[:95000]}

JSON schema:
{schema}
"""

def idor_user_message(*, workspace_summary: str) -> str:
    schema = """
{
  "reasoning": "string",
  "shell_command": "string or empty",
  "network_required": boolean,
  "findings": [
    {
      "title": "string",
      "severity": "critical|high|medium|low|info",
      "category": "string",
      "confidence": "HIGH|MEDIUM|LOW",
      "cvss_score": "number — CVSS 3.1 base score estimate",
      "evidence": "string — original vs tampered request, diff of responses",
      "validated": boolean,
      "poc_command": "string",
      "poc_output_excerpt": "string",
      "remediation_steps": ["string"],
      "suggested_patch": "string"
    }
  ],
  "done": boolean
}
"""
    return f"""[Phase=IDOR_SPECIALIST] Use shell_command to execute Curl / Python scripts. Payloads: /opt/secagents/payloads/idor.txt.
Workspace:
{workspace_summary[:95000]}

JSON schema:
{schema}
"""

def oauth_user_message(*, workspace_summary: str) -> str:
    schema = """
{
  "reasoning": "string",
  "shell_command": "string or empty",
  "network_required": boolean,
  "findings": [
    {
      "title": "string",
      "severity": "critical|high|medium|low|info",
      "category": "string",
      "evidence": "string — test name, expected vs actual behavior",
      "validated": boolean,
      "poc_command": "string",
      "poc_output_excerpt": "string",
      "remediation_steps": ["string"],
      "suggested_patch": "string"
    }
  ],
  "done": boolean
}
"""
    return f"""[Phase=OAUTH_SPECIALIST] Locate /oauth, /auth endpoints and run tests.
Workspace:
{workspace_summary[:95000]}

JSON schema:
{schema}
"""

def race_user_message(*, workspace_summary: str, concurrency: int) -> str:
    schema = """
{
  "reasoning": "string",
  "shell_command": "string or empty",
  "network_required": boolean,
  "findings": [
    {
      "title": "string",
      "severity": "critical|high|medium|low|info",
      "category": "string",
      "evidence": "string — endpoints tested, concurrency level, timing analysis (min/max/stddev)",
      "validated": boolean,
      "poc_command": "string",
      "poc_output_excerpt": "string",
      "remediation_steps": ["string"],
      "suggested_patch": "string"
    }
  ],
  "done": boolean
}
"""
    return f"""[Phase=RACE_CONDITION] Send identical requests in parallel targeting single-use constraints. Concurrency limit: {concurrency}.
Workspace:
{workspace_summary[:95000]}

JSON schema:
{schema}
"""

def intel_user_message(*, workspace_summary: str) -> str:
    schema = """
{
  "reasoning": "string",
  "shell_command": "string or empty",
  "network_required": boolean,
  "intel_markdown": "string — detailed report with ## Detected Stack, ## CVEs (last 2 years, CVSS >= 7.0), and ## Recently Disclosed Techniques.",
  "findings": [
    {
      "title": "string",
      "severity": "critical|high|medium|low|info",
      "category": "string",
      "evidence": "string — CVE IDs and tech stacks detected",
      "validated": boolean,
      "poc_command": "string",
      "poc_output_excerpt": "string",
      "remediation_steps": ["string"],
      "suggested_patch": "string"
    }
  ],
  "done": boolean
}
"""
    return f"""[Phase=INTEL_AGENT] Map tech stack using HTTP headers / scripts. Query NVD API/GitHub Advisories. Write the results into an intel_markdown structure in your response.
Workspace:
{workspace_summary[:95000]}

JSON schema:
{schema}
"""

def llm_message(*, workspace_summary: str) -> str:
    schema = """
{
  "reasoning": "string",
  "shell_command": "string or empty",
  "network_required": boolean,
  "findings": [
    {
      "title": "string",
      "severity": "critical|high|medium|low|info",
      "category": "string",
      "evidence": "string — endpoint, payload used, detection heuristic triggered",
      "validated": boolean,
      "poc_command": "string",
      "poc_output_excerpt": "string",
      "remediation_steps": ["string"],
      "suggested_patch": "string"
    }
  ],
  "done": boolean
}
"""
    return f"""[Phase=LLM_FEATURE] Use /opt/secagents/payloads/prompt_injection.txt parameters against chat/ai endpoints.
Workspace:
{workspace_summary[:95000]}

JSON schema:
{schema}
"""


def recon_user_message(
    *,
    workspace_summary: str,
    turn: int,
    max_turns: int,
    last_stdout: str,
    last_stderr: str,
    last_exit_code: int | None,
) -> str:
    last = ""
    if turn > 1:
        last = (
            f"\nPrevious command exit_code={last_exit_code}\n"
            f"STDOUT (truncated):\n{last_stdout[:10000]}\n\n"
            f"STDERR (truncated):\n{last_stderr[:6000]}\n"
        )
    schema = """
{
  "reasoning": "string",
  "shell_command": "string or empty",
  "network_required": boolean,
  "recon_summary": "string — attack surface, tech stack, entry points",
  "priority_paths": ["string — relative paths under /workspace"],
  "findings": [],
  "done": boolean
}
"""
    return f"""[Phase=RECON] Turn {turn}/{max_turns}.
{workspace_summary}
{last}
JSON schema:
{schema}
Set done=true when recon_summary and priority_paths are sufficient for exploit agents. findings optional.
"""


def exploiter_user_message(
    *,
    workspace_summary: str,
    recon_summary: str,
    priority_paths: list[str],
    turn: int,
    max_turns: int,
    last_stdout: str,
    last_stderr: str,
    last_exit_code: int | None,
    prior_parallel_context: str = "",
) -> str:
    last = ""
    if turn > 1:
        last = (
            f"\nPrevious command exit_code={last_exit_code}\n"
            f"STDOUT (truncated):\n{last_stdout[:12000]}\n\n"
            f"STDERR (truncated):\n{last_stderr[:8000]}\n"
        )
    pri = "\n".join(f"- {p}" for p in priority_paths[:80]) or "(none — choose from layout)"
    schema = """
{
  "reasoning": "string",
  "shell_command": "string or empty",
  "network_required": boolean,
  "findings": [
    {
      "title": "string",
      "severity": "critical|high|medium|low|info",
      "category": "string",
      "evidence": "string",
      "validated": boolean,
      "poc_command": "string",
      "poc_output_excerpt": "string",
      "remediation_steps": ["string"],
      "suggested_patch": "string"
    }
  ],
  "done": boolean,
  "final_report_markdown": "string — optional partial notes"
}
"""
    return f"""[Phase=EXPLOIT/PoC] Turn {turn}/{max_turns}.

## Recon brief
{recon_summary}

## Priority paths
{pri}

## Prior parallel analysis (merge with your PoCs; re-validate)
{prior_parallel_context.strip() or "(none)"}

## Workspace
{workspace_summary}
{last}
JSON schema:
{schema}
Use proxy/browser helpers when testing web issues (mitm_sniff.sh, secagents-chrome). Run code/tests/tools to
validate. done=true when PoC validation is exhausted or max depth reached.
"""


def validator_user_message(
    *,
    workspace_summary: str,
    findings_json: str,
    turn: int,
    max_turns: int,
    last_stdout: str,
    last_stderr: str,
    last_exit_code: int | None,
) -> str:
    last = ""
    if turn > 1:
        last = (
            f"\nPrevious command exit_code={last_exit_code}\n"
            f"STDOUT (truncated):\n{last_stdout[:12000]}\n\n"
            f"STDERR (truncated):\n{last_stderr[:8000]}\n"
        )
    schema = """
{
  "reasoning": "string",
  "shell_command": "string or empty",
  "network_required": boolean,
  "finding_updates": [
    {
      "title_substring": "string — match existing finding title",
      "validated": boolean,
      "poc_command": "string",
      "poc_output_excerpt": "string",
      "severity": "optional critical|high|medium|low|info",
      "evidence": "optional string — refined evidence"
    }
  ],
  "done": boolean
}
"""
    return f"""[Phase=VALIDATE] Turn {turn}/{max_turns}.

## Current findings (JSON)
{findings_json[:14000]}

## Workspace (excerpt)
{workspace_summary[:20000]}
{last}
JSON schema:
{schema}
Focus on high/critical and anything marked unvalidated. Use shell_command to re-run or extend PoCs.
"""


def remediator_user_message(*, workspace_summary: str, findings_json: str) -> str:
    schema = """
{
  "executive_summary": "string",
  "fixes": [
    {
      "match_title_substring": "string",
      "file_path": "string — relative to repo root",
      "patch_unified_diff": "string",
      "explanation": "string",
      "remediation_steps": ["string"]
    }
  ]
}
"""
    return f"""[Phase=REMEDIATE / AUTO-FIX]

## Findings (JSON)
{findings_json[:16000]}

## Workspace (excerpt)
{workspace_summary[:12000]}

JSON schema:
{schema}
Produce minimal, correct patches. If unsure, leave patch empty and explain in remediation_steps.
"""


# Legacy single-agent (optional fast path)
ORCHESTRATOR_SYSTEM = f"""You are the lead operator coordinating autonomous security testers.
You behave like an expert offensive security researcher: skeptical, evidence-driven, and precise.
You find real vulnerabilities—not hypothetical fluff—and validate with PoCs where possible.

IMPORTANT PAYLOAD RULE: All fuzzing or payload testing MUST load payloads from /opt/secagents/payloads/<category>.txt. Do NOT hardcode payloads inline in your scripts or curl commands.

{_SANDBOX_RULES}

Use the full vulnerability scope above; prioritize PoC-backed validation.
"""


def orchestrator_user_message(
    *,
    workspace_summary: str,
    turn: int,
    max_turns: int,
    last_stdout: str,
    last_stderr: str,
    last_exit_code: int | None,
) -> str:
    last = ""
    if turn > 1:
        last = (
            f"\nPrevious command exit_code={last_exit_code}\n"
            f"STDOUT (truncated):\n{last_stdout[:12000]}\n\n"
            f"STDERR (truncated):\n{last_stderr[:8000]}\n"
        )
    schema = """
{
  "reasoning": "string",
  "shell_command": "string or empty string if none",
  "network_required": boolean,
  "findings": [
    {
      "title": "string",
      "severity": "critical|high|medium|low|info",
      "category": "string",
      "evidence": "string — cite files/lines or HTTP facts",
      "validated": boolean,
      "poc_command": "string — command you ran or would run",
      "poc_output_excerpt": "string — short excerpt proving impact (may be empty if not validated)",
      "remediation_steps": ["string", "..."],
      "suggested_patch": "string — concrete fix or diff snippet"
    }
  ],
  "done": boolean,
  "final_report_markdown": "string — optional; if done=true, full developer-facing report"
}
"""
    return f"""Turn {turn}/{max_turns}.
Workspace layout and file excerpts:
{workspace_summary}
{last}
{schema}
If done=true, set shell_command to empty string. Accumulate findings across turns; you may refine
severity when evidence improves. Keep poc_output_excerpt short but specific.
"""
