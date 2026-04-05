from __future__ import annotations

import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from secagents.agents.prompts import (
    CODE_ANALYST_SYSTEM,
    EXPLOITER_SYSTEM,
    INFRA_CONFIG_SYSTEM,
    ORCHESTRATOR_SYSTEM,
    OSINT_SURFACE_SYSTEM,
    RECON_SYSTEM,
    REMEDIATOR_SYSTEM,
    VALIDATOR_SYSTEM,
    code_analyst_user_message,
    exploiter_user_message,
    infra_config_user_message,
    orchestrator_user_message,
    osint_surface_user_message,
    recon_user_message,
    remediator_user_message,
    validator_user_message,
)
from secagents.config import AppConfig
from secagents.knowledge.graph import build_knowledge_graph
from secagents.llm.providers import chat_completion, extract_json_object
from secagents.sandbox import build_sandbox_image_if_needed, run_in_sandbox


@dataclass
class ScanFinding:
    title: str
    severity: str
    category: str
    evidence: str
    validated: bool
    poc_command: str
    poc_output_excerpt: str
    remediation_steps: list[str]
    suggested_patch: str


@dataclass
class AutoFixItem:
    finding_title: str
    file_path: str
    patch: str
    explanation: str


@dataclass
class ScanResult:
    findings: list[ScanFinding] = field(default_factory=list)
    transcript: list[dict] = field(default_factory=list)
    final_report_markdown: str | None = None
    recon_brief: str | None = None
    priority_targets: list[str] = field(default_factory=list)
    auto_fixes: list[AutoFixItem] = field(default_factory=list)
    remediation_summary: str | None = None
    static_analysis_brief: str | None = None
    osint_surface_brief: str | None = None
    osint_suggested_checks: list[str] = field(default_factory=list)
    infra_config_brief: str | None = None
    infra_config_risks: list[str] = field(default_factory=list)
    infra_hardening_hints: list[str] = field(default_factory=list)
    infra_specialist_ran: bool = False
    knowledge_graph: dict = field(default_factory=dict)
    orchestration_mermaid: str | None = None


def _is_safeish_command(cmd: str) -> bool:
    c = cmd.strip().lower()
    if not c:
        return True
    banned = (
        "docker ",
        "kubectl ",
        "mount ",
        "/dev/",
        "mkfs",
        "dd ",
        "chmod 777",
        "> /etc/",
        "curl http://169.254",
    )
    return not any(b in c for b in banned)


def _normalize_title(title: str) -> str:
    t = title.lower().strip()
    t = re.sub(r"\s+", " ", t)
    return t[:200]


def dedupe_findings(findings: list[ScanFinding]) -> list[ScanFinding]:
    """Keep strongest, prefer validated entries per normalized title."""
    by_key: dict[str, ScanFinding] = {}
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def score(f: ScanFinding) -> tuple[int, int]:
        sev = rank.get(f.severity.lower(), 0)
        v = 1 if f.validated else 0
        return (v, sev)

    for f in findings:
        k = _normalize_title(f.title)
        if not k:
            k = f"untitled-{id(f)}"
        cur = by_key.get(k)
        if cur is None or score(f) > score(cur):
            by_key[k] = f
    return list(by_key.values())


def _collect_workspace_summary(root: Path, cfg: AppConfig) -> str:
    root = root.resolve()
    lines: list[str] = []
    lines.append(f"ROOT: {root}")
    ignore = {
        ".git",
        "__pycache__",
        "node_modules",
        ".venv",
        "venv",
        "dist",
        "build",
        ".mypy_cache",
    }
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ignore]
        for fn in filenames:
            p = Path(dirpath) / fn
            try:
                rel = p.relative_to(root)
            except ValueError:
                continue
            files.append(rel)
    files.sort(key=lambda x: str(x).lower())
    lines.append(f"FILE_COUNT: {len(files)}")
    preview = files[: min(len(files), 400)]
    lines.append("FILES:\n" + "\n".join(str(p).replace("\\", "/") for p in preview))
    priority_suffixes = (
        ".py",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".go",
        ".java",
        ".rb",
        ".php",
        ".yml",
        ".yaml",
        ".json",
        ".toml",
        ".env",
        ".md",
        "Dockerfile",
    )
    picked: list[Path] = []
    for rel in files:
        s = str(rel).lower()
        if any(s.endswith(sfx) for sfx in priority_suffixes) or rel.name in (
            "Dockerfile",
            "Makefile",
        ):
            picked.append(rel)
        if len(picked) >= cfg.max_files_in_context:
            break
    lines.append("\n--- EXCERPTS ---\n")
    budget = cfg.max_file_bytes
    for rel in picked:
        if budget <= 0:
            break
        fp = root / rel
        try:
            data = fp.read_bytes()
        except OSError:
            continue
        if b"\x00" in data[:1024]:
            continue
        text = data.decode("utf-8", errors="replace")
        chunk = text[: min(len(text), budget, 4000)]
        budget -= len(chunk.encode("utf-8", errors="replace"))
        loc = str(rel).replace("\\", "/")
        lines.append(f"\n### {loc}\n```\n{chunk}\n```\n")
    return "\n".join(lines)


def _merge_findings(existing: list[ScanFinding], raw: list[dict]) -> None:
    for item in raw:
        try:
            f = ScanFinding(
                title=str(item.get("title") or "Untitled"),
                severity=str(item.get("severity") or "info"),
                category=str(item.get("category") or "general"),
                evidence=str(item.get("evidence") or ""),
                validated=bool(item.get("validated")),
                poc_command=str(item.get("poc_command") or ""),
                poc_output_excerpt=str(item.get("poc_output_excerpt") or ""),
                remediation_steps=list(item.get("remediation_steps") or []),
                suggested_patch=str(item.get("suggested_patch") or ""),
            )
        except (TypeError, ValueError):
            continue
        existing.append(f)


def _findings_to_json(findings: list[ScanFinding]) -> str:
    return json.dumps(
        [
            {
                "title": f.title,
                "severity": f.severity,
                "category": f.category,
                "evidence": f.evidence,
                "validated": f.validated,
                "poc_command": f.poc_command,
                "poc_output_excerpt": f.poc_output_excerpt,
                "remediation_steps": f.remediation_steps,
                "suggested_patch": f.suggested_patch,
            }
            for f in findings
        ],
        indent=2,
    )


def _match_finding_index(findings: list[ScanFinding], title_substring: str) -> int | None:
    sub = title_substring.lower().strip()
    if not sub:
        return None
    for i, f in enumerate(findings):
        if sub in f.title.lower():
            return i
    return None


def _apply_finding_updates(findings: list[ScanFinding], updates: list[dict]) -> None:
    for u in updates:
        idx = _match_finding_index(findings, str(u.get("title_substring") or ""))
        if idx is None:
            continue
        f = findings[idx]
        if "validated" in u:
            f.validated = bool(u["validated"])
        if u.get("poc_command"):
            f.poc_command = str(u["poc_command"])
        if u.get("poc_output_excerpt"):
            f.poc_output_excerpt = str(u["poc_output_excerpt"])
        if u.get("severity"):
            f.severity = str(u["severity"])
        if u.get("evidence"):
            f.evidence = str(u["evidence"])


def _execute_agent_command(
    workspace: Path,
    cfg: AppConfig,
    allow_network: bool,
    data: dict,
) -> tuple[str, str, int | None]:
    cmd = str(data.get("shell_command") or "").strip()
    if not cmd:
        return "", "", None
    if not _is_safeish_command(cmd):
        return "", "Blocked potentially unsafe sandbox command.", 126
    net = "bridge" if (allow_network and bool(data.get("network_required"))) else "none"
    code, out, err = run_in_sandbox(
        workspace,
        cmd,
        image=cfg.docker_image_sandbox,
        network=net,
        timeout_sec=cfg.sandbox_command_timeout_sec,
        shm_size=(cfg.sandbox_shm_size.strip() or None),
    )
    return out, err, code


def _budget_turns(cfg: AppConfig) -> tuple[int, int, int]:
    """recon, exploit, validate turn budgets (must sum to <= max_agent_turns)."""
    t = max(1, cfg.max_agent_turns)
    r = min(max(0, cfg.recon_turns), t // 3)
    v = min(max(0, cfg.validation_turns), t // 3)
    e = t - r - v
    if e < 2:
        need = 2 - e
        take = min(need, r)
        r -= take
        need -= take
        take = min(need, v)
        v -= take
        e = t - r - v
    return r, max(1, e), v


def run_single_agent_scan(
    workspace: Path,
    cfg: AppConfig,
    *,
    allow_network: bool = False,
) -> ScanResult:
    """Legacy single-orchestrator loop (fast path)."""
    build_sandbox_image_if_needed(None, cfg.docker_image_sandbox)
    summary = _collect_workspace_summary(workspace, cfg)
    result = ScanResult()
    last_out, last_err = "", ""
    last_code: int | None = None

    for turn in range(1, cfg.max_agent_turns + 1):
        user = orchestrator_user_message(
            workspace_summary=summary,
            turn=turn,
            max_turns=cfg.max_agent_turns,
            last_stdout=last_out,
            last_stderr=last_err,
            last_exit_code=last_code,
        )
        text = chat_completion(cfg, system=ORCHESTRATOR_SYSTEM, user=user)
        try:
            data = extract_json_object(text)
        except (ValueError, TypeError) as e:
            result.transcript.append({"phase": "single", "turn": turn, "parse_error": str(e)})
            break

        result.transcript.append({"phase": "single", "turn": turn, "data": data})
        _merge_findings(result.findings, list(data.get("findings") or []))

        if data.get("final_report_markdown"):
            result.final_report_markdown = str(data["final_report_markdown"])

        if bool(data.get("done")):
            break

        last_out, last_err, last_code = _execute_agent_command(workspace, cfg, allow_network, data)

    result.findings = dedupe_findings(result.findings)
    if cfg.run_remediation_pass and result.findings:
        _run_remediation_phase(cfg, summary, result)

    kg = build_knowledge_graph(
        finding_titles=[f.title for f in result.findings],
        priority_targets=result.priority_targets,
        infra_specialist_ran=result.infra_specialist_ran,
    )
    result.knowledge_graph = kg.to_dict()
    result.orchestration_mermaid = kg.mermaid_flowchart()

    return result


def _phase_recon(
    workspace: Path,
    cfg: AppConfig,
    allow_network: bool,
    summary: str,
    result: ScanResult,
    max_turns: int,
) -> tuple[str, list[str]]:
    if max_turns <= 0:
        return "Recon skipped (0 turns).", []
    last_out, last_err = "", ""
    last_code: int | None = None
    recon_summary = ""
    priority_paths: list[str] = []

    for turn in range(1, max_turns + 1):
        user = recon_user_message(
            workspace_summary=summary,
            turn=turn,
            max_turns=max_turns,
            last_stdout=last_out,
            last_stderr=last_err,
            last_exit_code=last_code,
        )
        text = chat_completion(cfg, system=RECON_SYSTEM, user=user)
        try:
            data = extract_json_object(text)
        except (ValueError, TypeError) as e:
            result.transcript.append({"phase": "recon", "turn": turn, "parse_error": str(e)})
            break
        result.transcript.append({"phase": "recon", "turn": turn, "data": data})
        recon_summary = str(data.get("recon_summary") or recon_summary)
        pp = data.get("priority_paths")
        if isinstance(pp, list):
            priority_paths = [str(x) for x in pp if x][:120]
        _merge_findings(result.findings, list(data.get("findings") or []))

        if bool(data.get("done")):
            break

        last_out, last_err, last_code = _execute_agent_command(workspace, cfg, allow_network, data)

    if not recon_summary:
        recon_summary = "Recon completed without explicit summary; use workspace layout."
    return recon_summary, priority_paths


def _phase_exploit(
    workspace: Path,
    cfg: AppConfig,
    allow_network: bool,
    summary: str,
    recon_summary: str,
    priority_paths: list[str],
    result: ScanResult,
    max_turns: int,
    prior_parallel_context: str = "",
) -> None:
    last_out, last_err = "", ""
    last_code: int | None = None

    for turn in range(1, max_turns + 1):
        user = exploiter_user_message(
            workspace_summary=summary,
            recon_summary=recon_summary,
            priority_paths=priority_paths,
            turn=turn,
            max_turns=max_turns,
            last_stdout=last_out,
            last_stderr=last_err,
            last_exit_code=last_code,
            prior_parallel_context=prior_parallel_context,
        )
        text = chat_completion(cfg, system=EXPLOITER_SYSTEM, user=user)
        try:
            data = extract_json_object(text)
        except (ValueError, TypeError) as e:
            result.transcript.append({"phase": "exploit", "turn": turn, "parse_error": str(e)})
            break
        result.transcript.append({"phase": "exploit", "turn": turn, "data": data})
        _merge_findings(result.findings, list(data.get("findings") or []))

        if data.get("final_report_markdown"):
            result.final_report_markdown = str(data["final_report_markdown"])

        if bool(data.get("done")):
            break

        last_out, last_err, last_code = _execute_agent_command(workspace, cfg, allow_network, data)


def _phase_validate(
    workspace: Path,
    cfg: AppConfig,
    allow_network: bool,
    summary: str,
    result: ScanResult,
    max_turns: int,
) -> None:
    if max_turns <= 0 or not result.findings:
        return
    last_out, last_err = "", ""
    last_code: int | None = None

    for turn in range(1, max_turns + 1):
        fj = _findings_to_json(result.findings)
        user = validator_user_message(
            workspace_summary=summary,
            findings_json=fj,
            turn=turn,
            max_turns=max_turns,
            last_stdout=last_out,
            last_stderr=last_err,
            last_exit_code=last_code,
        )
        text = chat_completion(cfg, system=VALIDATOR_SYSTEM, user=user)
        try:
            data = extract_json_object(text)
        except (ValueError, TypeError) as e:
            result.transcript.append({"phase": "validate", "turn": turn, "parse_error": str(e)})
            break
        result.transcript.append({"phase": "validate", "turn": turn, "data": data})

        updates = data.get("finding_updates")
        if isinstance(updates, list):
            _apply_finding_updates(result.findings, [dict(x) for x in updates if isinstance(x, dict)])

        if bool(data.get("done")):
            break

        last_out, last_err, last_code = _execute_agent_command(workspace, cfg, allow_network, data)


def _run_remediation_phase(
    cfg: AppConfig,
    summary: str,
    result: ScanResult,
) -> None:
    if not result.findings:
        return
    user = remediator_user_message(
        workspace_summary=summary,
        findings_json=_findings_to_json(result.findings),
    )
    text = chat_completion(cfg, system=REMEDIATOR_SYSTEM, user=user)
    try:
        data = extract_json_object(text)
    except (ValueError, TypeError) as e:
        result.transcript.append({"phase": "remediate", "parse_error": str(e)})
        return

    result.transcript.append({"phase": "remediate", "data": data})
    if data.get("executive_summary"):
        result.remediation_summary = str(data["executive_summary"])
        if not result.final_report_markdown:
            result.final_report_markdown = result.remediation_summary

    fixes = data.get("fixes")
    if not isinstance(fixes, list):
        return
    for fx in fixes:
        if not isinstance(fx, dict):
            continue
        title = str(fx.get("match_title_substring") or "")
        path = str(fx.get("file_path") or "")
        patch = str(fx.get("patch_unified_diff") or "")
        expl = str(fx.get("explanation") or "")
        steps = list(fx.get("remediation_steps") or [])
        if title or path or patch:
            result.auto_fixes.append(
                AutoFixItem(
                    finding_title=title,
                    file_path=path,
                    patch=patch,
                    explanation=expl,
                )
            )
        idx = _match_finding_index(result.findings, title)
        if idx is not None:
            f = result.findings[idx]
            if patch and not f.suggested_patch.strip():
                f.suggested_patch = patch
            if steps:
                f.remediation_steps = list(dict.fromkeys([*f.remediation_steps, *steps]))


def _parallel_opening_specialists(
    cfg: AppConfig,
    summary: str,
    result: ScanResult,
) -> tuple[str, str]:
    """Run parallel opening specialists; return (prior_context, summary_for_recon).

    - ``parallel_specialists >= 2``: Code analyst + OSINT surface.
    - ``parallel_specialists >= 3``: also Infra / Config (three-way parallel).
    Values above 3 use the same three tracks for the opening phase.
    """
    if cfg.parallel_specialists < 2:
        return "", summary

    def _code_payload() -> dict:
        try:
            raw = chat_completion(
                cfg,
                system=CODE_ANALYST_SYSTEM,
                user=code_analyst_user_message(workspace_summary=summary),
            )
            return extract_json_object(raw)
        except Exception as e:
            return {"parse_error": str(e), "findings": [], "analysis_brief": ""}

    def _osint_payload() -> dict:
        try:
            raw = chat_completion(
                cfg,
                system=OSINT_SURFACE_SYSTEM,
                user=osint_surface_user_message(workspace_summary=summary),
            )
            return extract_json_object(raw)
        except Exception as e:
            return {
                "parse_error": str(e),
                "surface_brief": "",
                "suggested_checks": [],
            }

    def _infra_payload() -> dict:
        try:
            raw = chat_completion(
                cfg,
                system=INFRA_CONFIG_SYSTEM,
                user=infra_config_user_message(workspace_summary=summary),
            )
            return extract_json_object(raw)
        except Exception as e:
            return {
                "parse_error": str(e),
                "findings": [],
                "infra_brief": "",
                "config_risks": [],
                "hardening_checks": [],
            }

    run_infra = cfg.parallel_specialists >= 3
    workers = 3 if run_infra else 2
    result.infra_specialist_ran = run_infra

    with ThreadPoolExecutor(max_workers=workers) as pool:
        fut_c = pool.submit(_code_payload)
        fut_o = pool.submit(_osint_payload)
        fut_i = pool.submit(_infra_payload) if run_infra else None
        d_code = fut_c.result()
        d_osint = fut_o.result()
        d_infra = fut_i.result() if fut_i is not None else None

    result.transcript.append(
        {"phase": "parallel_open", "agent": "code_analyst", "data": d_code}
    )
    result.transcript.append(
        {"phase": "parallel_open", "agent": "osint_surface", "data": d_osint}
    )
    if d_infra is not None:
        result.transcript.append(
            {"phase": "parallel_open", "agent": "infra_config", "data": d_infra}
        )

    result.static_analysis_brief = str(d_code.get("analysis_brief") or "")
    _merge_findings(result.findings, list(d_code.get("findings") or []))
    result.osint_surface_brief = str(d_osint.get("surface_brief") or "")
    sc = d_osint.get("suggested_checks")
    if isinstance(sc, list):
        result.osint_suggested_checks = [str(x) for x in sc if x][:50]

    if d_infra is not None:
        result.infra_config_brief = str(d_infra.get("infra_brief") or "")
        cr = d_infra.get("config_risks")
        if isinstance(cr, list):
            result.infra_config_risks = [str(x) for x in cr if x][:60]
        hc = d_infra.get("hardening_checks")
        if isinstance(hc, list):
            result.infra_hardening_hints = [str(x) for x in hc if x][:50]
        _merge_findings(result.findings, list(d_infra.get("findings") or []))

    parts: list[str] = []
    if result.static_analysis_brief:
        parts.append("### Code analyst (parallel)\n" + result.static_analysis_brief)
    if result.osint_surface_brief:
        parts.append("### OSINT surface (parallel)\n" + result.osint_surface_brief)
    if result.osint_suggested_checks:
        parts.append(
            "### OSINT suggested checks\n"
            + "\n".join(f"- {x}" for x in result.osint_suggested_checks)
        )
    if result.infra_config_brief or result.infra_config_risks or result.infra_hardening_hints:
        ib = result.infra_config_brief or ""
        parts.append("### Infra / config (parallel)\n" + ib.strip())
        if result.infra_config_risks:
            parts.append(
                "**Config risks:**\n"
                + "\n".join(f"- {x}" for x in result.infra_config_risks[:40])
            )
        if result.infra_hardening_hints:
            parts.append(
                "**Hardening checks (for Exploit/Recon):**\n"
                + "\n".join(f"- {x}" for x in result.infra_hardening_hints[:40])
            )
    prior = "\n\n".join(p for p in parts if p.strip())
    summary_recon = summary + (
        "\n\n## Parallel specialist output (already completed)\n" + prior if prior else ""
    )
    return prior, summary_recon


def run_team_scan(
    workspace: Path,
    cfg: AppConfig,
    *,
    allow_network: bool = False,
) -> ScanResult:
    """Distributed workflow: parallel specialists → Recon → Exploit → Validator → Remediator + knowledge graph."""
    build_sandbox_image_if_needed(None, cfg.docker_image_sandbox)
    summary = _collect_workspace_summary(workspace, cfg)
    result = ScanResult()

    prior_parallel, summary_recon = _parallel_opening_specialists(cfg, summary, result)

    r_turns, e_turns, v_turns = _budget_turns(cfg)
    recon_summary, priority = _phase_recon(
        workspace, cfg, allow_network, summary_recon, result, r_turns
    )
    result.recon_brief = recon_summary
    result.priority_targets = priority

    _phase_exploit(
        workspace,
        cfg,
        allow_network,
        summary,
        recon_summary,
        priority,
        result,
        e_turns,
        prior_parallel_context=prior_parallel,
    )
    result.findings = dedupe_findings(result.findings)

    _phase_validate(workspace, cfg, allow_network, summary, result, v_turns)
    result.findings = dedupe_findings(result.findings)

    if cfg.run_remediation_pass:
        _run_remediation_phase(cfg, summary, result)

    kg = build_knowledge_graph(
        finding_titles=[f.title for f in result.findings],
        priority_targets=result.priority_targets,
        infra_specialist_ran=result.infra_specialist_ran,
    )
    result.knowledge_graph = kg.to_dict()
    result.orchestration_mermaid = kg.mermaid_flowchart()

    return result


def run_red_team_scan(
    workspace: Path,
    cfg: AppConfig,
    *,
    allow_network: bool = False,
    use_agent_team: bool = True,
) -> ScanResult:
    if use_agent_team and cfg.use_agent_team:
        return run_team_scan(workspace, cfg, allow_network=allow_network)
    return run_single_agent_scan(workspace, cfg, allow_network=allow_network)
