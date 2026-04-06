from __future__ import annotations

import json
from pathlib import Path

from secagents.agents.orchestrator import AutoFixItem, ScanFinding, ScanResult
from secagents.config import Severity, severity_rank, should_fail_ci


def _render_autofix_section(auto_fixes: list[AutoFixItem]) -> str:
    if not auto_fixes:
        return ""
    lines: list[str] = ["## Auto-fix bundle", ""]
    for i, fx in enumerate(auto_fixes, start=1):
        lines.append(f"### Fix {i}: `{fx.finding_title or 'finding'}` → `{fx.file_path or 'n/a'}`")
        if fx.explanation:
            lines.append(fx.explanation)
            lines.append("")
        if fx.patch.strip():
            lines.append("```diff")
            lines.append(fx.patch.strip()[:20000])
            lines.append("```")
            lines.append("")
    return "\n".join(lines)


def _render_h1_report(target_label: str, result: ScanResult, provider: str, model: str) -> str:
    lines = ["# Security Scan Overview (HackerOne run)", "", f"**Target:** {target_label}", ""]
    
    cvss_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "none"
    }

    for f in result.findings:
        sev = cvss_map.get(f.severity.lower(), "none")
        lines.extend([
            "## Vulnerability Report",
            "",
            f"**Title:** {f.title[:100]}",
            f"**Severity:** {sev}",
            f"**Asset:** {target_label}",
            "",
            "### Summary",
            f"The scanner identified a potential {f.category} vulnerability. {f.evidence}",
            "",
            "### Steps to Reproduce",
            f"1. Attempt the following payload/command: `{f.poc_command or 'N/A'}`",
            "",
            "### Impact",
            f"An attacker may exploit this {f.category} issue. {f.poc_output_excerpt}",
            "",
            "### Supporting Material",
            "See the automated scan transcript for full steps.",
            "",
            "### Suggested Fix",
            f"{(f.suggested_patch or 'Review and patch the endpoint.')}",
            ""
        ])
    return "\n".join(lines)


def _bugcrowd_vrt_map(category: str) -> str:
    cat = category.lower()
    if 'xss' in cat or 'cross-site' in cat:
        return "Cross-Site Scripting (XSS)"
    if 'sqli' in cat or 'sql' in cat:
        return "SQL Injection"
    if 'ssrf' in cat:
        return "Server-Side Request Forgery (SSRF)"
    if 'idor' in cat:
        return "Insecure Direct Object Reference (IDOR)"
    if 'oauth' in cat:
        return "OAuth / OpenID Related Issues"
    if 'race' in cat or 'toctou' in cat:
        return "Race Condition"
    if 'inject' in cat:
        return "Injection"
    if 'sensitive' in cat or 'data' in cat:
        return "Sensitive Data Exposure"
    if 'auth' in cat:
        return "Broken Authentication"
    return "Uncategorized"

def _render_bugcrowd_report(target_label: str, result: ScanResult, provider: str, model: str) -> str:
    lines = ["# External Scan Document (Bugcrowd run)", "", f"**Target:** {target_label}", ""]
    
    cvss_score_map = {
        "critical": "9.0",
        "high": "7.5",
        "medium": "5.0",
        "low": "3.0",
        "info": "0.0"
    }

    for f in result.findings:
        vrt = _bugcrowd_vrt_map(f.category)
        score = cvss_score_map.get(f.severity.lower(), "0.0")
        lines.extend([
            "## Bug Report",
            "",
            f"**Title:** {f.title}",
            f"**VRT Category:** {vrt}",
            f"**Target:** {target_label}",
            f"**CVSS Score:** {score} (Network/Adjacent)",
            "",
            "### Description",
            f"{f.evidence}",
            "",
            "### Reproduction Steps",
            f"`{f.poc_command or 'N/A'}`",
            "",
            "### Impact Assessment",
            f"Exploiting this allows access mapping to {score} severity.",
            "",
            "### Remediation",
            f"{(f.suggested_patch or 'Follow best security practices.')}",
            ""
        ])
    return "\n".join(lines)

def render_markdown_report(
    target_label: str,
    result: ScanResult,
    *,
    provider: str,
    model: str,
    platform: str = "generic",
) -> str:
    if platform == "h1":
        return _render_h1_report(target_label, result, provider, model)
    if platform == "bugcrowd":
        return _render_bugcrowd_report(target_label, result, provider, model)
    lines: list[str] = [
        "# SecAgents security report",
        "",
        f"- **Target:** `{target_label}`",
        f"- **Model:** `{provider}` / `{model}`",
        "",
        "Distributed workflow: **parallel specialists** (Code analyst + OSINT; optional **Infra/Config** "
        "when `--parallel-specialists` ≥ 3) → **Recon** → **Exploit/PoC** → **Validator** → **Remediator**.",
        "",
        "**Agentic toolkit (sandbox):** HTTP proxy via mitmproxy/helpers, headless Chromium for DOM/XSS/CSRF "
        "style checks, batch terminals, **Python** (+ bandit), recon utilities, static + dynamic validation, "
        "**knowledge graph** export.",
        "",
    ]
    if (
        result.static_analysis_brief
        or result.osint_surface_brief
        or result.osint_suggested_checks
        or result.infra_config_brief
        or result.infra_config_risks
        or result.infra_hardening_hints
    ):
        lines.append("## Parallel specialists (shared into Recon/Exploit)")
        lines.append("")
        if result.static_analysis_brief:
            lines.append("### Code analyst (static)")
            lines.append(result.static_analysis_brief.strip())
            lines.append("")
        if result.osint_surface_brief:
            lines.append("### OSINT / attack surface")
            lines.append(result.osint_surface_brief.strip())
            lines.append("")
        if result.osint_suggested_checks:
            lines.append("### OSINT suggested checks")
            for s in result.osint_suggested_checks[:35]:
                lines.append(f"- {s}")
            lines.append("")
        if result.infra_config_brief or result.infra_config_risks or result.infra_hardening_hints:
            lines.append("### Infra / config (parallel)")
            if result.infra_config_brief:
                lines.append(result.infra_config_brief.strip())
                lines.append("")
            if result.infra_config_risks:
                lines.append("**Config risks:**")
                for r in result.infra_config_risks[:35]:
                    lines.append(f"- {r}")
                lines.append("")
            if result.infra_hardening_hints:
                lines.append("**Hardening checks:**")
                for h in result.infra_hardening_hints[:35]:
                    lines.append(f"- {h}")
                lines.append("")
    if result.recon_brief:
        lines.append("## Attack surface (Recon)")
        lines.append(result.recon_brief.strip())
        lines.append("")
        if result.priority_targets:
            lines.append("**Priority targets:**")
            for p in result.priority_targets[:40]:
                lines.append(f"- `{p}`")
            lines.append("")

    if result.remediation_summary:
        lines.append("## Remediation summary")
        lines.append(result.remediation_summary.strip())
        lines.append("")

    if result.final_report_markdown and result.final_report_markdown != result.remediation_summary:
        lines.append("## Executive notes")
        lines.append(result.final_report_markdown.strip())
        lines.append("")

    validated = [f for f in result.findings if f.validated]
    unvalidated = [f for f in result.findings if not f.validated]
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def sort_key(ff: ScanFinding) -> tuple[int, str]:
        return (sev_order.get(ff.severity.lower(), 99), ff.title)

    def _finding_block(f: ScanFinding, heading_level: str = "###") -> list[str]:
        v = "validated" if f.validated else "unvalidated"
        out = [
            f"{heading_level} [{f.severity.upper()}] {f.title} _({v})_",
            f"- **Category:** {f.category}",
            f"- **Evidence:** {f.evidence}",
        ]
        if f.poc_command:
            out.append(f"- **PoC command:** `{f.poc_command}`")
        if f.poc_output_excerpt:
            out.append(f"- **PoC excerpt:**\n\n```\n{f.poc_output_excerpt[:4000]}\n```")
        if f.remediation_steps:
            out.append("- **Remediation:**")
            for step in f.remediation_steps:
                out.append(f"  - {step}")
        if f.suggested_patch.strip():
            out.append("- **Suggested fix:**\n\n```\n" + f.suggested_patch.strip() + "\n```")
        out.append("")
        return out

    lines.append("## Validated findings (PoC-backed)")
    lines.append("")
    if not validated:
        lines.append("_None recorded as validated; triage unvalidated items below._")
        lines.append("")
    else:
        for f in sorted(validated, key=sort_key):
            lines.extend(_finding_block(f))

    lines.append("## Needs triage (unvalidated)")
    lines.append("")
    if not unvalidated:
        lines.append("_All findings have PoC validation, or no findings._")
        lines.append("")
    else:
        for f in sorted(unvalidated, key=lambda x: (sev_order.get(x.severity.lower(), 99), x.title)):
            lines.extend(_finding_block(f))

    lines.append(_render_autofix_section(result.auto_fixes))

    if result.knowledge_graph:
        lines.append("## Knowledge graph (structured)")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(result.knowledge_graph, indent=2)[:14000])
        lines.append("```")
        lines.append("")
    if result.orchestration_mermaid:
        lines.append("## Agent orchestration (Mermaid)")
        lines.append("")
        lines.append("```mermaid")
        lines.append(result.orchestration_mermaid.strip())
        lines.append("```")
        lines.append("")

    if not result.findings:
        lines.append("## Findings")
        lines.append("")
        lines.append("_No findings recorded._")
        lines.append("")

    lines.append("## Agent transcript (compact)")
    lines.append("")
    lines.append("```json")
    lines.append(json.dumps(result.transcript, indent=2)[:12000])
    lines.append("```")
    return "\n".join(lines)


def findings_to_json(target_label: str, result: ScanResult, *, provider: str, model: str) -> str:
    payload = {
        "target": target_label,
        "provider": provider,
        "model": model,
        "recon_brief": result.recon_brief,
        "priority_targets": result.priority_targets,
        "remediation_summary": result.remediation_summary,
        "findings": [
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
            for f in result.findings
        ],
        "auto_fixes": [
            {
                "finding_title": x.finding_title,
                "file_path": x.file_path,
                "patch": x.patch,
                "explanation": x.explanation,
            }
            for x in result.auto_fixes
        ],
        "transcript": result.transcript,
        "final_report_markdown": result.final_report_markdown,
        "static_analysis_brief": result.static_analysis_brief,
        "osint_surface_brief": result.osint_surface_brief,
        "osint_suggested_checks": result.osint_suggested_checks,
        "infra_config_brief": result.infra_config_brief,
        "infra_config_risks": result.infra_config_risks,
        "infra_hardening_hints": result.infra_hardening_hints,
        "ran_specialists": result.ran_specialists,
        "knowledge_graph": result.knowledge_graph,
        "orchestration_mermaid": result.orchestration_mermaid,
    }
    return json.dumps(payload, indent=2)


def write_autofix_markdown(out_dir: Path, result: ScanResult) -> Path | None:
    if not result.auto_fixes:
        return None
    path = out_dir / "autofix.md"
    body = _render_autofix_section(result.auto_fixes)
    path.write_text("# SecAgents auto-fix bundle\n\n" + body, encoding="utf-8")
    return path


def write_reports(
    out_dir: Path,
    target_label: str,
    result: ScanResult,
    *,
    provider: str,
    model: str,
    platform: str = "generic",
) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / "report.md"
    json_path = out_dir / "report.json"
    md_path.write_text(
        render_markdown_report(target_label, result, provider=provider, model=model, platform=platform),
        encoding="utf-8",
    )
    json_path.write_text(
        findings_to_json(target_label, result, provider=provider, model=model),
        encoding="utf-8",
    )
    write_autofix_markdown(out_dir, result)
    if result.knowledge_graph:
        (out_dir / "knowledge_graph.json").write_text(
            json.dumps(result.knowledge_graph, indent=2),
            encoding="utf-8",
        )
    return md_path, json_path


def max_severity(result: ScanResult) -> Severity | None:
    rank_map = {
        "critical": Severity.critical,
        "high": Severity.high,
        "medium": Severity.medium,
        "low": Severity.low,
        "info": Severity.info,
    }
    best: Severity | None = None

    for f in result.findings:
        s = rank_map.get(f.severity.lower())
        if s is None:
            continue
        if best is None or severity_rank(s) > severity_rank(best):
            best = s
    return best


def ci_should_fail(result: ScanResult, fail_on: Severity) -> bool:
    for f in result.findings:
        try:
            s = Severity(f.severity.lower())
        except ValueError:
            continue
        if should_fail_ci(fail_on, s):
            return True
    return False
