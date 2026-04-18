"""Enhanced reporting with detailed findings, CVSS scores, and beautiful formatting."""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

from secagents.agents.orchestrator import ScanFinding, ScanResult


@dataclass
class CVSSMetrics:
    """CVSS v3.1 vector components and resulting score."""
    
    av: str = "N"  # Attack Vector: N=Network, A=Adjacent, L=Local, P=Physical
    ac: str = "L"  # Attack Complexity: L=Low, H=High
    pr: str = "N"  # Privileges Required: N=None, L=Low, H=High
    ui: str = "N"  # User Interaction: N=None, R=Required
    s: str = "U"   # Scope: U=Unchanged, C=Changed
    c: str = "H"   # Confidentiality: H=High, L=Low, N=None
    i: str = "H"   # Integrity: H=High, L=Low, N=None
    a: str = "H"   # Availability: H=High, L=Low, N=None
    base_score: float = 0.0
    severity: str = "medium"  # Critical, High, Medium, Low
    vector: str = ""
    
    def calculate_vector(self) -> str:
        """Generate CVSS vector string."""
        self.vector = (
            f"CVSS:3.1/AV:{self.av}/AC:{self.ac}/PR:{self.pr}/UI:{self.ui}/"
            f"S:{self.s}/C:{self.c}/I:{self.i}/A:{self.a}"
        )
        return self.vector
    
    def guess_score_from_severity(self, severity: str) -> float:
        """Estimate base score from categorical severity."""
        severity = severity.lower()
        if severity == "critical":
            return 9.0
        elif severity == "high":
            return 7.5
        elif severity == "medium":
            return 5.0
        elif severity == "low":
            return 3.0
        else:
            return 0.1


@dataclass
class DetailedFinding:
    """Extended finding with CVSS, impact, and remediation details."""
    
    title: str
    severity: str
    category: str
    evidence: str
    validated: bool
    poc_command: str
    poc_output_excerpt: str
    remediation_steps: list[str]
    suggested_patch: str
    
    # Extended fields
    cvss_metrics: CVSSMetrics | None = None
    cvss_score: float = 0.0
    business_impact: str = ""
    attack_complexity: str = "Low"  # Low, Moderate, High
    likelihood: str = "High"  # High, Medium, Low
    affected_components: list[str] | None = None
    cwe_ids: list[str] | None = None
    references: list[str] | None = None
    confidence_score: float = 1.0
    false_positive_risk: str = "Low"  # High, Medium, Low
    remediation_difficulty: str = "Medium"  # Easy, Medium, Hard
    estimated_fix_time: str = "2-4 hours"
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, handling complex types."""
        data = asdict(self)
        if self.cvss_metrics:
            data['cvss_metrics'] = asdict(self.cvss_metrics)
        return data


def enhance_finding_with_cvss(
    finding: ScanFinding,
    severity_override: str | None = None,
) -> DetailedFinding:
    """Enhance a basic finding with CVSS metrics and additional details."""
    
    severity = severity_override or finding.severity
    
    # Create CVSS metrics based on finding characteristics
    cvss = CVSSMetrics()
    cvss.base_score = cvss.guess_score_from_severity(severity)
    
    # Estimate metrics based on category
    category_lower = finding.category.lower()
    
    if "idor" in category_lower or "auth" in category_lower:
        cvss.av = "N"
        cvss.pr = "N"
        cvss.ui = "N"
        cvss.c = "H"
        cvss.i = "H"
        cvss.a = "H"
    
    elif "xss" in category_lower or "injection" in category_lower:
        cvss.av = "N"
        cvss.ac = "L"
        cvss.pr = "N"
        cvss.ui = finding.poc_output_excerpt != "User interaction required" and "N" or "R"
    
    elif "ssrf" in category_lower or "xxe" in category_lower:
        cvss.av = "N"
        cvss.pr = "L" if "upload" in finding.evidence.lower() else "N"
        cvss.ui = "N"
    
    elif "race" in category_lower or "timing" in category_lower:
        cvss.ac = "H"
        cvss.pr = "N"
        cvss.ui = "N"
    
    cvss.calculate_vector()
    
    # Estimate business impact
    impact = ""
    if severity.lower() == "critical":
        impact = "Complete system compromise, data breach, or service disruption"
    elif severity.lower() == "high":
        impact = "Significant access to sensitive data or functionality"
    elif severity.lower() == "medium":
        impact = "Moderate unauthorized access or information disclosure"
    else:
        impact = "Minor impact or edge case vulnerability"
    
    # Estimate remediation difficulty
    if "database" in finding.evidence.lower() or "architecture" in finding.evidence.lower():
        remediation_difficulty = "Hard"
        fix_time = "1-3 weeks"
    elif "configuration" in finding.evidence.lower() or "header" in finding.evidence.lower():
        remediation_difficulty = "Easy"
        fix_time = "1-2 hours"
    else:
        remediation_difficulty = "Medium"
        fix_time = "4-8 hours"
    
    # Extract CWE IDs if mentioned in evidence
    cwe_ids = []
    if "CWE-" in finding.evidence:
        import re
        cwe_matches = re.findall(r'CWE-\d+', finding.evidence)
        cwe_ids = list(set(cwe_matches))
    
    return DetailedFinding(
        title=finding.title,
        severity=severity,
        category=finding.category,
        evidence=finding.evidence,
        validated=finding.validated,
        poc_command=finding.poc_command,
        poc_output_excerpt=finding.poc_output_excerpt,
        remediation_steps=finding.remediation_steps,
        suggested_patch=finding.suggested_patch,
        cvss_metrics=cvss,
        cvss_score=cvss.base_score,
        business_impact=impact,
        cwe_ids=cwe_ids if cwe_ids else None,
        confidence_score=0.95 if finding.validated else 0.65,
        remediation_difficulty=remediation_difficulty,
        estimated_fix_time=fix_time,
    )


def render_enhanced_markdown_report(
    target_label: str,
    result: ScanResult,
    *,
    provider: str,
    model: str,
    include_technical: bool = True,
) -> str:
    """Render comprehensive markdown report with enhanced findings."""
    
    lines = [
        "# SecAgents Security Audit Report",
        "",
        f"**Target**: {target_label}",
        f"**Model**: {provider} / {model}",
        "",
    ]
    
    # Summary metrics
    findings_by_severity = {}
    for finding in result.findings:
        sev = finding.severity.lower()
        findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1
    
    lines.append("## Executive Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = findings_by_severity.get(sev, 0)
        if count > 0:
            lines.append(f"| {sev.capitalize()} | {count} |")
    
    lines.append("")
    
    if result.findings:
        total_findings = len(result.findings)
        lines.append(f"**Total Findings**: {total_findings}")
        lines.append("")
        
        # Enhance and list findings
        for i, finding in enumerate(result.findings, 1):
            enhanced = enhance_finding_with_cvss(finding)
            
            lines.append(f"## Finding {i}: {enhanced.title}")
            lines.append("")
            
            # Severity and CVSS
            lines.append(f"**Severity**: {enhanced.severity.upper()}")
            if enhanced.cvss_score > 0:
                vector = enhanced.cvss_metrics.vector if enhanced.cvss_metrics is not None else ""
                lines.append(f"**CVSS v3.1**: {enhanced.cvss_score} ({vector})")
            lines.append(f"**Category**: {enhanced.category}")
            lines.append("")
            
            # Metadata
            metadata = []
            if enhanced.confidence_score > 0:
                metadata.append(f"Confidence: {int(enhanced.confidence_score*100)}%")
            metadata.append(f"Complexity: {enhanced.attack_complexity}")
            metadata.append(f"Likelihood: {enhanced.likelihood}")
            if enhanced.cwe_ids:
                metadata.append(f"CWEs: {', '.join(enhanced.cwe_ids)}")
            
            if metadata:
                lines.append("| Metric | Value |")
                lines.append("|--------|-------|")
                for meta in metadata:
                    if ":" in meta:
                        k, v = meta.split(":", 1)
                        lines.append(f"| {k.strip()} | {v.strip()} |")
                lines.append("")
            
            # Description
            lines.append("### Description")
            lines.append(f"{enhanced.evidence}")
            lines.append("")
            
            if enhanced.business_impact:
                lines.append("### Business Impact")
                lines.append(f"{enhanced.business_impact}")
                lines.append("")
            
            # Proof of Concept
            if enhanced.poc_command:
                lines.append("### Proof of Concept")
                lines.append(f"**Command**: `{enhanced.poc_command}`")
                lines.append("")
                if enhanced.poc_output_excerpt:
                    lines.append("**Expected Output**:")
                    lines.append("```")
                    lines.append(enhanced.poc_output_excerpt[:500])
                    lines.append("```")
                    lines.append("")
            
            # Remediation
            lines.append("### Remediation")
            lines.append(f"**Difficulty**: {enhanced.remediation_difficulty}")
            lines.append(f"**Estimated Time**: {enhanced.estimated_fix_time}")
            lines.append("")
            lines.append("**Steps**:")
            for step in enhanced.remediation_steps:
                lines.append(f"1. {step}")
            lines.append("")
            
            if enhanced.suggested_patch:
                lines.append("**Patch**:")
                lines.append("```diff")
                lines.append(enhanced.suggested_patch[:1000])
                lines.append("```")
                lines.append("")
    
    else:
        lines.append("**No vulnerabilities found.**")
        lines.append("")
    
    # Appendix
    lines.append("## Methodology")
    lines.append(
        "This security assessment was conducted using an autonomous multi-agent "
        "red-team framework with the following agents: "
    )
    
    if result.ran_specialists:
        lines.append(", ".join(result.ran_specialists))
    else:
        lines.append("Recon, Exploit/PoC, Validator, Remediator")
    
    lines.append("")
    
    if result.recon_brief:
        lines.append("## Reconnaissance Brief")
        lines.append(result.recon_brief[:500])
        lines.append("")
    
    return "\n".join(lines)


def render_json_report(
    target_label: str,
    result: ScanResult,
) -> str:
    """Render findings as structured JSON for integration."""
    
    findings_data = []
    for finding in result.findings:
        enhanced = enhance_finding_with_cvss(finding)
        findings_data.append(enhanced.to_dict())
    
    report = {
        "target": target_label,
        "total_findings": len(result.findings),
        "findings": findings_data,
        "summary": {
            "critical": sum(1 for f in result.findings if f.severity.lower() == "critical"),
            "high": sum(1 for f in result.findings if f.severity.lower() == "high"),
            "medium": sum(1 for f in result.findings if f.severity.lower() == "medium"),
            "low": sum(1 for f in result.findings if f.severity.lower() == "low"),
        }
    }
    
    return json.dumps(report, indent=2, default=str)


def render_cvss_dashboard(result: ScanResult) -> str:
    """Render CVSS score distribution and risk matrix."""
    
    lines = ["# Vulnerability Risk Dashboard", ""]
    
    if not result.findings:
        return "No vulnerabilities to display."
    
    # Create risk matrix
    risk_matrix = {
        "Critical": [],
        "High": [],
        "Medium": [],
        "Low": [],
        "Info": []
    }
    
    avg_cvss = 0.0
    cvss_scores = []
    
    for finding in result.findings:
        enhanced = enhance_finding_with_cvss(finding)
        severity_key = finding.severity.capitalize()
        if severity_key in risk_matrix:
            risk_matrix[severity_key].append(enhanced)
            cvss_scores.append(enhanced.cvss_score)
    
    if cvss_scores:
        avg_cvss = sum(cvss_scores) / len(cvss_scores)
    
    lines.append(f"## Risk Metrics")
    lines.append(f"- **Average CVSS Score**: {avg_cvss:.2f}")
    lines.append(f"- **Highest Risk**: {max(cvss_scores):.1f}")
    lines.append(f"- **Lowest Risk**: {min(cvss_scores):.1f}")
    lines.append("")
    
    # Risk by category
    lines.append("## Findings by Severity")
    lines.append("")
    
    for severity_level in ["Critical", "High", "Medium", "Low", "Info"]:
        findings = risk_matrix[severity_level]
        if findings:
            lines.append(f"### {severity_level} ({len(findings)})")
            for finding in findings[:5]:  # Show top 5
                lines.append(f"  - {finding.title} (CVSS: {finding.cvss_score})")
            if len(findings) > 5:
                lines.append(f"  - ... and {len(findings) - 5} more")
            lines.append("")
    
    return "\n".join(lines)
