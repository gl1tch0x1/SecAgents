"""Multi-AI Consensus & Verification System for reducing false positives.

This module implements a consensus-based approach where multiple LLMs verify findings
before they're included in the final report. This dramatically reduces false positives.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from secagents.config import AppConfig, LLMProvider
from secagents.llm.providers import chat_completion, extract_json_object


@dataclass
class ConsensusVote:
    """A single LLM's evaluation of a finding."""
    
    provider: str
    model: str
    is_valid: bool
    confidence: float  # 0.0-1.0
    reasoning: str
    severity_adjustment: str | None = None


@dataclass
class ConsensusResult:
    """Result of multi-AI consensus on a finding."""
    
    finding_title: str
    votes: list[ConsensusVote] = field(default_factory=list)
    agreement_rate: float = 0.0  # percentage of votes that agree it's valid
    final_decision: bool = False  # True if consensus reached
    confidence_score: float = 0.0  # 0.0-1.0
    recommended_severity: str | None = None
    should_include_in_report: bool = True
    reason: str = ""


CONSENSUS_VERIFICATION_PROMPT = """You are a security expert validating a vulnerability finding.

**FINDING TO VERIFY:**
Title: {title}
Severity: {severity}
Category: {category}
Evidence: {evidence}
PoC Command: {poc_command}
PoC Output: {poc_output_excerpt}
Remediation Steps: {remediation_steps}
Suggested Patch: {suggested_patch}
Validated: {validated}

**YOUR TASK:**
Evaluate whether this finding is a REAL vulnerability or a FALSE POSITIVE.

Consider:
1. Is the evidence compelling and reproducible?
2. Does the PoC actually demonstrate impact?
3. Are there common false positives this resembles?
4. What's the actual severity if real?
5. Could this be a limitation/feature rather than a bug?

Return ONLY valid JSON (no markdown):
{{
  "is_valid": boolean,
  "confidence": 0.0-1.0,
  "reasoning": "string — explain your decision",
  "severity_adjustment": "critical|high|medium|low|info|none" or null,
  "false_positive_likelihood": "string — why this might be FP if invalid"
}}
"""


def verify_finding_consensus(
    cfg: AppConfig,
    title: str,
    severity: str,
    category: str,
    evidence: str,
    poc_command: str,
    poc_output_excerpt: str,
    remediation_steps: list[str],
    suggested_patch: str,
    validated: bool,
    *,
    verify_models: list[str] | None = None,
) -> ConsensusResult:
    """
    Verify a single finding using consensus from multiple LLMs.
    
    Args:
        cfg: Application configuration
        title, severity, category, evidence, poc_*, remediation_*, suggested_patch: Finding details
        validated: Whether the Exploit agent already validated this
        verify_models: List of models to use for verification. If None, uses cfg.consensus_models
    
    Returns:
        ConsensusResult with votes and final decision
    """
    if not cfg.use_multi_ai_consensus or not verify_models:
        # Bypass consensus if disabled
        return ConsensusResult(
            finding_title=title,
            votes=[],
            agreement_rate=1.0,
            final_decision=True,
            confidence_score=1.0 if validated else 0.5,
            should_include_in_report=True,
            reason="Consensus verification disabled or no models specified"
        )
    
    result = ConsensusResult(finding_title=title)
    
    # Format the verification prompt
    prompt = CONSENSUS_VERIFICATION_PROMPT.format(
        title=title,
        severity=severity,
        category=category,
        evidence=evidence[:500],  # Limit context
        poc_command=poc_command,
        poc_output_excerpt=poc_output_excerpt[:300],
        remediation_steps=", ".join(remediation_steps[:3]),
        suggested_patch=suggested_patch[:200],
        validated=validated
    )
    
    # Collect votes from each verification model
    for model_spec in verify_models[:cfg.consensus_min_agreement + 2]:  # Get a few extra
        try:
            vote = _single_model_verdict(cfg, model_spec, prompt)
            result.votes.append(vote)
        except Exception as e:
            # Log but continue if one model fails
            result.votes.append(ConsensusVote(
                provider="error",
                model=model_spec,
                is_valid=validated,  # Fallback to original validation
                confidence=0.3,
                reasoning=f"Verification failed: {str(e)}"
            ))
    
    # Calculate consensus metrics
    if result.votes:
        valid_votes = sum(1 for v in result.votes if v.is_valid)
        result.agreement_rate = valid_votes / len(result.votes)
        
        # Average confidence from valid votes
        valid_confidences = [v.confidence for v in result.votes if v.is_valid]
        result.confidence_score = sum(valid_confidences) / len(valid_confidences) if valid_confidences else 0.0
        
        # Consensus decision: require minimum agreement
        min_required = max(1, cfg.consensus_min_agreement)
        result.final_decision = valid_votes >= min_required
        
        # Recommend severity adjustment if consensus suggests it
        severity_adjustments = [v.severity_adjustment for v in result.votes if v.severity_adjustment]
        if severity_adjustments:
            result.recommended_severity = severity_adjustments[0]
        
        # Generate reason
        if result.final_decision:
            result.reason = f"Consensus verified: {valid_votes}/{len(result.votes)} models agree this is valid"
        else:
            result.reason = f"Consensus failed: only {valid_votes}/{len(result.votes)} models agree this is valid"
        
        # Apply confidence threshold
        result.should_include_in_report = (
            result.final_decision and 
            result.confidence_score >= cfg.confidence_threshold
        )
    
    return result


def _single_model_verdict(
    cfg: AppConfig,
    model_spec: str,
    prompt: str,
) -> ConsensusVote:
    """Get a single model's verdict on a finding."""
    
    # Parse model spec (format: "provider:model" or just "model")
    provider_str = "openai"  # default
    model_name = model_spec
    
    if ":" in model_spec:
        provider_str, model_name = model_spec.split(":", 1)
    
    # Temporarily use target model for this chat completion
    original_provider = cfg.provider
    original_model = cfg.model
    
    try:
        cfg.provider = _get_provider(provider_str)
        cfg.model = model_name
        
        response = chat_completion(
            cfg,
            system="You are a cybersecurity expert verifying vulnerability findings. Be critical and conservative to avoid false positives.",
            user=prompt
        )
        
        data = extract_json_object(response)
        
        return ConsensusVote(
            provider=provider_str,
            model=model_name,
            is_valid=bool(data.get("is_valid", False)),
            confidence=float(data.get("confidence", 0.5)),
            reasoning=str(data.get("reasoning", "")),
            severity_adjustment=data.get("severity_adjustment")
        )
    
    except Exception as e:
        raise RuntimeError(f"Failed to get verdict from {model_spec}: {str(e)}")
    
    finally:
        cfg.provider = original_provider
        cfg.model = original_model


def _get_provider(provider_str: str) -> LLMProvider:
    """Parse provider string to LLMProvider enum."""
    try:
        return LLMProvider(provider_str.lower())
    except ValueError:
        return LLMProvider.openai  # default fallback


def filter_findings_by_confidence(
    findings: list[dict[str, Any]],
    consensus_results: dict[str, ConsensusResult],
    threshold: float = 0.75,
) -> tuple[list[dict[str, Any]], list[str]]:
    """
    Filter findings based on consensus confidence scores.
    
    Returns:
        (high_confidence_findings, low_confidence_finding_titles)
    """
    high_confidence = []
    low_confidence = []
    
    for finding in findings:
        title = finding.get("title", "")
        consensus = consensus_results.get(title)
        
        if not consensus:
            high_confidence.append(finding)  # No verification attempted
            continue
        
        if consensus.should_include_in_report:
            # Update severity if consensus recommends
            if consensus.recommended_severity:
                finding["severity"] = consensus.recommended_severity
            high_confidence.append(finding)
        else:
            low_confidence.append(title)
    
    return high_confidence, low_confidence


# False Positive Filter Rules
FALSE_POSITIVE_PATTERNS = {
    "info_severity": {
        "keywords": ["info", "notice", "advisory"],
        "min_severity": "low",
        "reason": "Info-level findings often are not actionable"
    },
    "missing_poc": {
        "keywords": ["poc_output_excerpt"],
        "must_have_value": True,
        "reason": "Findings without PoC output are less reliable"
    },
    "unvalidated": {
        "keywords": ["validated"],
        "must_be_true": True,
        "confidence_penalty": 0.2,
        "reason": "Unvalidated findings have lower confidence"
    },
    "generic_evidence": {
        "patterns": ["appears", "might", "could", "may be vulnerable"],
        "Min_confidence": 0.6,
        "reason": "Vague evidence indicates potential false positive"
    },
}


def apply_false_positive_filter(
    finding: dict[str, Any],
    cfg: AppConfig,
) -> tuple[bool, float, str]:
    """
    Apply heuristic filters to identify likely false positives.
    
    Returns:
        (should_keep_finding, confidence_penalty, reason)
    """
    if not cfg.enable_false_positive_filter:
        return True, 0.0, ""
    
    penalties = []
    reasons = []
    
    # Check severity
    severity = str(finding.get("severity", "")).lower()
    if severity == "info":
        penalties.append(0.15)
        reasons.append("Info-level severity is often not actionable")
    
    # Check PoC presence
    poc = finding.get("poc_output_excerpt", "").strip()
    if not poc:
        penalties.append(0.3)
        reasons.append("Missing PoC output reduces confidence")
    
    # Check validation status
    if not finding.get("validated", False):
        penalties.append(0.2)
        reasons.append("Finding not validated by exploit agent")
    
    # Check evidence quality
    evidence = str(finding.get("evidence", "")).lower()
    vague_words = ["appears", "might", "could", "may be", "possibly", "seems"]
    vague_count = sum(1 for w in vague_words if w in evidence)
    if vague_count >= 2:
        penalties.append(0.25)
        reasons.append(f"Multiple vague indicators ({vague_count}) found in evidence")
    
    # Calculate total penalty
    total_penalty = sum(penalties)
    keep_finding = total_penalty < 0.6  # Threshold
    
    return keep_finding, total_penalty, "; ".join(reasons)
