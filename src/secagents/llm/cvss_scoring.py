"""CVSS v3.1 scoring system for automated vulnerability assessment.

Implements CVSS v3.1 scoring to provide standardized vulnerability severity ratings.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class AttackVector(StrEnum):
    """Attack Vector (AV) metric."""
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"


class AttackComplexity(StrEnum):
    """Attack Complexity (AC) metric."""
    LOW = "L"
    HIGH = "H"


class PrivilegesRequired(StrEnum):
    """Privileges Required (PR) metric."""
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class UserInteraction(StrEnum):
    """User Interaction (UI) metric."""
    NONE = "N"
    REQUIRED = "R"


class Scope(StrEnum):
    """Scope (S) metric."""
    UNCHANGED = "U"
    CHANGED = "C"


class Impact(StrEnum):
    """Impact metrics (C/I/A) - Confidentiality, Integrity, Availability."""
    HIGH = "H"
    LOW = "L"
    NONE = "N"


@dataclass
class CVSSv31Metrics:
    """CVSS v3.1 metrics for vulnerability scoring."""
    
    attack_vector: str  # N, A, L, P
    attack_complexity: str  # L, H
    privileges_required: str  # N, L, H
    user_interaction: str  # N, R
    scope: str  # U, C
    confidentiality: str  # H, L, N
    integrity: str  # H, L, N
    availability: str  # H, L, N
    
    def to_vector_string(self) -> str:
        """Convert to CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H format."""
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/"
            f"PR:{self.privileges_required}/UI:{self.user_interaction}/"
            f"S:{self.scope}/C:{self.confidentiality}/I:{self.integrity}/A:{self.availability}"
        )


class CVSSv31Scorer:
    """Calculate CVSS v3.1 scores and severity ratings."""
    
    # Base score metrics lookup tables
    AV_SCORES = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    AC_SCORES = {"L": 0.77, "H": 0.44}
    PR_SCORES_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_SCORES_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
    UI_SCORES = {"N": 0.85, "R": 0.62}
    IMPACT_SCORES = {"H": 0.56, "L": 0.22, "N": 0.0}
    
    @staticmethod
    def calculate_base_score(metrics: CVSSv31Metrics) -> float:
        """Calculate the base CVSS v3.1 score (0.0-10.0)."""
        
        # Calculate impact score
        scope_coeff = 7.52 if metrics.scope == "U" else 9.6
        c_score = CVSSv31Scorer.IMPACT_SCORES[metrics.confidentiality]
        i_score = CVSSv31Scorer.IMPACT_SCORES[metrics.integrity]
        a_score = CVSSv31Scorer.IMPACT_SCORES[metrics.availability]
        impact = 1 - ((1 - c_score) * (1 - i_score) * (1 - a_score))
        
        # Calculate exploitability score
        av_score = CVSSv31Scorer.AV_SCORES[metrics.attack_vector]
        ac_score = CVSSv31Scorer.AC_SCORES[metrics.attack_complexity]
        ui_score = CVSSv31Scorer.UI_SCORES[metrics.user_interaction]
        pr_scores = (
            CVSSv31Scorer.PR_SCORES_UNCHANGED
            if metrics.scope == "U"
            else CVSSv31Scorer.PR_SCORES_CHANGED
        )
        pr_score = pr_scores[metrics.privileges_required]
        exploitability = 8.22 * av_score * ac_score * pr_score * ui_score
        
        # Calculate base score
        if metrics.scope == "U":
            base_score = min(exploitability + impact, 10.0)
        else:
            base_score = min(1.08 * (exploitability + impact), 10.0)
        
        return round(base_score, 1)
    
    @staticmethod
    def score_to_severity(score: float) -> str:
        """Convert CVSS score to severity rating."""
        if score == 0.0:
            return "NONE"
        elif score < 4.0:
            return "LOW"
        elif score < 7.0:
            return "MEDIUM"
        elif score < 9.0:
            return "HIGH"
        else:
            return "CRITICAL"
    
    @staticmethod
    def infer_metrics_from_category(category: str) -> CVSSv31Metrics:
        """Infer CVSS metrics based on vulnerability category."""
        
        category_lower = category.lower()
        
        # Default base case
        metrics = CVSSv31Metrics(
            attack_vector="N",
            attack_complexity="L",
            privileges_required="N",
            user_interaction="N",
            scope="U",
            confidentiality="H",
            integrity="H",
            availability="H"
        )
        
        # Adjust based on category
        if "xss" in category_lower:
            metrics.scope = "C"
            metrics.user_interaction = "R"
            metrics.privileges_required = "N"
            metrics.availability = "N"
        elif "sqli" in category_lower or "injection" in category_lower:
            metrics.integrity = "H"
            metrics.confidentiality = "H"
            metrics.availability = "H"
        elif "idor" in category_lower:
            metrics.privileges_required = "N"
            metrics.user_interaction = "N"
            metrics.attack_complexity = "L"
            metrics.availability = "N"
        elif "ssrf" in category_lower:
            metrics.scope = "C"
            metrics.attack_vector = "N"
            metrics.availability = "H"
        elif "auth" in category_lower or "broken" in category_lower:
            metrics.privileges_required = "N"
            metrics.user_interaction = "N"
            metrics.confidentiality = "H"
        elif "crypto" in category_lower or "weak" in category_lower:
            metrics.attack_complexity = "H"
            metrics.attack_vector = "N"
        elif "race" in category_lower or "timing" in category_lower:
            metrics.attack_complexity = "H"
            metrics.privileges_required = "L"
            metrics.user_interaction = "N"
        
        return metrics


def calculate_cvss_score(category: str) -> tuple[float, str]:
    """
    Calculate CVSS v3.1 score for a vulnerability category.
    
    Returns: (score, severity) tuple
    """
    metrics = CVSSv31Scorer.infer_metrics_from_category(category)
    score = CVSSv31Scorer.calculate_base_score(metrics)
    severity = CVSSv31Scorer.score_to_severity(score)
    return score, severity
