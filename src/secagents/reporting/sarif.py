"""SARIF (Static Analysis Results Interchange Format) export for industry compatibility.

Exports vulnerability findings in SARIF format for integration with modern security tools.
Reference: https://sarifweb.azurewebsites.net/
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from secagents.agents.orchestrator import ScanFinding, ScanResult


@dataclass
class SARIFRun:
    """SARIF run results container."""
    
    tool_name: str
    tool_version: str
    target_uri: str
    results: list[dict[str, Any]]
    
    def to_dict(self) -> dict:
        """Convert to SARIF run dictionary."""
        return {
            "tool": {
                "driver": {
                    "name": self.tool_name,
                    "version": self.tool_version,
                    "informationUri": "https://github.com/gl1tch0x1/secagents",
                    "rules": self._build_rules()
                }
            },
            "results": self.results,
            "properties": {
                "scanStarted": datetime.now().isoformat(),
                "targetUri": self.target_uri
            }
        }
    
    def _build_rules(self) -> list[dict]:
        """Build SARIF rules from findings."""
        rules = []
        seen_ids = set()
        
        for result in self.results:
            rule_id = result.get("ruleId", "unknown")
            if rule_id not in seen_ids:
                rules.append({
                    "id": rule_id,
                    "name": result.get("message", {}).get("text", ""),
                    "shortDescription": {
                        "text": result.get("message", {}).get("text", "")
                    },
                    "helpUri": "https://owasp.org/Top10",
                    "properties": {
                        "category": result.get("properties", {}).get("category", ""),
                        "severity": result.get("properties", {}).get("severity", "")
                    }
                })
                seen_ids.add(rule_id)
        
        return rules


class SARIFExporter:
    """Export scan results to SARIF format."""
    
    @staticmethod
    def finding_to_sarif_result(finding: ScanFinding, location_uri: str = "") -> dict:
        """Convert a ScanFinding to SARIF result format."""
        
        # Map severity to SARIF level
        level_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "none"
        }
        level = level_map.get(finding.severity.lower(), "warning")
        
        # Build result object
        result = {
            "ruleId": f"{finding.category.lower().replace(' ', '_')}_{hash(finding.title) % 10000}",
            "level": level,
            "message": {
                "text": finding.title,
                "markdown": f"**Title:** {finding.title}\n\n**Evidence:** {finding.evidence}\n\n**Category:** {finding.category}"
            },
            "properties": {
                "category": finding.category,
                "severity": finding.severity,
                "validated": finding.validated,
                "confidence": "high" if finding.validated else "medium"
            }
        }
        
        # Add location if provided
        if location_uri:
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": location_uri
                    }
                }
            }]
        
        # Add PoC if available
        if finding.poc_command:
            result["relatedLocations"] = [{
                "message": {
                    "text": "Proof of Concept",
                    "markdown": f"```bash\n{finding.poc_command}\n```"
                }
            }]
        
        # Add remediation
        if finding.remediation_steps or finding.suggested_patch:
            fix_text = "\n".join(finding.remediation_steps) if finding.remediation_steps else finding.suggested_patch
            result["fixes"] = [{
                "description": {
                    "text": fix_text
                }
            }]
        
        return result
    
    @staticmethod
    def export_to_sarif(result: ScanResult, target_label: str, version: str = "1.0") -> dict:
        """Convert ScanResult to complete SARIF log."""
        
        sarif_results = [
            SARIFExporter.finding_to_sarif_result(finding, target_label)
            for finding in result.findings
        ]
        
        run = SARIFRun(
            tool_name="SecAgents",
            tool_version=version,
            target_uri=target_label,
            results=sarif_results
        )
        
        return {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [run.to_dict()]
        }
    
    @staticmethod
    def write_sarif_file(result: ScanResult, output_path: str, target_label: str) -> str:
        """Write SARIF output to file and return path."""
        from pathlib import Path
        
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        sarif_data = SARIFExporter.export_to_sarif(result, target_label)
        
        with open(path, "w") as f:
            json.dump(sarif_data, f, indent=2)
        
        return str(path)


# Import dataclass here to avoid circular imports
from dataclasses import dataclass
