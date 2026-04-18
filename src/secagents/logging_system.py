"""Enterprise-grade logging and audit trail system for SecAgents.

Provides structured logging, audit trails, and observability for security scans.
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from secagents.cli.ui import ui


class LogLevel(StrEnum):
    """Standard log levels with additional security levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    AUDIT = "AUDIT"  # Security audit trail
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class AuditCategory(StrEnum):
    """Categories for audit logging."""
    SCAN_START = "scan_start"
    SCAN_COMPLETE = "scan_complete"
    FINDING_CREATED = "finding_created"
    FINDING_UPDATED = "finding_updated"
    VULNERABILITY_DETECTED = "vulnerability_detected"
    REMEDIATION_APPLIED = "remediation_applied"
    CONFIGURATION_CHANGED = "configuration_changed"
    AUTH_ATTEMPT = "auth_attempt"
    POLICY_VIOLATION = "policy_violation"
    ERROR_OCCURRED = "error_occurred"


@dataclass
class AuditEvent:
    """Structured audit event for compliance and forensics."""
    timestamp: str
    category: AuditCategory
    message: str
    severity: str
    user_context: dict[str, Any] | None = None
    finding_id: str | None = None
    file_path: str | None = None
    metadata: dict[str, Any] | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            k: v for k, v in asdict(self).items()
            if v is not None
        }


class SecAgentsLogger:
    """Enterprise logging system with audit trails and structured logging."""
    
    _instance: SecAgentsLogger | None = None
    
    def __init__(self, log_dir: Path | None = None, level: str = "INFO"):
        self.log_dir = log_dir or Path(".secagents-logs")
        self.log_dir.mkdir(exist_ok=True, parents=True)
        self.level = level
        self.audit_events: list[AuditEvent] = []
        self._setup_handlers()
    
    def _setup_handlers(self) -> None:
        """Setup logging handlers for file and console output."""
        self.logger = logging.getLogger("secagents")
        self.logger.setLevel(self.level.upper())
        
        # File handler for general logs
        general_log = self.log_dir / f"secagents-{datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.FileHandler(general_log)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        self.logger.addHandler(file_handler)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
        self.logger.addHandler(console_handler)
        
        # Audit log (JSON)
        self.audit_log_path = self.log_dir / "audit.jsonl"
    
    def log_audit(self, event: AuditEvent) -> None:
        """Log an audit event to the audit trail."""
        self.audit_events.append(event)
        with open(self.audit_log_path, "a") as f:
            f.write(json.dumps(event.to_dict()) + "\n")
        self.logger.info(f"[AUDIT] {event.category}: {event.message}")
    
    def log_scan_start(self, target: str, metadata: dict | None = None) -> None:
        """Log the start of a security scan."""
        event = AuditEvent(
            timestamp=datetime.now().isoformat(),
            category=AuditCategory.SCAN_START,
            message=f"Security scan initiated on target: {target}",
            severity="info",
            metadata=metadata or {}
        )
        self.log_audit(event)
    
    def log_scan_complete(self, target: str, finding_count: int, duration_sec: float) -> None:
        """Log the completion of a security scan."""
        event = AuditEvent(
            timestamp=datetime.now().isoformat(),
            category=AuditCategory.SCAN_COMPLETE,
            message=f"Security scan completed on {target}",
            severity="info",
            metadata={
                "finding_count": finding_count,
                "duration_seconds": duration_sec,
                "findings_per_second": finding_count / max(duration_sec, 0.1)
            }
        )
        self.log_audit(event)
    
    def log_vulnerability_detected(self, title: str, severity: str, category: str) -> None:
        """Log when a vulnerability is detected."""
        event = AuditEvent(
            timestamp=datetime.now().isoformat(),
            category=AuditCategory.VULNERABILITY_DETECTED,
            message=f"Vulnerability detected: {title}",
            severity=severity,
            metadata={
                "vuln_title": title,
                "vuln_category": category
            }
        )
        self.log_audit(event)
    
    def log_error(self, message: str, error: Exception | None = None) -> None:
        """Log an error with optional exception context."""
        msg = message
        if error:
            msg += f": {str(error)}"
        event = AuditEvent(
            timestamp=datetime.now().isoformat(),
            category=AuditCategory.ERROR_OCCURRED,
            message=msg,
            severity="error",
            metadata={"error_type": type(error).__name__} if error else None
        )
        self.log_audit(event)
        self.logger.error(msg)
    
    @classmethod
    def get_instance(cls) -> SecAgentsLogger:
        """Get or create the singleton logger instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def export_audit_report(self, output_path: Path) -> None:
        """Export audit events to a report file."""
        with open(output_path, "w") as f:
            f.write("# SecAgents Audit Trail Report\n\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write(f"Total Events: {len(self.audit_events)}\n\n")
            
            for event in self.audit_events:
                f.write(f"## {event.timestamp} - {event.category}\n")
                f.write(f"**Severity:** {event.severity}\n")
                f.write(f"**Message:** {event.message}\n")
                if event.metadata:
                    f.write(f"**Details:** {json.dumps(event.metadata, indent=2)}\n")
                f.write("\n")


def get_logger() -> SecAgentsLogger:
    """Convenience function to get the global logger instance."""
    return SecAgentsLogger.get_instance()
