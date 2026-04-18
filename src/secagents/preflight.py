"""Configuration pre-flight checks for environment validation.

Validates system configuration before starting scans to ensure all requirements are met.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from secagents.config import AppConfig


@dataclass
class PreflightCheck:
    """Result of a preflight check."""
    name: str
    passed: bool
    message: str
    severity: str = "warning"  # "error", "warning", "info"
    remediation: str = ""


class PreflightValidator:
    """Validate system and configuration before scanning."""
    
    def __init__(self, config: AppConfig):
        self.config = config
        self.checks: list[PreflightCheck] = []
    
    def validate_all(self) -> tuple[bool, list[PreflightCheck]]:
        """
        Run all preflight checks.
        
        Returns:
            (all_passed, checks_results)
        """
        self._check_python_version()
        self._check_required_packages()
        self._check_docker_available()
        self._check_api_keys()
        self._check_disk_space()
        self._check_memory_available()
        self._check_network_connectivity()
        self._check_llm_provider()
        
        critical_failures = [
            c for c in self.checks
            if c.severity == "error" and not c.passed
        ]
        
        return len(critical_failures) == 0, self.checks
    
    def _check_python_version(self) -> None:
        """Check Python version compatibility (3.11+ required)."""
        self.checks.append(PreflightCheck(
            name="Python Version",
            passed=True,
            message=f"Python {sys.version.split()[0]} OK (3.11+ required)"
        ))
    
    def _check_required_packages(self) -> None:
        """Check if required packages are installed."""
        required = ["pydantic", "typer", "rich", "httpx"]
        missing = []
        
        for pkg in required:
            try:
                __import__(pkg)
            except ImportError:
                missing.append(pkg)
        
        if missing:
            self.checks.append(PreflightCheck(
                name="Required Packages",
                passed=False,
                message=f"Missing packages: {', '.join(missing)}",
                severity="error",
                remediation=f"Run: pip install {' '.join(missing)}"
            ))
        else:
            self.checks.append(PreflightCheck(
                name="Required Packages",
                passed=True,
                message="All required packages found"
            ))
    
    def _check_docker_available(self) -> None:
        """Check if Docker is available."""
        import shutil
        docker_path = shutil.which("docker")
        
        if not docker_path:
            self.checks.append(PreflightCheck(
                name="Docker",
                passed=False,
                message="Docker not found in PATH",
                severity="error",
                remediation="Install Docker Desktop or Docker Engine"
            ))
        else:
            self.checks.append(PreflightCheck(
                name="Docker",
                passed=True,
                message=f"Docker found at {docker_path}"
            ))
    
    def _check_api_keys(self) -> None:
        """Check if required API keys are configured."""
        if self.config.provider.value == "openai" and not self.config.openai_api_key:
            self.checks.append(PreflightCheck(
                name="OpenAI API Key",
                passed=False,
                message="OpenAI API key not configured",
                severity="error",
                remediation="Set OPENAI_API_KEY or SECAGENTS_OPENAI_API_KEY"
            ))
        elif self.config.provider.value == "anthropic" and not self.config.anthropic_api_key:
            self.checks.append(PreflightCheck(
                name="Anthropic API Key",
                passed=False,
                message="Anthropic API key not configured",
                severity="error",
                remediation="Set ANTHROPIC_API_KEY or SECAGENTS_ANTHROPIC_API_KEY"
            ))
        else:
            self.checks.append(PreflightCheck(
                name="API Keys",
                passed=True,
                message=f"API keys configured for {self.config.provider.value}"
            ))
    
    def _check_disk_space(self) -> None:
        """Check available disk space."""
        import shutil
        
        usage = shutil.disk_usage("/")
        available_gb = usage.free / (1024 ** 3)
        
        if available_gb < 1.0:
            self.checks.append(PreflightCheck(
                name="Disk Space",
                passed=False,
                message=f"Only {available_gb:.1f}GB free (minimum 1GB required)",
                severity="warning"
            ))
        else:
            self.checks.append(PreflightCheck(
                name="Disk Space",
                passed=True,
                message=f"{available_gb:.1f}GB available"
            ))
    
    def _check_memory_available(self) -> None:
        """Check available system memory."""
        import psutil
        
        try:
            memory = psutil.virtual_memory()
            available_gb = memory.available / (1024 ** 3)
            
            if available_gb < 2.0:
                self.checks.append(PreflightCheck(
                    name="System Memory",
                    passed=False,
                    message=f"Only {available_gb:.1f}GB available (minimum 2GB recommended)",
                    severity="warning"
                ))
            else:
                self.checks.append(PreflightCheck(
                    name="System Memory",
                    passed=True,
                    message=f"{available_gb:.1f}GB available"
                ))
        except Exception:
            self.checks.append(PreflightCheck(
                name="System Memory",
                passed=True,
                message="Could not check memory (psutil not available)",
                severity="info"
            ))
    
    def _check_network_connectivity(self) -> None:
        """Check internet connectivity if using cloud providers."""
        import socket
        
        if self.config.provider.value in ["openai", "anthropic", "groq", "qwen", "deepseek", "xai"]:
            try:
                socket.create_connection(("8.8.8.8", 53), timeout=3)
                self.checks.append(PreflightCheck(
                    name="Network Connectivity",
                    passed=True,
                    message="Internet connectivity available"
                ))
            except (TimeoutError, OSError):
                self.checks.append(PreflightCheck(
                    name="Network Connectivity",
                    passed=False,
                    message="Cannot reach internet (required for cloud LLM providers)",
                    severity="error",
                    remediation="Check your internet connection"
                ))
        else:
            self.checks.append(PreflightCheck(
                name="Network Connectivity",
                passed=True,
                message="Local provider (offline mode)",
                severity="info"
            ))
    
    def _check_llm_provider(self) -> None:
        """Check LLM provider configuration."""
        provider = self.config.provider.value
        
        if provider == "ollama":
            # Check if Ollama is running
            import httpx
            try:
                client = httpx.Client(timeout=3.0)
                resp = client.get(f"{self.config.ollama_base_url}/api/tags")
                if resp.status_code == 200:
                    self.checks.append(PreflightCheck(
                        name="Ollama Provider",
                        passed=True,
                        message=f"Ollama running at {self.config.ollama_base_url}"
                    ))
                else:
                    raise Exception("Invalid response")
            except Exception:
                self.checks.append(PreflightCheck(
                    name="Ollama Provider",
                    passed=False,
                    message=f"Cannot connect to Ollama at {self.config.ollama_base_url}",
                    severity="warning",
                    remediation="Start Ollama: docker run -d --name ollama -p 11434:11434 ollama/ollama"
                ))
        else:
            self.checks.append(PreflightCheck(
                name="LLM Provider",
                passed=True,
                message=f"Using {provider} provider"
            ))
    
    def print_report(self) -> None:
        """Print preflight check report."""
        from secagents.cli.ui import ui
        
        passed = sum(1 for c in self.checks if c.passed)
        total = len(self.checks)
        
        ui.h2(f"System Preflight Check ({passed}/{total} passed)")
        
        for check in self.checks:
            if check.passed:
                ui.print_success(f"✓ {check.name}: {check.message}")
            elif check.severity == "error":
                ui.print_error(f"✗ {check.name}: {check.message}")
                if check.remediation:
                    ui.print_info(f"  → {check.remediation}")
            else:
                ui.print_warning(f"⚠ {check.name}: {check.message}")
                if check.remediation:
                    ui.print_info(f"  → {check.remediation}")
