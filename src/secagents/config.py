from __future__ import annotations

import os
from enum import StrEnum

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class LLMProvider(StrEnum):
    openai = "openai"
    anthropic = "anthropic"
    ollama = "ollama"


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class AppConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SECAGENTS_",
        env_file=".env",
        extra="ignore",
    )

    provider: LLMProvider = Field(default=LLMProvider.ollama)
    model: str = Field(default="llama3.2")
    openai_api_key: str | None = Field(default=None)
    anthropic_api_key: str | None = Field(default=None)
    ollama_base_url: str = Field(default="http://127.0.0.1:11434")

    temperature: float = Field(default=0.15, ge=0.0, le=2.0)
    top_p: float = Field(default=0.9, ge=0.0, le=1.0)
    max_tokens: int = Field(default=4096, ge=256, le=128000)

    docker_image_sandbox: str = Field(default="secagents-sandbox:latest")
    ollama_container_name: str = Field(default="secagents-ollama")
    ollama_docker_image: str = Field(default="ollama/ollama:latest")
    ollama_host_port: int = Field(default=11434)

    max_agent_turns: int = Field(default=24, ge=1, le=200)
    max_file_bytes: int = Field(default=120_000)
    max_files_in_context: int = Field(default=80)

    # Multi-agent team (Recon → Exploit → Validator → Remediator)
    use_agent_team: bool = Field(default=True)
    recon_turns: int = Field(default=3, ge=0, le=80)
    validation_turns: int = Field(default=5, ge=0, le=80)
    run_remediation_pass: bool = Field(default=True)

    # Parallel LLM specialists at scan open: 2 = code + OSINT; 3 = +Intel; 4 = +IDOR/OAuth; 5 = +Race; 6 = +LLM
    parallel_specialists: int = Field(default=2, ge=1, le=10)
    
    # New specialist flags
    disable_idor: bool = Field(default=False)
    disable_oauth: bool = Field(default=False)
    disable_race: bool = Field(default=False)
    disable_intel: bool = Field(default=False)
    disable_llm_agent: bool = Field(default=False)
    force_llm_agent: bool = Field(default=False)
    skip_intel: bool = Field(default=False)
    race_concurrency: int = Field(default=10, ge=1, le=100)

    sandbox_shm_size: str = Field(default="1g")
    sandbox_command_timeout_sec: int = Field(default=300, ge=30, le=3600)

    @model_validator(mode="after")
    def _fill_standard_api_env(self) -> AppConfig:
        upd: dict = {}
        if not self.openai_api_key and os.getenv("OPENAI_API_KEY"):
            upd["openai_api_key"] = os.getenv("OPENAI_API_KEY")
        if not self.anthropic_api_key and os.getenv("ANTHROPIC_API_KEY"):
            upd["anthropic_api_key"] = os.getenv("ANTHROPIC_API_KEY")
        if upd:
            return self.model_copy(update=upd)
        return self


def severity_rank(s: Severity) -> int:
    order: dict[Severity, int] = {
        Severity.info: 0,
        Severity.low: 1,
        Severity.medium: 2,
        Severity.high: 3,
        Severity.critical: 4,
    }
    return order[s]


def should_fail_ci(fail_on: Severity, finding_severity: Severity) -> bool:
    return severity_rank(finding_severity) >= severity_rank(fail_on)
