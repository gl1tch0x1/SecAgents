from __future__ import annotations

from secagents.config import AppConfig, LLMProvider


def test_app_config_defaults() -> None:
    c = AppConfig()
    assert c.provider == LLMProvider.ollama
    assert 1 <= c.parallel_specialists <= 8
    assert c.sandbox_command_timeout_sec >= 30
    assert c.use_agent_team is True
