from __future__ import annotations

from unittest.mock import patch

import pytest

from secagents.config import AppConfig
from secagents.reporting.report import (
    ScanFinding,
    ScanResult,
    _bugcrowd_vrt_map,
    _render_bugcrowd_report,
)

# ---------------------------------------------------------------------------
# VRT category mapper tests
# ---------------------------------------------------------------------------

def test_bugcrowd_vrt_mapper_idor():
    assert _bugcrowd_vrt_map("idor testing") == "Insecure Direct Object Reference (IDOR)"


def test_bugcrowd_vrt_mapper_oauth():
    assert _bugcrowd_vrt_map("Oauth") == "OAuth / OpenID Related Issues"


def test_bugcrowd_vrt_mapper_xss():
    assert _bugcrowd_vrt_map("Stored XSS") == "Cross-Site Scripting (XSS)"


def test_bugcrowd_vrt_mapper_sqli():
    assert _bugcrowd_vrt_map("SQL injection") == "SQL Injection"


def test_bugcrowd_vrt_mapper_unknown():
    assert _bugcrowd_vrt_map("unknown category") == "Uncategorized"


# ---------------------------------------------------------------------------
# Report formatting tests
# ---------------------------------------------------------------------------

def test_report_formatting_bugcrowd():
    sf = ScanFinding(
        title="IDOR on Profile",
        severity="high",
        category="idor",
        evidence="user_id changed to 5",
        validated=True,
        poc_command="curl -X POST /profile",
        poc_output_excerpt="data",
        remediation_steps=["Fix it"],
        suggested_patch="",
    )
    res = ScanResult(findings=[sf])
    bc_report = _render_bugcrowd_report("example.com", res, "mock", "mockmodel")
    assert "## Bug Report" in bc_report
    assert "Insecure Direct Object Reference (IDOR)" in bc_report
    assert "7.5" in bc_report


# ---------------------------------------------------------------------------
# AppConfig fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_cfg():
    return AppConfig(
        provider="openai",
        openai_api_key="sk-test",
        parallel_specialists=6,
        disable_idor=False,
        disable_oauth=False,
        disable_race=False,
        disable_intel=False,
        disable_llm_agent=False,
        force_llm_agent=True,
        recon_turns=0,
        validation_turns=0,
        run_remediation_pass=False,
        max_agent_turns=2,
        use_agent_team=True,
    )


# ---------------------------------------------------------------------------
# Orchestrator integration test (fully mocked — no Docker / network / LLM)
# ---------------------------------------------------------------------------

def test_intel_agent_cve_lookup(mock_cfg, tmp_path):
    llm_response = (
        '{"findings": [{"title": "Detected API", "severity": "info", "category": "intel"}],'
        ' "intel_markdown": "## Detected Stack"}'
    )

    with patch("secagents.agents.orchestrator.chat_completion", return_value=llm_response), \
         patch("secagents.agents.orchestrator.build_sandbox_image_if_needed"), \
         patch("secagents.agents.orchestrator.run_in_sandbox", return_value=("", "", 0)):

        from secagents.agents.orchestrator import run_team_scan
        result = run_team_scan(tmp_path, mock_cfg, allow_network=True)

        assert "intel" in result.ran_specialists
        assert "idor" in result.ran_specialists
        assert "llm_feature" in result.ran_specialists
        assert "## Detected Stack" in result.intel_markdown
