from __future__ import annotations

from secagents.knowledge.graph import build_knowledge_graph


def test_knowledge_graph_without_infra() -> None:
    g = build_knowledge_graph(
        finding_titles=["Test finding"],
        priority_targets=["src/"],
        infra_specialist_ran=False,
    )
    d = g.to_dict()
    assert d["parallel_infra_specialist"] is False
    ids = {n["id"] for n in d["nodes"]}
    assert "code_analyst" in ids
    assert "infra_config" not in ids


def test_knowledge_graph_with_infra() -> None:
    g = build_knowledge_graph(
        finding_titles=[],
        priority_targets=[],
        infra_specialist_ran=True,
    )
    d = g.to_dict()
    assert d["parallel_infra_specialist"] is True
    ids = {n["id"] for n in d["nodes"]}
    assert "infra_config" in ids
    mm = g.mermaid_flowchart()
    assert "Infra" in mm or "infra" in mm.lower()
