from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class GraphNode:
    id: str
    kind: str  # agent | finding | asset | technique | artifact
    label: str
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    source: str
    target: str
    relation: str


@dataclass
class KnowledgeGraph:
    """Structured findings and attack documentation for cross-agent coordination."""

    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    ran_specialists: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "nodes": [asdict(n) for n in self.nodes],
            "edges": [asdict(e) for e in self.edges],
        }
        d["ran_specialists"] = self.ran_specialists
        # backwards-compat key expected by older tests
        d["parallel_infra_specialist"] = "infra_config" in self.ran_specialists
        return d

    def mermaid_flowchart(self) -> str:
        n_findings = sum(1 for x in self.nodes if x.kind == "finding")
        n_assets = sum(1 for x in self.nodes if x.kind == "asset")
        lines = [
            "flowchart LR",
            "  subgraph P[\"Parallel specialists\"]",
            "    CA[Code Analyst]",
            "    OS[OSINT Surface]",
        ]
        
        name_map = {
            "infra_config": "Infra / Config",
            "intel": "Intel Agent",
            "idor": "IDOR Agent",
            "oauth": "OAuth Agent",
            "race": "Race Cond Agent",
            "llm_feature": "LLM Feature Agent"
        }
        
        for sp in self.ran_specialists:
            if sp in name_map:
                lines.append(f"    {sp.upper()}[{name_map[sp]}]")

        lines.extend(
            [
                "  end",
                "  P --> R[Recon]",
                "  R --> E[Exploit PoC]",
                "  E --> V[Validator]",
                "  V --> M[Remediator]",
                f"  KB[\"Knowledge: {n_findings} findings / {n_assets} assets\"]",
                "  E --> KB",
                "  V --> KB",
            ]
        )
        return "\n".join(lines)


def build_knowledge_graph(
    *,
    finding_titles: list[str],
    priority_targets: list[str],
    ran_specialists: list[str] | None = None,
    # legacy kwarg — kept for backwards compatibility with existing tests
    infra_specialist_ran: bool | None = None,
) -> KnowledgeGraph:
    ran_specialists = list(ran_specialists or [])
    # honour the legacy flag: inject infra_config if not already present
    if infra_specialist_ran and "infra_config" not in ran_specialists:
        ran_specialists.insert(0, "infra_config")
    elif infra_specialist_ran is False and "infra_config" in ran_specialists:
        ran_specialists = [s for s in ran_specialists if s != "infra_config"]
    g = KnowledgeGraph(ran_specialists=ran_specialists)
    agent_names = ["code_analyst", "osint_surface"]
    
    agent_names.extend(ran_specialists)
    
    agent_names.extend(["recon", "exploit", "validator", "remediator"])
    for name in agent_names:
        g.nodes.append(GraphNode(id=name, kind="agent", label=name, meta={}))
    for i, p in enumerate(priority_targets[:40]):
        nid = f"asset_{i}"
        g.nodes.append(GraphNode(id=nid, kind="asset", label=p[:120], meta={"path": p}))
        g.edges.append(GraphEdge(source="recon", target=nid, relation="prioritizes"))
    for i, title in enumerate(finding_titles[:60]):
        fid = f"finding_{i}"
        g.nodes.append(GraphNode(id=fid, kind="finding", label=title[:120], meta={"title": title}))
        g.edges.append(GraphEdge(source="exploit", target=fid, relation="discovered"))
        g.edges.append(GraphEdge(source="validator", target=fid, relation="validates"))
    g.nodes.append(
        GraphNode(
            id="knowledge_base",
            kind="artifact",
            label="Structured session knowledge",
            meta={"type": "documentation"},
        )
    )
    g.edges.append(GraphEdge(source="exploit", target="knowledge_base", relation="documents"))
    g.edges.append(GraphEdge(source="code_analyst", target="knowledge_base", relation="feeds"))
    g.edges.append(GraphEdge(source="osint_surface", target="knowledge_base", relation="feeds"))
    
    for sp in ran_specialists:
        g.edges.append(GraphEdge(source=sp, target="knowledge_base", relation="feeds"))
        
    return g
