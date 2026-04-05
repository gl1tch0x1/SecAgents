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
    parallel_infra: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = {
            "nodes": [asdict(n) for n in self.nodes],
            "edges": [asdict(e) for e in self.edges],
        }
        d["parallel_infra_specialist"] = self.parallel_infra
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
        if self.parallel_infra:
            lines.append("    IF[Infra / Config]")
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
    infra_specialist_ran: bool = False,
) -> KnowledgeGraph:
    g = KnowledgeGraph(parallel_infra=infra_specialist_ran)
    agent_names = ["code_analyst", "osint_surface"]
    if infra_specialist_ran:
        agent_names.append("infra_config")
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
    if infra_specialist_ran:
        g.edges.append(GraphEdge(source="infra_config", target="knowledge_base", relation="feeds"))
    return g
