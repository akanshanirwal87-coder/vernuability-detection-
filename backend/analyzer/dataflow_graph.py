"""
Dataflow Graph representation for SecureCode AI.
Builds a directed graph of variable assignments, transformations, and sink calls to trace taint flow.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from .taint_state import DataFlowStep, TaintStatus


@dataclass
class DataFlowNode:
    node_id: str
    label: str
    line: int
    snippet: str
    node_type: str  # "SOURCE", "TRANSFORM", "SINK"
    description: str
    taint_status: TaintStatus = TaintStatus.UNTAINTED


@dataclass
class DataFlowEdge:
    source_id: str
    target_id: str
    label: str = ""


class DataFlowGraph:
    """Directed graph representing dataflow between variables and operations."""

    def __init__(self):
        self.nodes: Dict[str, DataFlowNode] = {}
        self.adjacency: Dict[str, List[str]] = {}
        self.reverse_adj: Dict[str, List[str]] = {}

    def add_node(
        self,
        node_id: str,
        label: str,
        line: int,
        snippet: str,
        node_type: str,
        description: str,
        taint_status: TaintStatus = TaintStatus.UNTAINTED,
    ) -> DataFlowNode:
        node = DataFlowNode(
            node_id=node_id,
            label=label,
            line=line,
            snippet=snippet,
            node_type=node_type,
            description=description,
            taint_status=taint_status,
        )
        self.nodes[node_id] = node
        if node_id not in self.adjacency:
            self.adjacency[node_id] = []
        if node_id not in self.reverse_adj:
            self.reverse_adj[node_id] = []
        return node

    def add_edge(self, source_id: str, target_id: str, label: str = ""):
        if source_id in self.nodes and target_id in self.nodes:
            if target_id not in self.adjacency[source_id]:
                self.adjacency[source_id].append(target_id)
            if source_id not in self.reverse_adj[target_id]:
                self.reverse_adj[target_id].append(source_id)

    def find_path(self, start_id: str, end_id: str) -> Optional[List[DataFlowNode]]:
        """Finds a path from start_id to end_id using Breadth-First Search (BFS)."""
        if start_id not in self.nodes or end_id not in self.nodes:
            return None

        queue: List[List[str]] = [[start_id]]
        visited: Set[str] = {start_id}

        while queue:
            current_path = queue.pop(0)
            current_node = current_path[-1]

            if current_node == end_id:
                return [self.nodes[nid] for nid in current_path]

            for neighbor in self.adjacency.get(current_node, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(current_path + [neighbor])

        return None

    def build_steps_from_path(self, path: List[DataFlowNode]) -> List[DataFlowStep]:
        """Converts an ordered list of DataFlowNodes into frontend DataFlowSteps."""
        steps: List[DataFlowStep] = []
        for idx, node in enumerate(path):
            steps.append(
                DataFlowStep(
                    step=idx + 1,
                    label=node.label,
                    code_snippet=node.snippet,
                    line=node.line,
                    type=node.node_type,
                    description=node.description,
                )
            )
        return steps
