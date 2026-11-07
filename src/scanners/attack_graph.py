#!/usr/bin/env python3
"""
attack_graph.py
===============
Proprietary Cross-Resource Attack Path DAG & Blast Radius Engine.

Patented / Novel Capabilities:
1. Cross-Resource Directed Acyclic Graph (DAG):
   Models decoupled Kubernetes entities (Ingresses, Services, Pods, ServiceAccounts,
   Roles, RoleBindings, Secrets, Host Kernels) as a connected graph of lateral privilege flow.
2. Multi-Hop Kill-Chain Traversal:
   Traces end-to-end exploit trajectories from external entrypoints (NodePort / Ingress)
   to high-value crown jewels (Cluster-Admin, Secret data, Node root access).
3. Mathematical Blast Radius Index (B in [0.0, 100.0]):
   Computes a closed-form topology score combining reachability, credential access,
   and breakout severity.
4. Native Mermaid Diagram Synthesis:
   Outputs visual graph representations for SecOps threat modeling.
"""

from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class AttackNode:
    id: str
    kind: str
    name: str
    namespace: str
    risk_score: float = 0.0
    is_external_entrypoint: bool = False
    is_crown_jewel: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


@dataclass
class AttackEdge:
    source_id: str
    target_id: str
    relation: str  # EXPOSES, ASSUMES_IDENTITY, BINDS_ROLE, CAN_READ_DATA, HOST_ESCAPE, LATERAL_TRAVERSAL
    mitre_technique_id: str
    description: str
    weight: float = 1.0

    def to_dict(self):
        return asdict(self)


@dataclass
class KillChainPath:
    path_id: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM
    nodes: List[str]
    edges: List[str]
    entrypoint: str
    crown_jewel: str
    hop_count: int
    blast_radius: float
    mitre_tactics: List[str]
    remediation_bottleneck: str

    def to_dict(self):
        return asdict(self)


class AttackGraphEngine:
    """
    Constructs and analyzes cross-manifest attack path topologies.
    """

    def __init__(self):
        self.nodes: Dict[str, AttackNode] = {}
        self.edges: List[AttackEdge] = []
        self.adjacency: Dict[str, List[AttackEdge]] = {}

    def add_node(self, node: AttackNode):
        self.nodes[node.id] = node
        if node.id not in self.adjacency:
            self.adjacency[node.id] = []

    def add_edge(self, edge: AttackEdge):
        self.edges.append(edge)
        self.adjacency.setdefault(edge.source_id, []).append(edge)

    def build_from_documents(self, documents: List[Dict[str, Any]]) -> "AttackGraphEngine":
        """
        Parses a list of Kubernetes manifests across any combination of kinds
        and synthesizes the unified attack path topology.
        """
        # Pass 1: Catalog all resources as nodes
        workloads = []
        services = []
        ingresses = []
        roles = []
        bindings = []
        secrets = []

        for doc in documents:
            if not isinstance(doc, dict):
                continue
            kind = doc.get("kind", "")
            meta = doc.get("metadata", {})
            name = meta.get("name", "unnamed")
            ns = "cluster" if kind in ("ClusterRole", "ClusterRoleBinding") else meta.get("namespace", "default")
            node_id = f"{kind}:{ns}/{name}"

            if kind in ("Pod", "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"):
                workloads.append((doc, node_id, ns, name))
            elif kind == "Service":
                services.append((doc, node_id, ns, name))
            elif kind == "Ingress":
                ingresses.append((doc, node_id, ns, name))
            elif kind in ("Role", "ClusterRole"):
                roles.append((doc, node_id, ns, name, kind == "ClusterRole"))
            elif kind in ("RoleBinding", "ClusterRoleBinding"):
                bindings.append((doc, node_id, ns, name, kind == "ClusterRoleBinding"))
            elif kind == "Secret":
                secrets.append((doc, node_id, ns, name))

        # Register Secrets (Crown Jewels)
        for doc, node_id, ns, name in secrets:
            self.add_node(AttackNode(
                id=node_id,
                kind="Secret",
                name=name,
                namespace=ns,
                risk_score=90.0,
                is_crown_jewel=True,
                metadata={"type": doc.get("type", "Opaque")}
            ))

        # Node Kernel (Ultimate Breakout Target)
        host_kernel_id = "NodeKernel:cluster-nodes"
        self.add_node(AttackNode(
            id=host_kernel_id,
            kind="NodeKernel",
            name="HostLinuxKernel",
            namespace="cluster",
            risk_score=100.0,
            is_crown_jewel=True,
            metadata={"privilege": "RING_0_ROOT"}
        ))

        # Pass 2: Process Workloads & Host Escapes
        for doc, node_id, ns, name in workloads:
            spec = doc.get("spec", {})
            if "template" in spec:
                pod_spec = spec.get("template", {}).get("spec", {})
            else:
                pod_spec = spec

            containers = pod_spec.get("containers", [])
            is_priv = any(c.get("securityContext", {}).get("privileged", False) for c in containers)
            host_pid = pod_spec.get("hostPID", False)
            host_net = pod_spec.get("hostNetwork", False)
            host_ipc = pod_spec.get("hostIPC", False)
            sa_name = pod_spec.get("serviceAccountName") or pod_spec.get("serviceAccount") or "default"

            # Check dangerous capabilities
            has_ptrace_or_admin = False
            for c in containers:
                add_caps = c.get("securityContext", {}).get("capabilities", {}).get("add", [])
                if any(cap in ("SYS_PTRACE", "SYS_ADMIN", "ALL") for cap in add_caps):
                    has_ptrace_or_admin = True

            # Check dangerous hostPath mounts
            has_root_hostpath = False
            for v in pod_spec.get("volumes", []):
                hp = v.get("hostPath", {})
                if hp and hp.get("path") in ("/", "/var/run/docker.sock", "/etc", "/root"):
                    has_root_hostpath = True

            # Register Workload Node
            risk_score = 40.0
            if is_priv or has_root_hostpath:
                risk_score = 95.0
            elif host_pid or host_net or has_ptrace_or_admin:
                risk_score = 75.0

            self.add_node(AttackNode(
                id=node_id,
                kind=doc.get("kind", "Workload"),
                name=name,
                namespace=ns,
                risk_score=risk_score,
                metadata={
                    "privileged": is_priv,
                    "hostPID": host_pid,
                    "hostNetwork": host_net,
                    "serviceAccount": sa_name,
                }
            ))

            # Edge: Workload -> Host Kernel Escape
            if is_priv or has_root_hostpath:
                self.add_edge(AttackEdge(
                    source_id=node_id,
                    target_id=host_kernel_id,
                    relation="HOST_ESCAPE",
                    mitre_technique_id="T1611",
                    description="Privileged container or root hostPath allows direct breakout to host kernel filesystem.",
                    weight=10.0,
                ))
            elif host_pid and has_ptrace_or_admin:
                self.add_edge(AttackEdge(
                    source_id=node_id,
                    target_id=host_kernel_id,
                    relation="HOST_ESCAPE",
                    mitre_technique_id="T1611",
                    description="Shared hostPID combined with SYS_PTRACE allows process injection into host PID 1.",
                    weight=8.5,
                ))

            # Edge: Workload -> ServiceAccount
            sa_node_id = f"ServiceAccount:{ns}/{sa_name}"
            if sa_node_id not in self.nodes:
                self.add_node(AttackNode(
                    id=sa_node_id,
                    kind="ServiceAccount",
                    name=sa_name,
                    namespace=ns,
                    risk_score=30.0,
                    is_crown_jewel=(sa_name == "cluster-admin")
                ))
            self.add_edge(AttackEdge(
                source_id=node_id,
                target_id=sa_node_id,
                relation="ASSUMES_IDENTITY",
                mitre_technique_id="T1078",
                description=f"Workload mounts API token for ServiceAccount '{sa_name}'.",
                weight=3.0,
            ))

        # Pass 3: Process Services & Ingresses (Entrypoints)
        for doc, node_id, ns, name in services:
            spec = doc.get("spec", {})
            svc_type = spec.get("type", "ClusterIP")
            is_entry = svc_type in ("NodePort", "LoadBalancer")
            self.add_node(AttackNode(
                id=node_id,
                kind="Service",
                name=name,
                namespace=ns,
                risk_score=60.0 if is_entry else 20.0,
                is_external_entrypoint=is_entry,
                metadata={"type": svc_type}
            ))
            # Match service selector to workloads
            selector = spec.get("selector", {})
            if selector:
                for w_doc, w_id, w_ns, w_name in workloads:
                    if w_ns == ns:
                        w_labels = w_doc.get("metadata", {}).get("labels", {})
                        if all(w_labels.get(k) == v for k, v in selector.items()):
                            self.add_edge(AttackEdge(
                                source_id=node_id,
                                target_id=w_id,
                                relation="ROUTES_TRAFFIC",
                                mitre_technique_id="T1190",
                                description=f"Service '{name}' ({svc_type}) routes incoming network traffic to workload.",
                                weight=4.0 if is_entry else 1.0,
                            ))

        for doc, node_id, ns, name in ingresses:
            self.add_node(AttackNode(
                id=node_id,
                kind="Ingress",
                name=name,
                namespace=ns,
                risk_score=75.0,
                is_external_entrypoint=True,
                metadata={"rules": len(doc.get("spec", {}).get("rules", []))}
            ))
            # Connect Ingress to backend Services
            for rule in doc.get("spec", {}).get("rules", []):
                for path in rule.get("http", {}).get("paths", []):
                    backend_svc = path.get("backend", {}).get("service", {}).get("name")
                    if backend_svc:
                        svc_id = f"Service:{ns}/{backend_svc}"
                        if svc_id in self.nodes:
                            self.add_edge(AttackEdge(
                                source_id=node_id,
                                target_id=svc_id,
                                relation="EXPOSES",
                                mitre_technique_id="T1190",
                                description=f"Ingress exposes Service '{backend_svc}' to external internet ingress.",
                                weight=5.0,
                            ))

        # Pass 4: Process RBAC Roles & Bindings
        for doc, node_id, ns, name, is_cluster in roles:
            rules = doc.get("rules", [])
            can_read_secrets = False
            has_wildcard = False
            can_exec = False
            for r in rules:
                resources = r.get("resources", [])
                verbs = r.get("verbs", [])
                if "*" in resources or "*" in verbs:
                    has_wildcard = True
                if "secrets" in resources and any(v in ("get", "list", "watch", "*") for v in verbs):
                    can_read_secrets = True
                if "pods/exec" in resources or "exec" in resources:
                    can_exec = True

            role_risk = 20.0
            if has_wildcard or name == "cluster-admin":
                role_risk = 100.0
            elif can_read_secrets or can_exec:
                role_risk = 80.0

            self.add_node(AttackNode(
                id=node_id,
                kind="ClusterRole" if is_cluster else "Role",
                name=name,
                namespace=ns,
                risk_score=role_risk,
                is_crown_jewel=(has_wildcard or name == "cluster-admin"),
                metadata={"can_read_secrets": can_read_secrets, "has_wildcard": has_wildcard}
            ))

            # Edge from Role to Secrets
            if can_read_secrets:
                for s_doc, s_id, s_ns, s_name in secrets:
                    if is_cluster or s_ns == ns:
                        self.add_edge(AttackEdge(
                            source_id=node_id,
                            target_id=s_id,
                            relation="CAN_READ_DATA",
                            mitre_technique_id="T1552.007",
                            description="Role has permission to read Kubernetes Secret credentials.",
                            weight=6.0,
                        ))

        # Pass 5: Connect ServiceAccounts -> Roles via RoleBindings
        for doc, node_id, ns, name, is_cluster in bindings:
            role_ref = doc.get("roleRef", {})
            role_name = role_ref.get("name", "")
            ref_kind = role_ref.get("kind", "Role")
            role_node_id = f"{ref_kind}:{ns if ref_kind == 'Role' else 'cluster'}/{role_name}"

            for subject in doc.get("subjects", []):
                s_kind = subject.get("kind", "")
                s_name = subject.get("name", "")
                s_ns = subject.get("namespace", ns)
                if s_kind == "ServiceAccount":
                    sa_id = f"ServiceAccount:{s_ns}/{s_name}"
                    if sa_id not in self.nodes:
                        self.add_node(AttackNode(
                            id=sa_id, kind="ServiceAccount", name=s_name, namespace=s_ns, risk_score=25.0
                        ))
                    if role_node_id in self.nodes:
                        self.add_edge(AttackEdge(
                            source_id=sa_id,
                            target_id=role_node_id,
                            relation="BINDS_ROLE",
                            mitre_technique_id="T1078.002",
                            description=f"Binding '{name}' grants privileges of '{role_name}' to ServiceAccount '{s_name}'.",
                            weight=7.0 if role_name == "cluster-admin" else 3.5,
                        ))

        return self

    def find_kill_chains(self) -> List[KillChainPath]:
        """
        Executes depth-first multi-hop graph search from all external entrypoints
        to high-value crown jewel nodes (Cluster-Admin, HostKernel, Secrets).
        """
        chains: List[KillChainPath] = []
        entrypoints = [n_id for n_id, n in self.nodes.items() if n.is_external_entrypoint]
        crown_jewels = {n_id for n_id, n in self.nodes.items() if n.is_crown_jewel}

        # If no explicit Ingress/NodePort, treat any non-privileged workload as a starting point
        if not entrypoints:
            entrypoints = [
                n_id for n_id, n in self.nodes.items()
                if n.kind in ("Pod", "Deployment", "StatefulSet", "DaemonSet")
            ]

        path_idx = 1
        for start_id in entrypoints:
            visited_paths: Set[Tuple[str, ...]] = set()

            def dfs(curr_id: str, current_path: List[str], edge_descriptions: List[str]):
                nonlocal path_idx
                if curr_id in crown_jewels and len(current_path) > 1:
                    path_tuple = tuple(current_path)
                    if path_tuple not in visited_paths:
                        visited_paths.add(path_tuple)
                        crown = self.nodes[curr_id]
                        blast = self._compute_path_blast_radius(current_path)
                        severity = "CRITICAL" if blast >= 75.0 else ("HIGH" if blast >= 45.0 else "MEDIUM")
                        
                        # Identify optimal bottleneck remediation
                        bottleneck = current_path[1] if len(current_path) > 2 else current_path[0]
                        
                        chains.append(KillChainPath(
                            path_id=f"KC-{path_idx:03d}",
                            title=f"Attack Vector: {self.nodes[start_id].name} -> {crown.name}",
                            severity=severity,
                            nodes=list(current_path),
                            edges=list(edge_descriptions),
                            entrypoint=start_id,
                            crown_jewel=curr_id,
                            hop_count=len(current_path) - 1,
                            blast_radius=blast,
                            mitre_tactics=["Initial Access", "Privilege Escalation", "Lateral Movement", "Credential Access"],
                            remediation_bottleneck=f"Harden node '{bottleneck}' to sever attack path.",
                        ))
                        path_idx += 1
                    return

                if len(current_path) >= 6:  # Prevent infinite traversal
                    return

                for edge in self.adjacency.get(curr_id, []):
                    next_id = edge.target_id
                    if next_id not in current_path:  # Prevent cycles
                        current_path.append(next_id)
                        edge_descriptions.append(f"{edge.relation} ({edge.mitre_technique_id}): {edge.description}")
                        dfs(next_id, current_path, edge_descriptions)
                        current_path.pop()
                        edge_descriptions.pop()

            dfs(start_id, [start_id], [])

        # Sort: highest blast radius first
        chains.sort(key=lambda c: (-c.blast_radius, c.hop_count))
        return chains

    def _compute_path_blast_radius(self, path: List[str]) -> float:
        """
        Mathematical Blast Radius formula:
        B(P) = Base(CrownJewel) * (1.0 - 0.08 * (hops - 1)) + EdgeCriticalityBonus
        """
        if not path:
            return 0.0
        crown_id = path[-1]
        crown_node = self.nodes.get(crown_id)
        base_score = crown_node.risk_score if crown_node else 50.0

        # Shorter paths to crown jewel have higher immediacy and lower attacker effort
        hops = max(1, len(path) - 1)
        decay = max(0.65, 1.0 - 0.08 * (hops - 1))
        
        # Check if host escape was present in path
        has_escape = any("NodeKernel" in p for p in path)
        escape_bonus = 15.0 if has_escape else 0.0

        return round(min(100.0, (base_score * decay) + escape_bonus), 1)

    def calculate_cluster_blast_radius(self) -> float:
        """
        Aggregates cluster-wide Blast Radius based on crown jewel exposure
        and critical kill-chain density.
        """
        chains = self.find_kill_chains()
        if not chains:
            return 10.0  # Baseline hardened cluster
        max_blast = max(c.blast_radius for c in chains)
        density_penalty = min(20.0, len(chains) * 2.5)
        return round(min(100.0, max_blast * 0.8 + density_penalty), 1)

    def to_mermaid(self, max_chains: int = 3) -> str:
        """Generates a Mermaid graph diagram representing discovered attack paths."""
        lines = ["flowchart TD", "  classDef crown fill:#f96,stroke:#333,stroke-width:2px;", "  classDef entry fill:#9f6,stroke:#333,stroke-width:2px;"]
        seen_nodes: Set[str] = set()
        seen_edges: Set[Tuple[str, str]] = set()

        chains = self.find_kill_chains()[:max_chains]
        for chain in chains:
            for i in range(len(chain.nodes) - 1):
                u = chain.nodes[i]
                v = chain.nodes[i + 1]
                seen_nodes.add(u)
                seen_nodes.add(v)
                if (u, v) not in seen_edges:
                    seen_edges.add((u, v))
                    # Sanitize node names for Mermaid
                    u_clean = u.replace(":", "_").replace("/", "_").replace("-", "_")
                    v_clean = v.replace(":", "_").replace("/", "_").replace("-", "_")
                    u_label = f"{self.nodes[u].kind}: {self.nodes[u].name}"
                    v_label = f"{self.nodes[v].kind}: {self.nodes[v].name}"
                    lines.append(f'  {u_clean}["{u_label}"] --> {v_clean}["{v_label}"]')

        for n_id in seen_nodes:
            n = self.nodes[n_id]
            n_clean = n_id.replace(":", "_").replace("/", "_").replace("-", "_")
            if n.is_crown_jewel:
                lines.append(f"  class {n_clean} crown;")
            elif n.is_external_entrypoint:
                lines.append(f"  class {n_clean} entry;")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        chains = self.find_kill_chains()
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "cluster_blast_radius": self.calculate_cluster_blast_radius(),
            "kill_chains_count": len(chains),
            "kill_chains": [c.to_dict() for c in chains],
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "mermaid_graph": self.to_mermaid(),
        }
