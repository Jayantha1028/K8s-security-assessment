import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

SYSTEM_NAMESPACES = {
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "falco",
}

# (key, kubectl resource, all namespaces?). The cluster-scoped kinds are
# fetched without -A.
RESOURCES = [
    ("roles", "roles", True),
    ("clusterroles", "clusterroles", False),
    ("rolebindings", "rolebindings", True),
    ("clusterrolebindings", "clusterrolebindings", False),
    ("deployments", "deployments", True),
    ("statefulsets", "statefulsets", True),
    ("daemonsets", "daemonsets", True),
    ("jobs", "jobs", True),
    ("cronjobs", "cronjobs", True),
    ("pods", "pods", True),
    ("networkpolicies", "networkpolicies", True),
]


def get_resources(context, resource, all_namespaces=True):
    command = [
        "kubectl",
        "--context", context,
        "get", resource,
        "-o", "json",
    ]

    if all_namespaces:
        command.insert(4, "-A")

    try:
        output = subprocess.check_output(
            command, text=True, stderr=subprocess.PIPE
        )
    except FileNotFoundError:
        raise SystemExit("kubectl was not found on PATH.")
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or "").strip() or f"exit code {error.returncode}"
        raise SystemExit(
            f"kubectl failed for '{resource}' in context {context}:\n{detail}"
        )

    try:
        return json.loads(output)
    except ValueError as error:
        raise SystemExit(f"kubectl returned invalid JSON for '{resource}': {error}")


def fetch_all(context):
    """
    Fetch every resource list the metrics need, concurrently.

    Each ``kubectl get`` is an independent, network-bound call, so running
    them in a thread pool costs roughly one call's latency instead of eleven.
    The first failure is raised as a clean SystemExit, as before.
    """
    with ThreadPoolExecutor(max_workers=len(RESOURCES)) as pool:
        futures = {
            key: pool.submit(get_resources, context, resource, all_ns)
            for key, resource, all_ns in RESOURCES
        }
        return {key: future.result() for key, future in futures.items()}


def rbac_metrics(data):
    """
    Measure RBAC risk from permissions actually bound to service accounts.

    This avoids penalizing every unused Role/ClusterRole in the cluster.
    """
    roles = data["roles"]
    cluster_roles = data["clusterroles"]
    role_bindings = data["rolebindings"]
    cluster_bindings = data["clusterrolebindings"]

    role_map = {}

    for role in roles.get("items", []):
        meta = role.get("metadata", {})
        key = (
            meta.get("namespace"),
            "Role",
            meta.get("name"),
        )
        role_map[key] = role.get("rules", []) or []

    for role in cluster_roles.get("items", []):
        meta = role.get("metadata", {})
        key = (
            None,
            "ClusterRole",
            meta.get("name"),
        )
        role_map[key] = role.get("rules", []) or []

    wildcard = 0
    secret_access = 0
    write_permissions = 0
    service_account_risk = 0
    cluster_admin = 0

    def score_binding(binding):
        nonlocal wildcard, secret_access
        nonlocal write_permissions, service_account_risk

        ref = binding.get("roleRef", {}) or {}
        kind = ref.get("kind")
        name = ref.get("name")

        namespace = None
        if kind == "Role":
            namespace = (
                binding.get("metadata", {})
                .get("namespace")
            )

        rules = role_map.get(
            (namespace, kind, name),
            []
        )

        service_account_subjects = [
            subject
            for subject in binding.get("subjects", []) or []
            if subject.get("kind") == "ServiceAccount"
        ]

        # Ignore Kubernetes/Falco system service accounts when computing
        # application RBAC risk; they are platform infrastructure, not
        # application permissions.
        service_account_subjects = [
            subject
            for subject in service_account_subjects
            if (
                subject.get("namespace") not in SYSTEM_NAMESPACES
                and not str(subject.get("name", "")).startswith("system:")
            )
        ]

        if not service_account_subjects:
            return

        points = 0

        for rule in rules:
            resources = rule.get("resources", []) or []
            verbs = rule.get("verbs", []) or []

            if "*" in resources or "*" in verbs:
                wildcard += 1
                points += 15

            if "secrets" in resources or "*" in resources:
                secret_access += 1
                points += 10

            if any(
                verb in verbs
                for verb in ["create", "update", "patch", "delete", "*"]
            ):
                write_permissions += 1
                points += 5

        service_account_risk += points

        if name == "cluster-admin" and kind == "ClusterRole":
            cluster_admin += 1

    for binding in role_bindings.get("items", []):
        namespace = (
            binding.get("metadata", {})
            .get("namespace", "")
        )
        if namespace not in SYSTEM_NAMESPACES:
            score_binding(binding)

    for binding in cluster_bindings.get("items", []):
        score_binding(binding)

    return {
        "rbac_risk_score": min(
            100,
            wildcard * 25
            + secret_access * 10
            + cluster_admin * 40
            + write_permissions * 2,
        ),
        "service_account_permission_score": min(
            100,
            service_account_risk,
        ),
        "wildcard_rbac_rules": wildcard,
        "cluster_admin_bindings": cluster_admin,
        "rbac_binding_count": (
            len(role_bindings.get("items", []))
            + len(cluster_bindings.get("items", []))
        ),
    }


def workload_metrics(data):
    privileged = 0
    root = 0
    host_path = 0
    risky_caps = 0
    host_port = 0

    deployments = data["deployments"]
    statefulsets = data["statefulsets"]
    daemonsets = data["daemonsets"]
    jobs = data["jobs"]
    cronjobs = data["cronjobs"]
    pods = data["pods"]
    network_policies = data["networkpolicies"]

    # Bare Pods (no controller) are workloads too: a privileged pod
    # created with `kubectl run` would otherwise be invisible. Pods that
    # have an owner are already counted through their controller.
    orphan_pods = [
        pod for pod in pods.get("items", [])
        if not (pod.get("metadata", {}).get("ownerReferences") or [])
    ]

    workloads = (
        deployments.get("items", [])
        + statefulsets.get("items", [])
        + daemonsets.get("items", [])
        + jobs.get("items", [])
        + cronjobs.get("items", [])
        + orphan_pods
    )

    policy_namespaces = {
        item.get("metadata", {}).get("namespace")
        for item in network_policies.get("items", [])
    }

    workload_namespaces = set()
    user_workload_count = 0

    risky_capabilities = {
        "SYS_ADMIN",
        "NET_ADMIN",
        "SYS_PTRACE",
        "NET_RAW",
        "SYS_MODULE",
    }

    for workload in workloads:
        meta = workload.get("metadata", {})
        namespace = meta.get("namespace", "default")

        if namespace in SYSTEM_NAMESPACES:
            continue

        workload_namespaces.add(namespace)
        user_workload_count += 1

        spec = workload.get("spec", {}) or {}

        # Jobs and CronJobs have an extra template layer.
        if workload.get("kind") == "Pod" or (
            "template" not in spec and "jobTemplate" not in spec
        ):
            # Bare Pod: the spec is the pod spec. (kubectl omits `kind`
            # on items inside a List, so fall back to the spec shape.)
            pod = spec
        elif "jobTemplate" in spec:
            pod = (
                spec.get("jobTemplate", {})
                .get("spec", {})
                .get("template", {})
                .get("spec", {})
                or {}
            )
        else:
            pod = (
                spec.get("template", {})
                .get("spec", {})
                or {}
            )

        for volume in pod.get("volumes", []) or []:
            if "hostPath" in volume:
                host_path += 1

        pod_security = pod.get("securityContext", {}) or {}

        containers = (
            list(pod.get("containers", []) or [])
            + list(pod.get("initContainers", []) or [])
            + list(pod.get("ephemeralContainers", []) or [])
        )

        for container in containers:
            security = container.get("securityContext", {}) or {}

            if security.get("privileged"):
                privileged += 1

            user = security.get(
                "runAsUser",
                pod_security.get("runAsUser")
            )
            non_root = security.get(
                "runAsNonRoot",
                pod_security.get("runAsNonRoot")
            )

            if user == 0 or (
                user is None and non_root is not True
            ):
                root += 1

            for capability in (
                security.get("capabilities", {})
                .get("add", [])
                or []
            ):
                if str(capability).upper() in risky_capabilities:
                    risky_caps += 1

            host_port += sum(
                1
                for port in container.get("ports", []) or []
                if port.get("hostPort")
            )

    missing_network_policies = sum(
        1
        for namespace in workload_namespaces
        if namespace not in policy_namespaces
    )

    return {
        "privileged_count": privileged,
        "root_execution_count": root,
        "host_path_count": host_path,
        "risky_capability_count": risky_caps,
        "host_port_count": host_port,
        "missing_network_policies": missing_network_policies,
        "workload_count": user_workload_count,
    }


def main():
    if len(sys.argv) != 2:
        raise SystemExit(
            "Usage: python3 src/collect_cluster_features.py <kube-context>"
        )

    data = fetch_all(sys.argv[1])

    result = {}
    result.update(rbac_metrics(data))
    result.update(workload_metrics(data))

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
