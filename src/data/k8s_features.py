import yaml

WORKLOAD_KINDS = {
    "Pod", "Deployment", "StatefulSet", "DaemonSet",
    "ReplicaSet", "Job", "CronJob"
}

# Workload-level indicators used by the ML dataset.
FEATURE_COLS = [
    "privileged",
    "host_network",
    "host_pid",
    "host_ipc",
    "host_path_volumes",
    "host_ports",
    "run_as_root",
    "allow_priv_esc",
    "rw_root_fs",
    "caps_not_dropped",
    "caps_added",
    "no_seccomp",
    "no_cpu_limit",
    "no_mem_limit",
    "image_latest",
    "automount_sa_token",
    "num_containers",
]


def get_pod_spec(doc):
    """Get the Pod spec from a supported Kubernetes workload."""
    kind = doc.get("kind")
    spec = doc.get("spec") or {}

    if kind == "Pod":
        return spec

    if kind == "CronJob":
        return (
            spec.get("jobTemplate", {})
            .get("spec", {})
            .get("template", {})
            .get("spec", {})
            or {}
        )

    return spec.get("template", {}).get("spec", {}) or {}


def image_is_floating(image):
    """True when an image is untagged or explicitly uses :latest."""
    if not image:
        return True
    if "@sha256:" in image:
        return False

    last_part = image.split("/")[-1]
    return ":" not in last_part or last_part.endswith(":latest")


def extract_features(doc):
    """
    Convert one Kubernetes workload into numeric security indicators.

    For multi-container workloads, a risky setting in any container is
    represented in the row (worst-case posture).
    """
    pod = get_pod_spec(doc)

    containers = (
        list(pod.get("containers") or [])
        + list(pod.get("initContainers") or [])
        + list(pod.get("ephemeralContainers") or [])
    )

    if not containers:
        raise ValueError("No containers found")

    pod_security = pod.get("securityContext") or {}
    features = {name: 0 for name in FEATURE_COLS}

    features["host_network"] = int(bool(pod.get("hostNetwork")))
    features["host_pid"] = int(bool(pod.get("hostPID")))
    features["host_ipc"] = int(bool(pod.get("hostIPC")))

    features["host_path_volumes"] = sum(
        1 for volume in pod.get("volumes") or []
        if "hostPath" in volume
    )

    # True means the token is automatically mounted unless explicitly disabled.
    features["automount_sa_token"] = int(
        pod.get("automountServiceAccountToken") is not False
    )

    features["num_containers"] = len(containers)

    for container in containers:
        security = container.get("securityContext") or {}

        if security.get("privileged"):
            features["privileged"] = 1

        user_id = security.get(
            "runAsUser",
            pod_security.get("runAsUser")
        )
        non_root = security.get(
            "runAsNonRoot",
            pod_security.get("runAsNonRoot")
        )

        if user_id == 0 or (user_id is None and non_root is not True):
            features["run_as_root"] = 1

        if security.get("allowPrivilegeEscalation", True):
            features["allow_priv_esc"] = 1

        if security.get("readOnlyRootFilesystem", False) is not True:
            features["rw_root_fs"] = 1

        capabilities = security.get("capabilities") or {}
        dropped = {
            str(value).upper()
            for value in capabilities.get("drop") or []
        }

        if "ALL" not in dropped:
            features["caps_not_dropped"] = 1

        features["caps_added"] += len(
            capabilities.get("add") or []
        )

        seccomp = (
            security.get("seccompProfile")
            or pod_security.get("seccompProfile")
        )
        if not seccomp:
            features["no_seccomp"] = 1

        limits = (
            container.get("resources", {})
            .get("limits", {})
            or {}
        )

        if "cpu" not in limits:
            features["no_cpu_limit"] = 1

        if "memory" not in limits:
            features["no_mem_limit"] = 1

        if image_is_floating(container.get("image")):
            features["image_latest"] = 1

        features["host_ports"] += sum(
            1
            for port in container.get("ports") or []
            if port.get("hostPort")
        )

    return features


def load_workloads(filename):
    """Return [(name, document)] for workloads in a YAML file."""
    workloads = []

    with open(filename) as file:
        for document in yaml.safe_load_all(file):
            if not isinstance(document, dict):
                continue

            kind = document.get("kind")

            # Support kubectl-style List documents.
            if kind == "List":
                documents = document.get("items") or []
            else:
                documents = [document]

            for item in documents:
                if not isinstance(item, dict):
                    continue
                if item.get("kind") not in WORKLOAD_KINDS:
                    continue

                name = (
                    item.get("metadata", {})
                    .get("name", "unnamed")
                )
                workloads.append((name, item))

    return workloads
