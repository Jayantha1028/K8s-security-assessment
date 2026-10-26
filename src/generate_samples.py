"""
Generate synthetic Kubernetes manifests with controlled security
profiles for the mid-semester dataset.

By default this ADDS new manifests to whatever is already in
data/raw/samples/synthetic/ instead of overwriting it, so you can accumulate a
bigger dataset over several runs:

    python3 src/generate_samples.py            # add more, on top of what's there
    python3 src/generate_samples.py --count 50 # add 50 more
    python3 src/generate_samples.py --fresh    # wipe the folder and start over

Each run uses a fresh random seed by default (printed at the end) so
repeated runs actually produce new variety instead of regenerating the
same 100 files every time - the previous version always used a fixed
seed, which meant every run was identical and "accumulating" data
just meant re-writing the same files. Pass --seed to reproduce a
specific batch.
"""

import argparse
import os
import random
import re
import shutil

import yaml

import paths


DEFAULT_COUNT = 100
DEFAULT_OUTPUT_DIR = str(paths.SAMPLES / "synthetic")

SAMPLE_NAME_RE = re.compile(r"sample-(\d+)\.yaml$")


# Each "profile" is a security band, not a fixed recipe. Every risky
# setting is an independent probability of being present in that band,
# sampled fresh per workload - so "hardened" no longer means one exact
# feature vector repeated 30-something times, it means a distribution
# of mostly-safe configurations that occasionally still slips (e.g. a
# hardened workload that forgot a seccomp profile). This is what makes
# the resulting dataset something a model has to actually learn from,
# instead of three points it can memorize by label.
PROFILE_PARAMS = {
    "hardened": {
        "privileged_prob": 0.0,
        "host_network_prob": 0.02,
        "host_pid_prob": 0.0,
        "host_ipc_prob": 0.03,
        "run_as_root_prob": 0.05,
        "allow_priv_esc_prob": 0.05,
        "read_only_root_prob": 0.9,
        "use_seccomp_prob": 0.92,
        "use_host_path_prob": 0.02,
        "use_host_port_prob": 0.08,
        "add_capability_prob": 0.05,
        "cpu_limit_prob": 0.92,
        "memory_limit_prob": 0.92,
        "service_account_token_prob": 0.15,
        "multi_container_prob": 0.08,
        "floating_image_prob": 0.03,
        "images": [
            "nginx:1.27-alpine", "nginx:1.26-alpine",
            "caddy:2.8-alpine", "httpd:2.4.62-alpine",
        ],
        "cpu_limits": ["100m", "250m", "500m"],
        "mem_limits": ["128Mi", "256Mi", "512Mi"],
    },
    "medium": {
        "privileged_prob": 0.05,
        "host_network_prob": 0.12,
        "host_pid_prob": 0.05,
        "host_ipc_prob": 0.4,
        "run_as_root_prob": 0.3,
        "allow_priv_esc_prob": 0.55,
        "read_only_root_prob": 0.3,
        "use_seccomp_prob": 0.55,
        "use_host_path_prob": 0.15,
        "use_host_port_prob": 0.55,
        "add_capability_prob": 0.5,
        "cpu_limit_prob": 0.7,
        "memory_limit_prob": 0.7,
        "service_account_token_prob": 0.65,
        "multi_container_prob": 0.22,
        "floating_image_prob": 0.18,
        "images": [
            "caddy:2.7-alpine", "node:18-slim",
            "python:3.11-slim", "redis:7-alpine",
        ],
        "cpu_limits": ["250m", "500m", "1"],
        "mem_limits": ["256Mi", "512Mi", "1Gi"],
    },
    "weak": {
        "privileged_prob": 0.65,
        "host_network_prob": 0.6,
        "host_pid_prob": 0.55,
        "host_ipc_prob": 0.75,
        "run_as_root_prob": 0.85,
        "allow_priv_esc_prob": 0.9,
        "read_only_root_prob": 0.05,
        "use_seccomp_prob": 0.1,
        "use_host_path_prob": 0.65,
        "use_host_port_prob": 0.8,
        "add_capability_prob": 0.85,
        "cpu_limit_prob": 0.15,
        "memory_limit_prob": 0.15,
        "service_account_token_prob": 0.9,
        "multi_container_prob": 0.35,
        "floating_image_prob": 0.5,
        "images": [
            "nginx:1.14.2", "python:2.7", "node:8", "httpd:2.2",
        ],
        "cpu_limits": ["500m", "1", "2"],
        "mem_limits": ["512Mi", "1Gi", "2Gi"],
    },
}

RISKY_CAPABILITIES = ["NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE", "NET_RAW"]


def flip(probability):
    return random.random() < probability


def choose_image(params):
    if flip(params["floating_image_prob"]):
        base = random.choice(params["images"]).split(":")[0]
        return random.choice([base, f"{base}:latest"])
    return random.choice(params["images"])


def build_container(name, params):
    """Sample one container's security posture from a profile band."""

    run_as_root = flip(params["run_as_root_prob"])

    security = {
        "privileged": flip(params["privileged_prob"]),
        "allowPrivilegeEscalation": flip(params["allow_priv_esc_prob"]),
        "readOnlyRootFilesystem": flip(params["read_only_root_prob"]),
    }

    if run_as_root:
        security["runAsUser"] = 0
        security["runAsNonRoot"] = False
    else:
        security["runAsUser"] = 1000
        security["runAsNonRoot"] = True

    if flip(params["use_seccomp_prob"]):
        security["seccompProfile"] = {"type": "RuntimeDefault"}

    if flip(params["add_capability_prob"]):
        added = random.sample(
            RISKY_CAPABILITIES,
            k=random.choice([1, 2]),
        )
        security["capabilities"] = {"add": added}
    else:
        security["capabilities"] = {"drop": ["ALL"]}

    container = {
        "name": name,
        "image": choose_image(params),
        "securityContext": security,
    }

    if flip(params["use_host_port_prob"]):
        container["ports"] = [
            {
                "containerPort": 8080,
                "hostPort": random.choice([8080, 8081, 9000]),
            }
        ]

    limits = {}

    if flip(params["cpu_limit_prob"]):
        limits["cpu"] = random.choice(params["cpu_limits"])

    if flip(params["memory_limit_prob"]):
        limits["memory"] = random.choice(params["mem_limits"])

    if limits:
        container["resources"] = {"limits": limits}

    uses_host_path = flip(params["use_host_path_prob"])

    return container, uses_host_path


def create_workload(number):

    # Pick a target security band (still weighted the same way as
    # before), then sample this workload's actual configuration from
    # that band's probabilities rather than copying a fixed recipe.
    profile_name = random.choices(
        ["hardened", "medium", "weak"],
        weights=[3, 4, 3],
        k=1,
    )[0]

    params = PROFILE_PARAMS[profile_name]

    containers = []
    host_path_needed = False

    container, needs_host_path = build_container("app", params)
    containers.append(container)
    host_path_needed = host_path_needed or needs_host_path

    # A minority of workloads carry a second container (e.g. a sidecar)
    # sampled from the same band. Real multi-container pods vary in
    # exactly this way, and it lets num_containers and the "worst case
    # across containers" feature logic actually see multiple values
    # instead of always being 1.
    if flip(params["multi_container_prob"]):
        extra, needs_host_path = build_container("sidecar", params)
        containers.append(extra)
        host_path_needed = host_path_needed or needs_host_path

    pod_spec = {
        "containers": containers,
        "hostNetwork": flip(params["host_network_prob"]),
        "hostPID": flip(params["host_pid_prob"]),
        "hostIPC": flip(params["host_ipc_prob"]),
        "automountServiceAccountToken": flip(
            params["service_account_token_prob"]
        ),
    }

    # When hostNetwork is enabled, Kubernetes API requires hostPort to match containerPort
    if pod_spec["hostNetwork"]:
        for c in containers:
            for p in c.get("ports", []):
                if "hostPort" in p:
                    p["hostPort"] = p["containerPort"]

    if host_path_needed:
        pod_spec["volumes"] = [
            {
                "name": "host-data",
                "hostPath": {
                    "path": "/tmp",
                    "type": "Directory",
                },
            }
        ]

        for container in containers:
            container["volumeMounts"] = [
                {
                    "name": "host-data",
                    "mountPath": "/data",
                }
            ]

    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": f"sample-{number}",
            "labels": {
                # This is the intended risk band, not a guarantee about
                # every feature - use it for reporting/grouping, not as
                # a stand-in ground-truth label for training.
                "security-profile": profile_name,
            },
        },
        "spec": {
            "replicas": 1,
            "selector": {
                "matchLabels": {
                    "app": f"sample-{number}"
                }
            },
            "template": {
                "metadata": {
                    "labels": {
                        "app": f"sample-{number}"
                    }
                },
                "spec": pod_spec,
            },
        },
    }


def existing_max_index(output_dir):
    """Highest sample-NNNN.yaml index already in output_dir, or 0."""
    if not os.path.isdir(output_dir):
        return 0

    indices = [
        int(match.group(1))
        for name in os.listdir(output_dir)
        if (match := SAMPLE_NAME_RE.match(name))
    ]
    return max(indices, default=0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--count", type=int, default=DEFAULT_COUNT,
        help=f"How many NEW manifests to generate (default {DEFAULT_COUNT})",
    )
    parser.add_argument(
        "--seed", type=int, default=None,
        help="Random seed. Default: a fresh seed each run (printed, so "
             "you can pass it back in to reproduce a batch).",
    )
    parser.add_argument(
        "--output-dir", default=DEFAULT_OUTPUT_DIR,
    )
    parser.add_argument(
        "--fresh", action="store_true",
        help="Delete the output directory first and number from 1, "
             "instead of adding on top of what's already there.",
    )
    args = parser.parse_args()

    if args.count < 1:
        raise SystemExit("--count must be at least 1")

    if args.fresh and os.path.isdir(args.output_dir):
        shutil.rmtree(args.output_dir)

    os.makedirs(args.output_dir, exist_ok=True)

    seed = (
        args.seed
        if args.seed is not None
        else random.SystemRandom().randint(0, 2**31 - 1)
    )
    random.seed(seed)

    start = 0 if args.fresh else existing_max_index(args.output_dir)

    for i in range(start + 1, start + args.count + 1):
        data = create_workload(i)
        filename = f"{args.output_dir}/sample-{i:04d}.yaml"

        with open(filename, "w") as file:
            yaml.safe_dump(data, file, sort_keys=False)

    print(f"Seed used: {seed}  (pass --seed {seed} to reproduce this batch)")
    print(
        f"Created {args.count} new manifest(s) in {args.output_dir}, "
        f"numbered {start + 1:04d}-{start + args.count:04d}"
    )


if __name__ == "__main__":
    main()
