from pathlib import Path
import subprocess
import sys


def run(command):
    try:
        return subprocess.check_output(
            command, text=True, errors="replace", stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        raise SystemExit("kubectl was not found on PATH.")
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or "").strip() or f"exit code {error.returncode}"
        raise SystemExit(f"Command failed: {' '.join(command)}\n{detail}")


def main():
    if len(sys.argv) != 3:
        raise SystemExit(
            "Usage: python3 src/collect_falco.py <kube-context> <output-file>"
        )

    context = sys.argv[1]
    output = Path(sys.argv[2])
    output.parent.mkdir(parents=True, exist_ok=True)

    # For continuous assessment, only collect recent events so old alerts
    # are not counted again in every snapshot.
    since = "5m"

    # Only the Falco agent pods (not helper pods), by the chart's label.
    pods = run([
        "kubectl", "--context", context,
        "get", "pods", "-n", "falco",
        "-l", "app.kubernetes.io/name=falco",
        "-o", "jsonpath={.items[*].metadata.name}",
    ]).split()

    if not pods:
        raise SystemExit(
            f"No Falco pod found in context {context}. "
            "Was scripts/setup-kind-clusters.sh run successfully?"
        )

    logs = []

    for pod in pods:
        # -c falco: the chart's pods also run helper containers
        # (e.g. falcoctl), so name the container explicitly.
        text = run([
            "kubectl", "--context", context,
            "logs", "-n", "falco", pod, "-c", "falco",
            "--since", since, "--tail", "5000",
        ])
        logs.append(f"--- {pod} ---\n{text}")

    output.write_text("\n".join(logs) + "\n")

    print("Saved:", output)


if __name__ == "__main__":
    main()
