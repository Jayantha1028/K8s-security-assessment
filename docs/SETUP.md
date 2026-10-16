# CDC-5: complete setup and run guide

Works on Linux, macOS, and Windows through **WSL2** (use the Linux steps inside
WSL; the scripts are bash). Do Part A and B first. Part C is optional but is the
main goal of the project.

Rule of thumb for Part C: 4+ CPU cores, 8 GB RAM free for Docker, 10 GB disk,
internet access (images and vulnerability databases are downloaded).

---------------------------------------------------------------------------
## A. Python environment (needed for everything)

Requires Python 3.10+ (`python3 --version`).

```bash
cd <project folder>              # the folder containing README.md
chmod +x run.sh scripts/*.sh
python3 -m venv .venv
source .venv/bin/activate          # run this in every new terminal
pip install --upgrade pip
pip install -r requirements.txt
```

## B. Verify the project (no Kubernetes needed)

```bash
python3 -m unittest discover -s tests -v
```
Expected: `Ran 38 tests ... OK` (takes about a minute).

---------------------------------------------------------------------------
## C1. Lightweight pipeline (needs only Kubescape)

Install Kubescape (any one):
```bash
brew install kubescape-cli                                                  # macOS / Linuxbrew
curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | /bin/bash   # Linux
```
Check: `kubescape version`

Run:
```bash
./run.sh --manifests --fresh   # first run (wipes generated samples, scans and the CSV)
./run.sh --manifests           # later: add another batch to the dataset
```
Output: `data/processed/kubernetes_security_dataset.csv`. Needs internet (Kubescape downloads
its framework on first use).

---------------------------------------------------------------------------
## C2. Cluster-backed pipeline (the full project)

### Install the tools

| Tool | macOS (Homebrew) | Linux |
|---|---|---|
| Docker | Docker Desktop: https://docs.docker.com/get-docker/ | Docker Engine: https://docs.docker.com/engine/install/ |
| kubectl | `brew install kubectl` | https://kubernetes.io/docs/tasks/tools/ |
| Kind | `brew install kind` | see below |
| Helm | `brew install helm` | `curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 \| bash` |
| Kubescape | `brew install kubescape-cli` | install script in C1 |
| Trivy | `brew install trivy` | `curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \| sudo sh -s -- -b /usr/local/bin` |

Kind on Linux (the version in the URL changes; take the current one from
https://kind.sigs.k8s.io/docs/user/quick-start/):
```bash
[ $(uname -m) = x86_64 ]  && curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.33.0/kind-linux-amd64
[ $(uname -m) = aarch64 ] && curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.33.0/kind-linux-arm64
chmod +x ./kind && sudo mv ./kind /usr/local/bin/kind
```

Linux only: let your user run Docker without sudo, then log out/in:
```bash
sudo usermod -aG docker $USER
```
Windows: use Docker Desktop with the WSL2 backend enabled for your distro, and
run everything inside the WSL terminal.

### Check everything is ready
```bash
docker info > /dev/null && echo "docker running"
for t in docker kind kubectl helm kubescape trivy; do command -v $t >/dev/null && echo "ok: $t" || echo "MISSING: $t"; done
```
All six must say `ok`. Docker must be running.

### Run (automated, recommended)
```bash
source .venv/bin/activate
./run.sh --all
```
Options: `SNAPSHOTS=8 PAUSE=60 ./run.sh --all` (snapshots per scenario, minimum 5;
seconds between snapshots). Expect roughly 30-60 minutes; the first run is
slowest because of image downloads.

It does: clusters + first assessment -> baseline snapshots -> medium-risk
scenario snapshots -> restores the weak workload (always) -> builds the dataset once -> trains -> report.

Outputs: `data/processed/final_security_dataset.csv`,
`models/security_models.joblib`, `reports/security_report.txt`.

### Run (manual, step by step)
```bash
./run.sh --final           # clusters + first assessment (2 rows, no training yet)
scripts/take_snapshot.sh snapshot_01      # repeat with unique names, at least 5
scripts/apply_medium_scenario.sh          # switch insecure cluster to medium risk
scripts/take_snapshot.sh medium_01        # repeat with unique names, at least 5
kubectl --context kind-ml-k8s-insecure apply -f manifests/insecure/weak-deployment.yaml   # restore weak workload
python3 src/train_security_models.py      # needs >= 20 rows and >= 5 snapshots per risk class (prints the per-class table)
python3 src/generate_report.py            # reports on data/processed/report_input.csv
```
Optional continuous collection: `INTERVAL=300 scripts/continuous_assessment.sh` (Ctrl+C to stop).

### Clean up when finished
```bash
kind delete cluster --name ml-k8s-secure
kind delete cluster --name ml-k8s-insecure
```
The insecure cluster is deliberately vulnerable: use a throwaway machine only.

---------------------------------------------------------------------------
## Troubleshooting

| Symptom | Fix |
|---|---|
| `Required command not found on PATH: X` | Install X (table above) and open a new terminal |
| `permission denied` on `/var/run/docker.sock` | Linux: add yourself to the `docker` group (above), log out/in |
| `Cannot connect to the Docker daemon` | Start Docker Desktop / `sudo systemctl start docker` |
| Kind cluster creation times out | Give Docker more RAM/CPU; `kind delete cluster --name <name>` and retry |
| Falco rollout times out / pods crash-loop | Inspect: `kubectl --context kind-ml-k8s-secure -n falco get pods` and `logs`. Falco's driver depends on the host kernel; on Docker Desktop (macOS/Windows) try adding `--set driver.kind=modern_ebpf` to the `helm install` line in `scripts/setup-kind-clusters.sh` (delete the clusters first) |
| `WARNING: skipping snapshots/...: missing X` | That snapshot was incomplete (a scanner failed); re-run it with the same name |
| `Need at least 5 distinct snapshots per risk class` | Collect more snapshots (`SNAPSHOTS=10 ./run.sh --all`), then check the class table printed before training |
| Training metrics look perfect | Expected: the score is derived from the same indicators the models use. Describe it as a pipeline demonstration, not real-world accuracy |
| Scan works by hand but not in the scripts | Make sure `kubectl config get-contexts` lists `kind-ml-k8s-secure` and `kind-ml-k8s-insecure` |
