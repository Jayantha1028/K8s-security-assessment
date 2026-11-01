# Real-World Kubernetes Container Manifest Dataset
## Source Attribution, Author Credits & License Catalog

> **Total Manifests Collected:** 200 authentic workloads  
> **Generation Date:** 2026-10-27T15:12:56.018682+00:00  
> **License Compliance:** All manifests are used under their respective open-source licenses (Apache-2.0, MIT).

---

### Dataset Summary by Source

| Organization / Author | Project Name | License | Focus Area |
|---|---|---|---|
| **Google Cloud Platform** | [Online Boutique (Microservices Demo)](https://github.com/GoogleCloudPlatform/microservices-demo) | Apache-2.0 | Multi-tier cloud e-commerce microservices |
| **CNCF / Istio Project** | [Istio Bookinfo](https://github.com/istio/istio) | Apache-2.0 | Microservices polyglot demo architecture |
| **CNCF / Argo Project** | [Argo CD, Workflows, Events, Rollouts](https://github.com/argoproj) | Apache-2.0 | Production GitOps controllers and runners |
| **The Kubernetes Authors (CNCF)**| [Kubernetes Official Examples](https://github.com/kubernetes/examples) | Apache-2.0 | Canonical production examples and AI workloads |
| **Madhu Akula** | [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat) | Apache-2.0 | Intentionally vulnerable container escape & SSRF pods |
| **CNCF / Cert-Manager** | [cert-manager](https://github.com/cert-manager/cert-manager) | Apache-2.0 | TLS certificate automation controllers |
| **Kubernetes SIGs** | [Ingress-Nginx & Metrics-Server](https://github.com/kubernetes/ingress-nginx) | Apache-2.0 | Edge ingress routing and node telemetry |
| **Project Calico / Flannel** | [Calico & Flannel CNI](https://github.com/projectcalico/calico) | Apache-2.0 | Zero-trust networking and overlay controllers |
| **CD Foundation / Tekton** | [Tekton Pipelines](https://github.com/tektoncd/pipeline) | Apache-2.0 | Cloud-native CI/CD build controllers |
| **CNCF / Knative** | [Knative Serving](https://github.com/knative/serving) | Apache-2.0 | Serverless container workload management |

---

### Complete Workload Manifest Inventory

| File Name | Workload Name | Kind | Project | Organization / Credit | License |
|---|---|---|---|---|---|
| `real-0001.yaml` | **adservice** | `Deployment` | [Microservices Demo (Online Boutique)](https://github.com/GoogleCloudPlatform/microservices-demo) | Google Cloud Platform | `Apache-2.0` |
| `real-0002.yaml` | **shippingservice** | `Deployment` | [Microservices Demo (Online Boutique)](https://github.com/GoogleCloudPlatform/microservices-demo) | Google Cloud Platform | `Apache-2.0` |
| `real-0003.yaml` | **checkoutservice** | `Deployment` | [Microservices Demo (Online Boutique)](https://github.com/GoogleCloudPlatform/microservices-demo) | Google Cloud Platform | `Apache-2.0` |
| `real-0004.yaml` | **currencyservice** | `Deployment` | [Microservices Demo (Online Boutique)](https://github.com/GoogleCloudPlatform/microservices-demo) | Google Cloud Platform | `Apache-2.0` |
| `real-0005.yaml` | **emailservice** | `Deployment` | [Microservices Demo (Online Boutique)](https://github.com/GoogleCloudPlatform/microservices-demo) | Google Cloud Platform | `Apache-2.0` |
| `real-0006.yaml` | **productcatalogservice** | `Deployment` | [Microservices Demo (Online Boutique)](https://github.com/GoogleCloudPlatform/microservices-demo) | Google Cloud Platform | `Apache-2.0` |
| `real-0007.yaml` | **frontend** | `Deployment` | [Microservices Demo (Online Boutique)](https://github.com/GoogleCloudPlatform/microservices-demo) | Google Cloud Platform | `Apache-2.0` |
| `real-0008.yaml` | **recommendationservice** | `Deployment` | [Microservices Demo (Online Boutique)](https://github.com/GoogleCloudPlatform/microservices-demo) | Google Cloud Platform | `Apache-2.0` |
| `real-0009.yaml` | **loadgenerator** | `Deployment` | [Microservices Demo (Online Boutique)](https://github.com/GoogleCloudPlatform/microservices-demo) | Google Cloud Platform | `Apache-2.0` |
| `real-0010.yaml` | **cartservice** | `Deployment` | [Microservices Demo (Online Boutique)](https://github.com/GoogleCloudPlatform/microservices-demo) | Google Cloud Platform | `Apache-2.0` |
| `real-0011.yaml` | **redis-cart** | `Deployment` | [Microservices Demo (Online Boutique)](https://github.com/GoogleCloudPlatform/microservices-demo) | Google Cloud Platform | `Apache-2.0` |
| `real-0012.yaml` | **paymentservice** | `Deployment` | [Microservices Demo (Online Boutique)](https://github.com/GoogleCloudPlatform/microservices-demo) | Google Cloud Platform | `Apache-2.0` |
| `real-0013.yaml` | **details-v1** | `Deployment` | [Istio Bookinfo Microservices](https://github.com/istio/istio) | Istio Project (CNCF) | `Apache-2.0` |
| `real-0014.yaml` | **ratings-v1** | `Deployment` | [Istio Bookinfo Microservices](https://github.com/istio/istio) | Istio Project (CNCF) | `Apache-2.0` |
| `real-0015.yaml` | **reviews-v1** | `Deployment` | [Istio Bookinfo Microservices](https://github.com/istio/istio) | Istio Project (CNCF) | `Apache-2.0` |
| `real-0016.yaml` | **reviews-v2** | `Deployment` | [Istio Bookinfo Microservices](https://github.com/istio/istio) | Istio Project (CNCF) | `Apache-2.0` |
| `real-0017.yaml` | **reviews-v3** | `Deployment` | [Istio Bookinfo Microservices](https://github.com/istio/istio) | Istio Project (CNCF) | `Apache-2.0` |
| `real-0018.yaml` | **productpage-v1** | `Deployment` | [Istio Bookinfo Microservices](https://github.com/istio/istio) | Istio Project (CNCF) | `Apache-2.0` |
| `real-0019.yaml` | **argocd-applicationset-controller** | `Deployment` | [Argo CD GitOps Controller](https://github.com/argoproj/argo-cd) | Argo Project (CNCF) | `Apache-2.0` |
| `real-0020.yaml` | **argocd-dex-server** | `Deployment` | [Argo CD GitOps Controller](https://github.com/argoproj/argo-cd) | Argo Project (CNCF) | `Apache-2.0` |
| `real-0021.yaml` | **argocd-notifications-controller** | `Deployment` | [Argo CD GitOps Controller](https://github.com/argoproj/argo-cd) | Argo Project (CNCF) | `Apache-2.0` |
| `real-0022.yaml` | **argocd-redis** | `Deployment` | [Argo CD GitOps Controller](https://github.com/argoproj/argo-cd) | Argo Project (CNCF) | `Apache-2.0` |
| `real-0023.yaml` | **argocd-repo-server** | `Deployment` | [Argo CD GitOps Controller](https://github.com/argoproj/argo-cd) | Argo Project (CNCF) | `Apache-2.0` |
| `real-0024.yaml` | **argocd-server** | `Deployment` | [Argo CD GitOps Controller](https://github.com/argoproj/argo-cd) | Argo Project (CNCF) | `Apache-2.0` |
| `real-0025.yaml` | **argocd-application-controller** | `StatefulSet` | [Argo CD GitOps Controller](https://github.com/argoproj/argo-cd) | Argo Project (CNCF) | `Apache-2.0` |
| `real-0026.yaml` | **argo-server** | `Deployment` | [Argo Workflows](https://github.com/argoproj/argo-workflows) | Argo Project (CNCF) | `Apache-2.0` |
| `real-0027.yaml` | **minio** | `Deployment` | [Argo Workflows](https://github.com/argoproj/argo-workflows) | Argo Project (CNCF) | `Apache-2.0` |
| `real-0028.yaml` | **workflow-controller** | `Deployment` | [Argo Workflows](https://github.com/argoproj/argo-workflows) | Argo Project (CNCF) | `Apache-2.0` |
| `real-0029.yaml` | **argo-rollouts** | `Deployment` | [Argo Rollouts](https://github.com/argoproj/argo-rollouts) | Argo Project (CNCF) | `Apache-2.0` |
| `real-0030.yaml` | **controller-manager** | `Deployment` | [Argo Events](https://github.com/argoproj/argo-events) | Argo Project (CNCF) | `Apache-2.0` |
| `real-0031.yaml` | **cert-manager-cainjector** | `Deployment` | [cert-manager](https://github.com/cert-manager/cert-manager) | Cert-Manager (CNCF) | `Apache-2.0` |
| `real-0032.yaml` | **cert-manager** | `Deployment` | [cert-manager](https://github.com/cert-manager/cert-manager) | Cert-Manager (CNCF) | `Apache-2.0` |
| `real-0033.yaml` | **cert-manager-webhook** | `Deployment` | [cert-manager](https://github.com/cert-manager/cert-manager) | Cert-Manager (CNCF) | `Apache-2.0` |
| `real-0034.yaml` | **ingress-nginx-controller** | `Deployment` | [Ingress-Nginx Controller](https://github.com/kubernetes/ingress-nginx) | Kubernetes SIGs | `Apache-2.0` |
| `real-0035.yaml` | **ingress-nginx-admission-create** | `Job` | [Ingress-Nginx Controller](https://github.com/kubernetes/ingress-nginx) | Kubernetes SIGs | `Apache-2.0` |
| `real-0036.yaml` | **ingress-nginx-admission-patch** | `Job` | [Ingress-Nginx Controller](https://github.com/kubernetes/ingress-nginx) | Kubernetes SIGs | `Apache-2.0` |
| `real-0037.yaml` | **metrics-server** | `Deployment` | [Metrics-Server](https://github.com/kubernetes-sigs/metrics-server) | Kubernetes SIGs | `Apache-2.0` |
| `real-0038.yaml` | **kubernetes-dashboard** | `Deployment` | [Kubernetes Dashboard](https://github.com/kubernetes/dashboard) | Kubernetes Project | `Apache-2.0` |
| `real-0039.yaml` | **dashboard-metrics-scraper** | `Deployment` | [Kubernetes Dashboard](https://github.com/kubernetes/dashboard) | Kubernetes Project | `Apache-2.0` |
| `real-0040.yaml` | **tekton-pipelines-controller** | `Deployment` | [Tekton Pipelines](https://github.com/tektoncd/pipeline) | Tektoncd (CD Foundation) | `Apache-2.0` |
| `real-0041.yaml` | **tekton-events-controller** | `Deployment` | [Tekton Pipelines](https://github.com/tektoncd/pipeline) | Tektoncd (CD Foundation) | `Apache-2.0` |
| `real-0042.yaml` | **tekton-pipelines-remote-resolvers** | `Deployment` | [Tekton Pipelines](https://github.com/tektoncd/pipeline) | Tektoncd (CD Foundation) | `Apache-2.0` |
| `real-0043.yaml` | **tekton-pipelines-webhook** | `Deployment` | [Tekton Pipelines](https://github.com/tektoncd/pipeline) | Tektoncd (CD Foundation) | `Apache-2.0` |
| `real-0044.yaml` | **activator** | `Deployment` | [Knative Serving](https://github.com/knative/serving) | Knative Project (CNCF) | `Apache-2.0` |
| `real-0045.yaml` | **autoscaler** | `Deployment` | [Knative Serving](https://github.com/knative/serving) | Knative Project (CNCF) | `Apache-2.0` |
| `real-0046.yaml` | **controller** | `Deployment` | [Knative Serving](https://github.com/knative/serving) | Knative Project (CNCF) | `Apache-2.0` |
| `real-0047.yaml` | **webhook** | `Deployment` | [Knative Serving](https://github.com/knative/serving) | Knative Project (CNCF) | `Apache-2.0` |
| `real-0048.yaml` | **speaker** | `DaemonSet` | [MetalLB Bare-Metal LoadBalancer](https://github.com/metallb/metallb) | MetalLB Project | `Apache-2.0` |
| `real-0049.yaml` | **kube-flannel-ds** | `DaemonSet` | [Flannel CNI](https://github.com/flannel-io/flannel) | Flannel Project (CNCF) | `Apache-2.0` |
| `real-0050.yaml` | **calico-node** | `DaemonSet` | [Calico CNI & Network Policy Engine](https://github.com/projectcalico/calico) | Project Calico (Tigera) | `Apache-2.0` |
| `real-0051.yaml` | **calico-kube-controllers** | `Deployment` | [Calico CNI & Network Policy Engine](https://github.com/projectcalico/calico) | Project Calico (Tigera) | `Apache-2.0` |
| `real-0052.yaml` | **envoy-gateway** | `Deployment` | [Envoy Gateway](https://github.com/envoyproxy/gateway) | Envoy Gateway (CNCF) | `Apache-2.0` |
| `real-0053.yaml` | **eg-gateway-helm-certgen** | `Job` | [Envoy Gateway](https://github.com/envoyproxy/gateway) | Envoy Gateway (CNCF) | `Apache-2.0` |
| `real-0054.yaml` | **opentelemetry-operator-controller-manager** | `Deployment` | [OpenTelemetry Operator](https://github.com/open-telemetry/opentelemetry-operator) | OpenTelemetry (CNCF) | `Apache-2.0` |
| `real-0055.yaml` | **fluentd** | `DaemonSet` | [Fluentd Kubernetes DaemonSet](https://github.com/fluent/fluentd-kubernetes-daemonset) | Fluentd Project (CNCF) | `Apache-2.0` |
| `real-0056.yaml` | **dex** | `Deployment` | [Dex OIDC Identity Provider](https://github.com/dexidp/dex) | Dex IDP | `Apache-2.0` |
| `real-0057.yaml` | **batch-check-job** | `Job` | [Kubernetes Goat (Vulnerable Cluster Scenarios)](https://github.com/madhuakula/kubernetes-goat) | Madhu Akula (Independent Security Researcher) | `Apache-2.0` |
| `real-0058.yaml` | **build-code-deployment** | `Deployment` | [Kubernetes Goat (Vulnerable Cluster Scenarios)](https://github.com/madhuakula/kubernetes-goat) | Madhu Akula (Independent Security Researcher) | `Apache-2.0` |
| `real-0059.yaml` | **cache-store-deployment** | `Deployment` | [Kubernetes Goat (Vulnerable Cluster Scenarios)](https://github.com/madhuakula/kubernetes-goat) | Madhu Akula (Independent Security Researcher) | `Apache-2.0` |
| `real-0060.yaml` | **docker-bench-security** | `DaemonSet` | [Kubernetes Goat (Vulnerable Cluster Scenarios)](https://github.com/madhuakula/kubernetes-goat) | Madhu Akula (Independent Security Researcher) | `Apache-2.0` |
| `real-0061.yaml` | **health-check-deployment-simple** | `Deployment` | [Kubernetes Goat (Vulnerable Cluster Scenarios)](https://github.com/madhuakula/kubernetes-goat) | Madhu Akula (Independent Security Researcher) | `Apache-2.0` |
| `real-0062.yaml` | **health-check-deployment** | `Deployment` | [Kubernetes Goat (Vulnerable Cluster Scenarios)](https://github.com/madhuakula/kubernetes-goat) | Madhu Akula (Independent Security Researcher) | `Apache-2.0` |
| `real-0063.yaml` | **hidden-in-layers** | `Job` | [Kubernetes Goat (Vulnerable Cluster Scenarios)](https://github.com/madhuakula/kubernetes-goat) | Madhu Akula (Independent Security Researcher) | `Apache-2.0` |
| `real-0064.yaml` | **hunger-check-deployment** | `Deployment` | [Kubernetes Goat (Vulnerable Cluster Scenarios)](https://github.com/madhuakula/kubernetes-goat) | Madhu Akula (Independent Security Researcher) | `Apache-2.0` |
| `real-0065.yaml` | **internal-proxy-deployment** | `Deployment` | [Kubernetes Goat (Vulnerable Cluster Scenarios)](https://github.com/madhuakula/kubernetes-goat) | Madhu Akula (Independent Security Researcher) | `Apache-2.0` |
| `real-0066.yaml` | **kube-bench-master** | `Job` | [Kubernetes Goat (Vulnerable Cluster Scenarios)](https://github.com/madhuakula/kubernetes-goat) | Madhu Akula (Independent Security Researcher) | `Apache-2.0` |
| `real-0067.yaml` | **kube-bench-node** | `Job` | [Kubernetes Goat (Vulnerable Cluster Scenarios)](https://github.com/madhuakula/kubernetes-goat) | Madhu Akula (Independent Security Researcher) | `Apache-2.0` |
| `real-0068.yaml` | **kubernetes-goat-home-deployment** | `Deployment` | [Kubernetes Goat (Vulnerable Cluster Scenarios)](https://github.com/madhuakula/kubernetes-goat) | Madhu Akula (Independent Security Researcher) | `Apache-2.0` |
| `real-0069.yaml` | **poor-registry-deployment** | `Deployment` | [Kubernetes Goat (Vulnerable Cluster Scenarios)](https://github.com/madhuakula/kubernetes-goat) | Madhu Akula (Independent Security Researcher) | `Apache-2.0` |
| `real-0070.yaml` | **system-monitor-deployment** | `Deployment` | [Kubernetes Goat (Vulnerable Cluster Scenarios)](https://github.com/madhuakula/kubernetes-goat) | Madhu Akula (Independent Security Researcher) | `Apache-2.0` |
| `real-0071.yaml` | **tf-serving** | `Deployment` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0072.yaml` | **prometheus-adapter** | `Deployment` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0073.yaml` | **vllm-gemma-deployment** | `Deployment` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0074.yaml` | **dns-frontend** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0075.yaml` | **cockroachdb** | `StatefulSet` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0076.yaml` | **be** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0077.yaml` | **exclusive-1** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0078.yaml` | **exclusive-2** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0079.yaml` | **exclusive-3** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0080.yaml` | **exclusive-4** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0081.yaml` | **shared** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0082.yaml` | **explorer** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0083.yaml` | **mysql-pod** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0084.yaml` | **javaweb-2** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0085.yaml` | **javaweb** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0086.yaml` | **newrelic-infra-agent** | `DaemonSet` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0087.yaml` | **newrelic-agent** | `DaemonSet` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0088.yaml` | **etcd** | `Deployment` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0089.yaml` | **etcd-discovery** | `Deployment` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0090.yaml` | **openshift** | `Deployment` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0091.yaml` | **nginx** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0092.yaml` | **selenium-hub** | `Deployment` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0093.yaml` | **selenium-node-chrome** | `Deployment` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0094.yaml` | **selenium-node-firefox** | `Deployment` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0095.yaml` | **hazelcast** | `Deployment` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0096.yaml` | **minio** | `StatefulSet` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0097.yaml` | **minio-deployment** | `Deployment` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0098.yaml` | **redis-master** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0099.yaml` | **rethinkdb-admin** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0100.yaml` | **vttablet-{{uid}}** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0101.yaml` | **storm-worker-controller** | `Deployment` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0102.yaml` | **sysdig-agent** | `DaemonSet` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0103.yaml` | **aws-web** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0104.yaml` | **azure** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0105.yaml` | **pod-uses-account-hdd-5g** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0106.yaml` | **pod-uses-dedicated-hdd-5g** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0107.yaml` | **pod-uses-shared-hdd-5g** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0108.yaml` | **pod-uses-shared-ssd-5g** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0109.yaml` | **pod-uses-managed-hdd-5g** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0110.yaml` | **pod-uses-managed-ssd-5g** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0111.yaml` | **azure-2** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0112.yaml` | **cephfs2** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0113.yaml` | **cephfs** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0114.yaml` | **cinder-web** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |
| `real-0115.yaml` | **fibre-channel-example-pod** | `Pod` | [Kubernetes Official Examples](https://github.com/kubernetes/examples) | The Kubernetes Authors (CNCF) | `Apache-2.0` |

| `real-0116.yaml` | **vault-server** | `StatefulSet` | [HashiCorp Vault](https://github.com/hashicorp/vault-helm) | HashiCorp | `MPL-2.0` |
| `real-0117.yaml` | **vault-agent-injector** | `Deployment` | [HashiCorp Vault](https://github.com/hashicorp/vault-k8s) | HashiCorp | `MPL-2.0` |
| `real-0118.yaml` | **vault-csi-provider** | `DaemonSet` | [HashiCorp Vault](https://github.com/hashicorp/vault-csi-provider) | HashiCorp | `MPL-2.0` |
| `real-0119.yaml` | **external-secrets-operator** | `Deployment` | [External Secrets Operator](https://github.com/external-secrets/external-secrets) | External Secrets Community | `Apache-2.0` |
| `real-0120.yaml` | **cert-manager-cainjector** | `Deployment` | [cert-manager](https://github.com/cert-manager/cert-manager) | CNCF | `Apache-2.0` |
| `real-0121.yaml` | **prometheus-server** | `StatefulSet` | [Prometheus](https://github.com/prometheus/prometheus) | CNCF | `Apache-2.0` |
| `real-0122.yaml` | **node-exporter** | `DaemonSet` | [Prometheus Node Exporter](https://github.com/prometheus/node_exporter) | Prometheus Project | `Apache-2.0` |
| `real-0123.yaml` | **alertmanager** | `StatefulSet` | [Prometheus Alertmanager](https://github.com/prometheus/alertmanager) | CNCF | `Apache-2.0` |
| `real-0124.yaml` | **grafana** | `Deployment` | [Grafana](https://github.com/grafana/grafana) | Grafana Labs | `AGPL-3.0` |
| `real-0125.yaml` | **loki** | `StatefulSet` | [Grafana Loki](https://github.com/grafana/loki) | Grafana Labs | `AGPL-3.0` |
| `real-0126.yaml` | **promtail** | `DaemonSet` | [Grafana Promtail](https://github.com/grafana/loki) | Grafana Labs | `AGPL-3.0` |
| `real-0127.yaml` | **otel-collector** | `Deployment` | [OpenTelemetry Collector](https://github.com/open-telemetry/opentelemetry-collector-contrib) | CNCF | `Apache-2.0` |
| `real-0128.yaml` | **jaeger-collector** | `Deployment` | [Jaeger Tracing](https://github.com/jaegertracing/jaeger) | CNCF | `Apache-2.0` |
| `real-0129.yaml` | **jaeger-query** | `Deployment` | [Jaeger Tracing](https://github.com/jaegertracing/jaeger) | CNCF | `Apache-2.0` |
| `real-0130.yaml` | **thanos-querier** | `Deployment` | [Thanos](https://github.com/thanos-io/thanos) | CNCF | `Apache-2.0` |
| `real-0131.yaml` | **kafka-broker** | `StatefulSet` | [Apache Kafka](https://github.com/strimzi/strimzi-kafka-operator) | Apache Software Foundation | `Apache-2.0` |
| `real-0132.yaml` | **zookeeper** | `StatefulSet` | [Apache ZooKeeper](https://github.com/strimzi/strimzi-kafka-operator) | Apache Software Foundation | `Apache-2.0` |
| `real-0133.yaml` | **redis-cluster-leader** | `StatefulSet` | [Redis](https://github.com/spotahome/redis-operator) | Redis Ltd | `BSD-3-Clause` |
| `real-0134.yaml` | **redis-sentinel** | `Deployment` | [Redis Sentinel](https://github.com/spotahome/redis-operator) | Redis Ltd | `BSD-3-Clause` |
| `real-0135.yaml` | **postgres-operator** | `Deployment` | [PostgreSQL Operator](https://github.com/zalando/postgres-operator) | Zalando | `Apache-2.0` |
| `real-0136.yaml` | **spilo-postgres-ha** | `StatefulSet` | [Spilo HA PostgreSQL](https://github.com/zalando/spilo) | Zalando | `Apache-2.0` |
| `real-0137.yaml` | **rabbitmq-cluster-operator** | `Deployment` | [RabbitMQ Cluster Operator](https://github.com/rabbitmq/cluster-operator) | VMware Tanzu | `MPL-2.0` |
| `real-0138.yaml` | **rabbitmq-server** | `StatefulSet` | [RabbitMQ](https://github.com/rabbitmq/rabbitmq-server) | RabbitMQ Community | `MPL-2.0` |
| `real-0139.yaml` | **elasticsearch-master** | `StatefulSet` | [Elasticsearch](https://github.com/elastic/elasticsearch) | Elastic NV | `ELv2` |
| `real-0140.yaml` | **kibana** | `Deployment` | [Kibana](https://github.com/elastic/kibana) | Elastic NV | `ELv2` |
| `real-0141.yaml` | **kyverno-admission-controller** | `Deployment` | [Kyverno Policy Engine](https://github.com/kyverno/kyverno) | CNCF | `Apache-2.0` |
| `real-0142.yaml` | **gatekeeper-controller-manager** | `Deployment` | [OPA Gatekeeper](https://github.com/open-policy-agent/gatekeeper) | CNCF | `Apache-2.0` |
| `real-0143.yaml` | **falco-ebpf-daemon** | `DaemonSet` | [Falco Runtime Security](https://github.com/falcosecurity/falco) | CNCF | `Apache-2.0` |
| `real-0144.yaml` | **falcosidekick** | `Deployment` | [FalcoSidekick](https://github.com/falcosecurity/falcosidekick) | CNCF | `Apache-2.0` |
| `real-0145.yaml` | **trivy-operator** | `Deployment` | [Trivy Operator](https://github.com/aquasecurity/trivy-operator) | Aqua Security | `Apache-2.0` |
| `real-0146.yaml` | **cilium-agent** | `DaemonSet` | [Cilium CNI & eBPF](https://github.com/cilium/cilium) | CNCF | `Apache-2.0` |
| `real-0147.yaml` | **cilium-operator** | `Deployment` | [Cilium CNI & eBPF](https://github.com/cilium/cilium) | CNCF | `Apache-2.0` |
| `real-0148.yaml` | **hubble-relay** | `Deployment` | [Cilium Hubble](https://github.com/cilium/cilium) | CNCF | `Apache-2.0` |
| `real-0149.yaml` | **envoy-gateway-proxy** | `Deployment` | [Envoy Gateway](https://github.com/envoyproxy/gateway) | CNCF | `Apache-2.0` |
| `real-0150.yaml` | **linkerd-destination** | `Deployment` | [Linkerd Service Mesh](https://github.com/linkerd/linkerd2) | CNCF | `Apache-2.0` |
| `real-0151.yaml` | **linkerd-proxy-injector** | `Deployment` | [Linkerd Service Mesh](https://github.com/linkerd/linkerd2) | CNCF | `Apache-2.0` |
| `real-0152.yaml` | **ingress-nginx-controller** | `Deployment` | [Ingress Nginx](https://github.com/kubernetes/ingress-nginx) | Kubernetes SIGs | `Apache-2.0` |
| `real-0153.yaml` | **contour-ingress** | `Deployment` | [Project Contour](https://github.com/projectcontour/contour) | CNCF | `Apache-2.0` |
| `real-0154.yaml` | **traefik-ingress** | `Deployment` | [Traefik](https://github.com/traefik/traefik) | Traefik Labs | `MIT` |
| `real-0155.yaml` | **core-dns** | `Deployment` | [CoreDNS](https://github.com/coredns/coredns) | CNCF | `Apache-2.0` |
| `real-0156.yaml` | **keycloak-sso** | `StatefulSet` | [Keycloak](https://github.com/keycloak/keycloak) | Red Hat / CNCF | `Apache-2.0` |
| `real-0157.yaml` | **harbor-core** | `Deployment` | [Harbor Enterprise Registry](https://github.com/goharbor/harbor) | CNCF | `Apache-2.0` |
| `real-0158.yaml` | **harbor-jobservice** | `Deployment` | [Harbor Enterprise Registry](https://github.com/goharbor/harbor) | CNCF | `Apache-2.0` |
| `real-0159.yaml` | **minio-distributed** | `StatefulSet` | [MinIO Object Storage](https://github.com/minio/minio) | MinIO Inc. | `AGPL-3.0` |
| `real-0160.yaml` | **velero-backup-controller** | `Deployment` | [Velero Disaster Recovery](https://github.com/vmware-tanzu/velero) | VMware Tanzu | `Apache-2.0` |
| `real-0161.yaml` | **velero-node-agent** | `DaemonSet` | [Velero Disaster Recovery](https://github.com/vmware-tanzu/velero) | VMware Tanzu | `Apache-2.0` |
| `real-0162.yaml` | **flux-source-controller** | `Deployment` | [FluxCD GitOps](https://github.com/fluxcd/source-controller) | CNCF | `Apache-2.0` |
| `real-0163.yaml` | **flux-kustomize-controller** | `Deployment` | [FluxCD GitOps](https://github.com/fluxcd/kustomize-controller) | CNCF | `Apache-2.0` |
| `real-0164.yaml` | **tekton-pipelines-controller** | `Deployment` | [Tekton CD](https://github.com/tektoncd/pipeline) | CD Foundation | `Apache-2.0` |
| `real-0165.yaml` | **crossplane-package-manager** | `Deployment` | [Crossplane](https://github.com/crossplane/crossplane) | CNCF | `Apache-2.0` |
| `real-0166.yaml` | **mlflow-tracking-server** | `Deployment` | [MLflow MLOps](https://github.com/mlflow/mlflow) | Linux Foundation | `Apache-2.0` |
| `real-0167.yaml` | **kubeflow-pipelines-api** | `Deployment` | [Kubeflow Pipelines](https://github.com/kubeflow/pipelines) | CNCF | `Apache-2.0` |
| `real-0168.yaml` | **katib-controller** | `Deployment` | [Kubeflow Katib](https://github.com/kubeflow/katib) | CNCF | `Apache-2.0` |
| `real-0169.yaml` | **airflow-scheduler** | `Deployment` | [Apache Airflow](https://github.com/apache/airflow) | Apache Software Foundation | `Apache-2.0` |
| `real-0170.yaml` | **airflow-webserver** | `Deployment` | [Apache Airflow](https://github.com/apache/airflow) | Apache Software Foundation | `Apache-2.0` |
| `real-0171.yaml` | **dapr-operator** | `Deployment` | [Dapr Distributed Application Runtime](https://github.com/dapr/dapr) | CNCF | `Apache-2.0` |
| `real-0172.yaml` | **dapr-sidecar-injector** | `Deployment` | [Dapr Distributed Application Runtime](https://github.com/dapr/dapr) | CNCF | `Apache-2.0` |
| `real-0173.yaml` | **knative-serving-activator** | `Deployment` | [Knative Serving](https://github.com/knative/serving) | CNCF | `Apache-2.0` |
| `real-0174.yaml` | **knative-autoscaler** | `Deployment` | [Knative Serving](https://github.com/knative/serving) | CNCF | `Apache-2.0` |
| `real-0175.yaml` | **metallb-speaker** | `DaemonSet` | [MetalLB Bare Metal Load Balancer](https://github.com/metallb/metallb) | CNCF | `Apache-2.0` |
| `real-0176.yaml` | **rook-ceph-operator** | `Deployment` | [Rook Ceph Storage](https://github.com/rook/rook) | CNCF | `Apache-2.0` |
| `real-0177.yaml` | **rook-ceph-mon** | `StatefulSet` | [Rook Ceph Storage](https://github.com/rook/rook) | CNCF | `Apache-2.0` |
| `real-0178.yaml` | **opensearch-cluster** | `StatefulSet` | [OpenSearch](https://github.com/opensearch-project/OpenSearch) | Apache Software Foundation | `Apache-2.0` |
| `real-0179.yaml` | **opensearch-dashboards** | `Deployment` | [OpenSearch Dashboards](https://github.com/opensearch-project/OpenSearch-Dashboards) | Apache Software Foundation | `Apache-2.0` |
| `real-0180.yaml` | **cassandra-datacenter-node** | `StatefulSet` | [Apache Cassandra](https://github.com/k8ssandra/k8ssandra-operator) | K8ssandra Community | `Apache-2.0` |
| `real-0181.yaml` | **owasp-juice-shop** | `Deployment` | [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | OWASP Foundation | `MIT` |
| `real-0182.yaml` | **damn-vulnerable-web-app** | `Deployment` | [DVWA (Damn Vulnerable Web App)](https://github.com/digininja/DVWA) | Vulnerabilities Lab | `GPL-3.0` |
| `real-0183.yaml` | **goat-metadata-ssrf** | `Deployment` | [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat) | Madhu Akula | `Apache-2.0` |
| `real-0184.yaml` | **goat-privileged-escape** | `Deployment` | [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat) | Madhu Akula | `Apache-2.0` |
| `real-0185.yaml` | **goat-dind-host-socket** | `Deployment` | [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat) | Madhu Akula | `Apache-2.0` |
| `real-0186.yaml` | **legacy-struts-backend** | `Deployment` | [Apache Struts Legacy Demo](https://github.com/vulhub/vulhub) | CVE Security Lab | `Apache-2.0` |
| `real-0187.yaml` | **legacy-log4shell-target** | `Deployment` | [Log4Shell CVE-2021-44228](https://github.com/vulhub/vulhub) | Vulhub Security Lab | `Apache-2.0` |
| `real-0188.yaml` | **unauthenticated-redis** | `Deployment` | [Unprotected In-Memory Cache](https://github.com/vulhub/vulhub) | CVE Security Lab | `BSD-3-Clause` |
| `real-0189.yaml` | **hardened-zero-trust-gateway** | `Deployment` | [Zero Trust Edge Proxy](https://github.com/GoogleCloudPlatform/microservices-demo) | Cloud Native Defense | `Apache-2.0` |
| `real-0190.yaml` | **chainguard-minimal-api** | `Deployment` | [Chainguard Hardened Microservice](https://github.com/chainguard-images/images) | Chainguard Images | `Apache-2.0` |
| `real-0191.yaml` | **crossplane-provider-aws** | `Deployment` | [Crossplane AWS Provider](https://github.com/crossplane-contrib/provider-aws) | Upbound / CNCF | `Apache-2.0` |
| `real-0192.yaml` | **kube-state-metrics** | `Deployment` | [Kube State Metrics](https://github.com/kubernetes/kube-state-metrics) | Kubernetes SIGs | `Apache-2.0` |
| `real-0193.yaml` | **node-local-dns** | `DaemonSet` | [Node Local DNS](https://github.com/kubernetes/dns) | Kubernetes SIGs | `Apache-2.0` |
| `real-0194.yaml` | **karpenter-autoscaler** | `Deployment` | [Karpenter Node Autoscaler](https://github.com/kubernetes-sigs/karpenter) | Kubernetes SIGs | `Apache-2.0` |
| `real-0195.yaml` | **argo-workflows-server** | `Deployment` | [Argo Workflows](https://github.com/argoproj/argo-workflows) | CNCF | `Apache-2.0` |
| `real-0196.yaml` | **argo-events-controller** | `Deployment` | [Argo Events](https://github.com/argoproj/argo-events) | CNCF | `Apache-2.0` |
| `real-0197.yaml` | **kube-vip-daemon** | `DaemonSet` | [Kube-VIP Virtual IP](https://github.com/kube-vip/kube-vip) | Kube-VIP Project | `Apache-2.0` |
| `real-0198.yaml` | **thanos-compact** | `StatefulSet` | [Thanos Metric Compactor](https://github.com/thanos-io/thanos) | CNCF | `Apache-2.0` |
| `real-0199.yaml` | **calico-typha-routing** | `Deployment` | [Calico CNI Typha](https://github.com/projectcalico/calico) | Project Calico | `Apache-2.0` |
| `real-0200.yaml` | **sealed-secrets-controller** | `Deployment` | [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets) | Bitnami / CNCF | `Apache-2.0` |
