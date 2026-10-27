# Real-World Kubernetes Container Manifest Dataset
## Source Attribution, Author Credits & License Catalog

> **Total Manifests Collected:** 115 authentic workloads  
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
