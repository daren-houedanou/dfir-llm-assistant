# Kubernetes en partant de Docker Compose

Ce guide part de la configuration Docker Compose (`deploy/docker-compose.yml`) et présente la même pile
dans Kubernetes (`deploy/k8s/`).

## 1. Le vocabulaire, traduit depuis Compose

| Dans Compose | Dans Kubernetes | Fichier du projet |
|---|---|---|
| un `service:` (ollama, litellm) | un **Deployment** qui gère des **Pods** (un Pod = un ou plusieurs conteneurs) | `base/ollama.yaml`, `base/litellm.yaml` |
| le nom DNS `ollama` entre conteneurs | un **Service** qui donne un nom et une IP stables aux Pods | `kind: Service` dans les mêmes fichiers |
| `volumes: ollama:` | un **PersistentVolumeClaim** (demande de disque) | `ollama-models` dans `base/ollama.yaml` |
| `ollama-pull` avec `restart: "no"` | un **Job** (tâche qui s'exécute une fois) | `ollama-pull-models` |
| `environment:` et `.env` | **ConfigMap** (config) et **Secret** (clés) | `configMapGenerator` dans `kustomization.yaml` |
| `networks: internal: true` | des **NetworkPolicies** (pare-feu entre Pods) | `base/networkpolicy.yaml` |
| `healthcheck:` | `readinessProbe` et `livenessProbe` | `base/litellm.yaml` |
| `docker compose up -d` | `kubectl apply -k <dossier>` | |
| `docker compose logs litellm` | `kubectl logs deploy/litellm` | |

**Kustomize** (le `-k`) assemble une **base** et des **overlays** (variantes). Ici la base est le
profil air-gapped (modèles locaux uniquement) et l'overlay `hybrid` ajoute les modèles cloud et la
sortie HTTPS de la passerelle. C'est l'équivalent de deux fichiers Compose superposés.

## 2. Essayer en local avec kind

[kind](https://kind.sigs.k8s.io/) crée un cluster Kubernetes dans Docker. Le modèle 7B demande environ 16 Go de RAM
(`llama3.2:3b` peut le remplacer dans `base/litellm-config.yaml` pour tester).

```bash
# Outils (ou simplement: nix develop, qui fournit kubectl et kustomize)
kind create cluster --name dfir

kubectl create namespace dfir-ai
kubectl -n dfir-ai create secret generic litellm-secrets --from-literal=master-key=sk-test
kubectl apply -k deploy/k8s/base

kubectl -n dfir-ai get pods -w                         # attendre Running / Completed
kubectl -n dfir-ai logs job/ollama-pull-models -f      # téléchargement des modèles

kubectl -n dfir-ai port-forward svc/litellm 4000:4000  # la passerelle sur localhost:4000
DFA_API_KEY=sk-test dfa models
```

Remarque : le réseau par défaut de kind n'applique pas les NetworkPolicies. Pour les voir
fonctionner, il faut installer Calico ou Cilium dans le cluster. Sur un vrai cluster, elles s'appliquent.

## 3. Choix de conception

- **Pourquoi 2 réplicas de LiteLLM mais 1 seul d'Ollama ?** La passerelle est sans état, on peut la
  dupliquer. Ollama a un disque en `ReadWriteOnce` et un GPU, on le met à l'échelle autrement
  (un Deployment par GPU ou vLLM).
- **Pourquoi `default-deny` ?** Tout est interdit puis on ouvre le strict nécessaire : Ollama ne
  parle qu'à LiteLLM et n'a aucune sortie. Les données d'enquête ne peuvent pas partir par erreur.
- **Pourquoi Pod Security `restricted` ?** Les conteneurs tournent sans root, sans privilèges et
  avec un profil seccomp. C'est la base attendue dans un CERT.
- **GPU** : décommenter `nvidia.com/gpu: 1` demande au scheduler un nœud avec GPU (NVIDIA device
  plugin installé).

## 4. Pour aller plus loin

1. Ajouter un `HorizontalPodAutoscaler` sur LiteLLM.
2. Remplacer Ollama par vLLM pour le débit en production.
3. Déployer avec Helm ou Argo CD (GitOps).
4. Exposer la passerelle via un Ingress avec TLS et authentification.
