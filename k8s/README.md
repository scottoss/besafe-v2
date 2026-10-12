# BeSafe Network — Kubernetes Deployment & Sharding Architecture

This repository contains the decoupled microservices architecture for BeSafe Network:
1. **Web Dashboard & Main API** (`web-dashboard`)
2. **VRChat Bot API & Worker** (`vrchat-bot`)
3. **Discord Bot Gateway Service** (`discord-bot`)

---

## 🏗️ Architecture Overview

```
                        ┌────────────────────────────────────────┐
                        │      Ingress Controller (HTTPS)        │
                        └───────────────────┬────────────────────┘
                                            │
                                            ▼
                    ┌────────────────────────────────────────────────┐
                    │     Web Dashboard Deployment (Port 3000)       │
                    │   - Vite Static Frontend + Admin REST API      │
                    │   - Scalable 2-10 replicas via HPA             │
                    └───────────┬────────────────────────┬───────────┘
                                │                        │
               (HTTP API)       │                        │ (HTTP API / Shard RPC)
                                ▼                        ▼
    ┌───────────────────────────────────┐    ┌──────────────────────────────────┐
    │    VRChat Bot API & Worker        │    │    Discord Bot StatefulSet       │
    │         (Port 3001)               │    │          (Port 3002)             │
    │  - 2FA Auth & Session Pool        │    │  - StatefulSet with Pod Ordinals │
    │  - Group Moderation & Bans        │    │    discord-bot-0  -> Shard 0/4   │
    │  - Group Partition Sharding       │    │    discord-bot-1  -> Shard 1/4   │
    │  - Display Name Sync Worker       │    │    discord-bot-2  -> Shard 2/4   │
    └─────────────────┬─────────────────┘    │    discord-bot-3  -> Shard 3/4   │
                      │                      └─────────────────┬────────────────┘
                      ▼                                        ▼
             ┌────────────────────────────────────────────────────────┐
             │            Shared Database (MongoDB Cluster)           │
             └────────────────────────────────────────────────────────┘
```

---

## ⚡ Discord Sharding in Kubernetes

Discord requires bots serving large numbers of guilds to connect via **Gateway Sharding**.

### How StatefulSet Sharding Works:
Instead of running an in-process sharder inside a single huge container, Kubernetes **StatefulSets** are used:
1. The StatefulSet `discord-bot` is configured with `replicas: 4` (or any target shard count).
2. Kubernetes generates pods with stable ordinal names:
   - Pod `discord-bot-0` extracts `SHARD_ID=0`
   - Pod `discord-bot-1` extracts `SHARD_ID=1`
   - Pod `discord-bot-2` extracts `SHARD_ID=2`
   - Pod `discord-bot-3` extracts `SHARD_ID=3`
3. `services/discord-bot/k8s-sharding.ts` automatically parses the hostname and configures `discord.js`:
   ```ts
   const client = new Client({
     shards: [shardId],
     shardCount: totalShards,
     intents: [...]
   });
   ```
4. **Key Advantages**:
   - **Zero downtime re-sharding**: Pods are scheduled across multiple Kubernetes worker nodes.
   - **Fault Isolation**: If Shard 1 crashes due to a voice stream error, Shards 0, 2, and 3 continue operating with zero disruption.
   - **Global Command Registration**: Only Shard 0 registers slash commands globally to avoid rate-limiting conflicts with the Discord API.

---

## 🥽 VRChat Bot Partitioning

VRChat limits bot accounts to ~100 groups each and enforces strict API rate limits.
To scale across hundreds of groups:
- The VRChat Bot service supports horizontal partitioning:
  `VRC_INSTANCE_ID` and `VRC_TOTAL_INSTANCES`.
- Each instance scans only its deterministic partition of the groups:
  ```ts
  assignedGroups = allGroups.filter((_, idx) => idx % totalInstances === instanceId);
  ```
- Exposes an internal HTTP REST API on port `3001` (`/api/vrchat/ban`, `/api/vrchat/unban`, `/api/vrchat/scan`, `/api/vrchat/status`), allowing the Web Dashboard to trigger VRChat enforcement without directly making external VRChat requests.

---

## 📦 Building Container Images

### Using Dockerfiles:
```bash
# 1. Build Web Dashboard image
docker build -t ghcr.io/besafe-network/web-dashboard:latest -f docker/Dockerfile.dashboard .

# 2. Build VRChat Bot image
docker build -t ghcr.io/besafe-network/vrchat-bot:latest -f docker/Dockerfile.vrchat .

# 3. Build Discord Bot image
docker build -t ghcr.io/besafe-network/discord-bot:latest -f docker/Dockerfile.discord .

# Push images to your container registry
docker push ghcr.io/besafe-network/web-dashboard:latest
docker push ghcr.io/besafe-network/vrchat-bot:latest
docker push ghcr.io/besafe-network/discord-bot:latest
```

---

## 🚀 Deploying to Kubernetes

### Step 1: Configure Secrets
Edit the `Secret` resource in `k8s/kubernetes.yaml` (or `kubernetes.yaml`) with your production credentials (`MONGO_URI`, `DISCORD_TOKEN`, `JWT_SECRET`).

### Step 2: Apply the Combined Manifest
Deploy the entire stack (Namespace, ConfigMap, Secrets, Services, Deployments, StatefulSet, Ingress, and HPAs) in a single command:
```bash
# Apply from the repository root:
kubectl apply -f kubernetes.yaml

# Or apply from the k8s directory:
kubectl apply -f k8s/kubernetes.yaml
```

### Step 3: Verify Pods & Shards
```bash
# Check running pods
kubectl get pods -n besafe-network

# Expected Output:
# NAME                             READY   STATUS    RESTARTS   AGE
# discord-bot-0                    1/1     Running   0          2m
# discord-bot-1                    1/1     Running   0          2m
# discord-bot-2                    1/1     Running   0          2m
# discord-bot-3                    1/1     Running   0          2m
# vrchat-bot-7b49cf5c77-x9k12      1/1     Running   0          2m
# web-dashboard-5f9b4c8d7b-2plwq   1/1     Running   0          2m
# web-dashboard-5f9b4c8d7b-7q9zt   1/1     Running   0          2m
```

### Step 4: Inspect Shard Logs
```bash
# Inspect Shard 0 logs
kubectl logs -n besafe-network discord-bot-0

# Inspect Shard 2 logs
kubectl logs -n besafe-network discord-bot-2
```

---

## 🧪 Local Multi-Service Development (Docker Compose)

To run all 3 services locally connected to MongoDB:
```bash
# Export your discord token
export DISCORD_TOKEN="your_token_here"

# Start the full stack
docker compose up --build
```
- Web Dashboard: `http://localhost:3000`
- VRChat Bot API: `http://localhost:3001`
- Discord Bot API: `http://localhost:3002`
- MongoDB: `mongodb://localhost:27017/besafe`

---

## 🛠️ Service Health Endpoints

| Service | Liveness Probe | Readiness Probe | Telemetry Endpoint |
|---|---|---|---|
| **Web Dashboard** | `GET /healthz` | `GET /readyz` | `GET /api/services/status` |
| **VRChat Bot** | `GET /healthz` | `GET /readyz` | `GET /api/vrchat/status` |
| **Discord Bot** | `GET /healthz` | `GET /readyz` | `GET /api/discord/status` |
