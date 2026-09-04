# Kubernetes fixtures (roadmap item 22)

## Provenance

Every file here was **recorded from a real Kubernetes cluster**, through the command
`src/shared/kubernetes.ts` actually builds — section markers, `--request-timeout`,
column sets and all. Nothing is reconstructed from documentation. Where a case could
not be recorded, it is listed under "What could not be captured" below rather than
invented, which is the rule `tests/fixtures/docker/README.md` sets out and for the
same reason: a fixture written from documentation agrees with whatever the author
believed the format was.

### The cluster

A **three-node `kind` cluster** — one control-plane, two workers — created for this
item and torn down after:

```
kind create cluster --name spk8s --config kind.yaml   # 1 control-plane + 2 workers
```

| | |
|---|---|
| kubectl client | v1.33.2 (darwin/arm64) |
| server | v1.33.2, nodes on v1.33.1 |
| CNI | kindnet |
| storage | `local-path-provisioner` (kind's default `standard` StorageClass) |

Three nodes matter: a single-node `kind` cluster cannot produce a drain that has
anywhere to reschedule to, so every drain would look blocked for the wrong reason.

### The workloads, and what each one is for

Applied from one manifest into namespaces `shop` and `edge`:

| Object | Why |
|---|---|
| Deployment `shop/checkout`, **1 replica**, behind Service `checkout` | The sole-Ready-endpoint case. Draining its node takes the Service to zero endpoints, and ownership alone says the pod is "safe". |
| Deployment `shop/catalog`, **2 replicas**, behind Service `catalog` | Paired with the tight PDB below. |
| PDB `shop/catalog-tight`, `minAvailable: 2` over 2 pods | Produces a real `disruptionsAllowed: 0`. |
| Deployment `shop/search`, **3 replicas** | Paired with the loose PDB. |
| PDB `shop/search-loose`, `minAvailable: 1` over 3 pods | The case a drain may proceed through. |
| PDB `shop/tier-web-expr`, `matchExpressions: tier In (web, api)` | Two things at once: a selector this module cannot evaluate from a list read, and — see below — a second PDB over pods that already have one. |
| Bare Pod `shop/orphan-debug`, no `ownerReferences` | The catastrophic deletion: nothing recreates it. |
| DaemonSet `edge/log-shipper` | The pods a drain is supposed to skip. |
| PVC `shop/catalog-data`, 2Gi RWO | Capacity read, and a `Pending` PVC when nothing binds it. |
| Secret `shop/checkout-stripe` with keys `api-key`, `webhook-secret` | Existence-without-values. The values are strings invented for the recording — nothing real was ever in this cluster — and they exist **so that a test can assert they are absent from every fixture**. |
| ServiceAccount `shop/deployer` + Role `pod-reader` + RoleBinding | The RBAC identity every `forbidden` fixture was recorded as. |
| Ingress `shop/shop-public`, class `nginx`, TLS `shop-tls` | Host, path and TLS-secret reads. No ingress controller was installed, which is why `ADDRESS` is empty — that is a real state, not a truncation. |

### How the `forbidden` fixtures were made

The recording kubeconfig is cluster-admin, so every denial was produced by
**impersonation**:

```
kubectl --context kind-spk8s <verb> --as=system:serviceaccount:shop:deployer
```

`deployer` can `get`/`list`/`watch` pods in `shop` and nothing else. The `--as` flag
is the **only** difference from the shipped command; the section markers, the flags
and kubectl's wording are verbatim. The API server produces these denials itself, so
the sentences are real RBAC output, not a hand-written approximation of one.

## Files

| File | Recorded from |
|---|---|
| `cordon-ok.txt` | `buildK8sCordonCommand('spk8s-worker', 'cordon', 'kind-spk8s')`, against a schedulable node. |
| `cordon-already.txt` | The same command run a second time. kubectl says **`already cordoned`** and still exits 0 — a success that changed nothing. |
| `uncordon-ok.txt` | The uncordon of the same node, in the same session. |
| `cordon-notfound.txt` | The same command against a node name that does not exist. |
| `cordon-forbidden.txt` | The same command, impersonating `deployer`. Note the verb: kubectl needs **`get` on nodes** before it can patch one, so the denial names `get`, not `patch`. |

## What could not be captured

- **A multi-node drain in anger.** `kind` nodes are containers on one host; every
  drain here rescheduled onto a sibling container on the same machine. Nothing in
  these fixtures proves how a drain behaves when the remaining nodes cannot fit the
  evicted pods — the pods go `Pending` and the drain still reports success, and that
  path is untested against a real cluster.
- **Helm.** No `helm` binary was available on the recording machine, so the Helm
  release listing has only its **not-installed** path recorded. The parse of a real
  `helm list -A -o json` document is unproven.
- **A metrics server.** `kind` ships without one, so nothing here exercises
  `kubectl top` beyond the `no-metrics` path the existing tests already cover.
- **An ingress controller.** Nothing was installed, so `ADDRESS` on the Ingress is
  empty in every recording. An Ingress that has been given a load-balancer address
  is unproven.
