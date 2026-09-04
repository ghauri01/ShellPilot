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

### Drain preflights

Each of these is one run of `buildK8sDrainPreflightCommand(node, 'kind-spk8s')` — four
kubectl calls in one shell command, section markers included.

| File | Node, and what makes it interesting |
|---|---|
| `preflight-blocked.txt` | `spk8s-worker`, holding four separate blockers at once: a bare pod, a pod with **two** emptyDir volumes, a `disruptionsAllowed: 0` budget over `catalog`, and the `matchExpressions` budget nothing can evaluate. |
| `preflight-sole-endpoint.txt` | `spk8s-worker2`, holding the only Ready endpoint of Service `shop/checkout`. |
| `preflight-clear.txt` | `spk8s-worker` after the blockers were removed and `checkout` was scaled to two. The one recording where a drain may proceed. |
| `preflight-pdb-denied.txt` | **The important one.** Recorded as a ServiceAccount with cluster-wide `get`/`list` on pods, nodes and endpointslices and **nothing on `poddisruptionbudgets`**. Three blocks answer with real data and the fourth is a Forbidden line — which is what makes "an empty budget list" and "a budget list I was not allowed to read" distinguishable at all. |
| `preflight-forbidden.txt` | The same command as `deployer`, who can read none of the four. |

### Drains

Each is one run of `buildK8sDrainCommand(node, 'kind-spk8s')`.

| File | What happened |
|---|---|
| `drain-ok.txt` | Two pods evicted, `node/spk8s-worker drained`. Note the node is left **`Ready,SchedulingDisabled`** — kubectl does not uncordon afterwards. |
| `drain-blocked-by-pdb.txt` | The recording that shaped the result type. Five pods were attempted, **three were evicted**, and two `catalog` pods hit `Cannot evict pod as it would violate the pod's disruption budget.` and were retried every five seconds until `global timeout reached: 2m0s`. A blocked drain is **not** a no-op. It also contains the case that corrected the parser: `search-698cd569f8-hhqrl` was rejected by the budget once and then evicted eight seconds later, so a rejection is not the same as a pod the budget is still holding. |
| `drain-two-pdbs.txt` | **The trap documentation would not have shown.** With two PDBs overlapping one pod — one on `matchLabels: {app: catalog}`, one on `matchExpressions: tier In (web, api)` — the API server answers `This pod has more than one PodDisruptionBudget, which the eviction subresource does not support.` *regardless of what either budget allows*. Both budgets had disruptions to spare. Nothing was evicted. |
| `drain-bare-pod.txt` | The refusal on a pod with no controller, with kubectl's real doubled wording: `cannot delete cannot delete Pods that declare no controller`. The node was cordoned **before** the refusal, which the read-back shows. |

### Execs

Each is one run of `buildK8sExecCommand(...)` against a two-container `busybox:1.36`
pod (`shop/toolbox`), except where noted.

| File | What it shows |
|---|---|
| `exec-ok.txt` | `echo "it's $HOME and \`date -u +%Y\` and 'quoted'"; id; hostname` in the `shell` container. `$HOME` and the backticks were expanded **inside the container**, which is the correct semantics and the reason the command is quoted exactly once on the way out. |
| `exec-silent.txt` | `touch /tmp/sp-probe`. Prints nothing and worked — so for exec, unlike a cordon, an empty answer is a success. |
| `exec-nonzero.txt` | `cat /nope/missing` in the `sidecar` container. Two lines, **neither of them a kubectl error**: the program's own stderr and kubectl's `command terminated with exit code 1`. A successful exec of a failing command. |
| `exec-no-shell.txt` | The same command against a `registry.k8s.io/pause` container, which is what a distroless image looks like from here: `OCI runtime exec failed … stat /bin/sh: no such file or directory`. |
| `exec-forbidden.txt` | Impersonating `deployer`, who can list pods in `shop`. The denial names **`pods/exec`**, a different subresource from `pods` — which is the RBAC point in one sentence. |

Two bugs were found by recording these rather than reasoning about them, and both
are asserted in `tests/kubernetesExec.test.ts`:

1. The shared `call()` helper appends `--request-timeout=10s` to the **end** of the
   argument list. Everything after `--` belongs to the container, so the flag
   arrived inside the pod as `sh`'s `$0`.
2. Quoting the command **twice** — once for the SSH shell, once "for the container's
   shell" — is wrong. kubectl hands `-c <arg>` to the container as a single argv
   element with no shell in between, so the second layer is a literal pair of quote
   characters. The recorded failure was
   `line 0: echo "it's $HOME and \`date\` and 'quoted'"; id: not found`.

### The cheap reads

| File | Recorded from |
|---|---|
| `resources.txt` | One run of `buildK8sResourcesCommand('kind-spk8s')` across all namespaces: PVCs, Ingresses, RoleBindings, ClusterRoleBindings and the secret listing. It contains the recording cluster's real `shop/checkout-stripe` secret row — **and `tests/kubernetesReads.test.ts` asserts that neither planted value appears in it, raw or base64**. The PVC in it is `Pending` with a 2Gi request and no capacity, which is what a `WaitForFirstConsumer` StorageClass looks like when nothing has mounted the claim. |
| `resources-forbidden.txt` | The same command as `deployer`. All five blocks denied. |
| `resources-crb-denied.txt` | The same command as a ServiceAccount granted `rolebindings`, `persistentvolumeclaims` and `ingresses` and **not** `clusterrolebindings` or `secrets`. The case that decided the RBAC merge: a merge that dropped the failed half would have shown a namespace's bindings and silently omitted the `cluster-admin` grant. |
| `api-scan.txt` | `buildK8sApiScanCommand('kind-spk8s')`. Note that the client is **v1.33.2** and the API server is **v1.33.1** — the scan reads the server's, and the test asserts both. A 1.33 server serves nothing in the deprecation table, which is the correct and uninteresting answer; the interesting half is `notChecked`. |
| `helm-missing.txt` | `buildK8sHelmListCommand('kind-spk8s')` on a machine with no helm. |

Recording these found a bug of exactly the class this module exists to prevent: the
first PVC parser tested `fields >= 8` and validated the first two as RFC 1123 names,
and a real `Error from server (Forbidden): persistentvolumeclaims is forbidden: …`
sentence passes both — `Error` is a valid name, so is `from`, and the sentence has
far more than eight tokens. The denial parsed as a PersistentVolumeClaim called
`from` in a namespace called `Error`, and the read reported OK. A PVC row is now
recognised by its `Bound|Pending|Lost` phase, the way an event row is recognised by
its type.

## What could not be captured

- **A multi-node drain in anger.** `kind` nodes are containers on one host; every
  drain here rescheduled onto a sibling container on the same machine, and the
  cluster was never under real resource pressure. Nothing in these fixtures proves
  how a drain behaves when the remaining nodes **cannot fit** the evicted pods: the
  replacements go `Pending`, the eviction still succeeds, and `kubectl drain` still
  reports the node drained. That path needs a real multi-node cluster with real
  requests and limits, and it is untested.
- **A drain of a NotReady node.** `planK8sDrain` carries a caveat about a kubelet
  that never confirms the deletions, and that caveat is reasoned rather than
  recorded — every node in these recordings was `Ready`.
- **A StatefulSet drain.** Everything here is a Deployment or a DaemonSet, so
  nothing exercises a pod with a bound `ReadWriteOnce` PersistentVolume that cannot
  follow it to another node.
- **Helm.** No `helm` binary was available on the recording machine, so the Helm
  release listing has only its **not-installed** path recorded. The parse of a real
  `helm list -A -o json` document is unproven.
- **A metrics server.** `kind` ships without one, so nothing here exercises
  `kubectl top` beyond the `no-metrics` path the existing tests already cover.
- **A pod whose container runs as a non-root user.** `busybox` runs as uid 0, so
  `exec-ok.txt` shows `uid=0(root)`. Nothing here proves what an exec looks like
  under a `runAsNonRoot` securityContext or a read-only root filesystem.
- **An ingress controller.** Nothing was installed, so `ADDRESS` on the Ingress is
  empty in every recording. An Ingress that has been given a load-balancer address
  is unproven.
