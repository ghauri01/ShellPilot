import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import {
  assessK8sDrain,
  buildK8sDrainCommand,
  buildK8sDrainPreflightCommand,
  parseK8sDrainPreflight,
  parseK8sDrainResult,
  planK8sDrain,
  K8S_DRAIN_TIMEOUT_SECONDS,
  type K8sDrainAssessment,
  type K8sDrainBlockerKind,
  type K8sDrainPod
} from '../src/shared/kubernetes'
import { KubernetesReader } from '../src/main/services/kubernetes'

// Roadmap item 22, part two: the drain.
//
// Every fixture replayed here was recorded from a real three-node `kind`
// cluster on Kubernetes v1.33 through the command this module actually builds.
// tests/fixtures/k8s/README.md says which command produced which file, how the
// Forbidden ones were made, and — importantly — what could not be captured.
const fixture = (name: string): string =>
  readFileSync(join(__dirname, 'fixtures', 'k8s', name), 'utf8')

const assess = (name: string, node: string): K8sDrainAssessment =>
  parseK8sDrainPreflight(node, fixture(name), 0)

const kinds = (a: K8sDrainAssessment): K8sDrainBlockerKind[] =>
  a.blockers.map((b) => b.kind)

const named = (a: K8sDrainAssessment, kind: K8sDrainBlockerKind): string[] =>
  a.blockers.filter((b) => b.kind === kind).map((b) => `${b.namespace}/${b.subject}`)

const pods = (a: K8sDrainAssessment): string[] =>
  a.evictable.map((p: K8sDrainPod) => `${p.namespace}/${p.name}`)

describe('the preflight reads all four things in one round trip', () => {
  const cmd = buildK8sDrainPreflightCommand('spk8s-worker', 'kind-spk8s')

  it('asks for the node, the pods on it, every PDB and every EndpointSlice', () => {
    expect(cmd).toContain('===SHELLPILOT-DNODE===')
    expect(cmd).toContain('===SHELLPILOT-DPODS===')
    expect(cmd).toContain('===SHELLPILOT-DPDB===')
    expect(cmd).toContain('===SHELLPILOT-DEPS===')
    expect(cmd).toContain('--field-selector spec.nodeName=spk8s-worker')
    expect(cmd).toContain('get poddisruptionbudgets --all-namespaces')
  })

  it('reads EndpointSlices and never v1 Endpoints', () => {
    // On the recording cluster (v1.33) `kubectl get endpoints` prints
    //   Warning: v1 Endpoints is deprecated in v1.33+; use discovery.k8s.io/v1 EndpointSlice
    // onto stderr, which every builder in this file redirects into the data
    // block — so the deprecated read would put a warning line where rows go.
    expect(cmd).toContain('get endpointslices --all-namespaces')
    expect(cmd).not.toContain('get endpoints ')
  })

  it('pairs each endpoint with its own readiness flag inside one range', () => {
    // The alignment hazard. Two flat `[*]` lists are joined independently, and
    // `default/kubernetes` has a Ready endpoint with NO targetRef — which
    // shortens the pod list by one and shifts every readiness flag after it
    // onto the wrong pod. The nested range makes that impossible.
    expect(cmd).toContain('{range .endpoints[*]}{.targetRef.name}{"="}{.conditions.ready}')
  })

  it('reads maps as jsonpath, never as custom-columns', () => {
    // kubectl renders a label map in custom-columns as Go's `map[a:1 b:2]`,
    // spaces and all, which no column splitter can take apart. jsonpath prints
    // compact JSON.
    expect(cmd).toContain('{.metadata.labels}')
    expect(cmd).not.toContain('custom-columns')
  })

  it('bounds every call, and refuses an unsafe node name', () => {
    expect(cmd.match(/--request-timeout=10s/g) ?? []).toHaveLength(4)
    expect(() => buildK8sDrainPreflightCommand('worker; id')).toThrow(/invalid node name/)
  })
})

describe('what the preflight found on a real node', () => {
  const a = assess('preflight-blocked.txt', 'spk8s-worker')

  it('sets DaemonSet pods aside instead of counting them as work', () => {
    // `--ignore-daemonsets` is passed, so these are not moved and must not
    // appear in the "N pods move" sentence.
    expect(a.daemonSetPods.map((p) => p.name).sort()).toEqual([
      'kindnet-wzkbx',
      'kube-proxy-c979n',
      'log-shipper-c2hkg'
    ])
    expect(pods(a).sort()).toEqual([
      'edge/scratch-cache',
      'shop/catalog-78f5dff949-bff58',
      'shop/orphan-debug'
    ])
  })

  it('refuses on a pod nothing owns', () => {
    expect(named(a, 'bare-pod')).toContain('shop/orphan-debug')
    expect(
      a.blockers.find((b) => b.subject === 'orphan-debug')?.detail
    ).toContain('nothing recreates it')
  })

  it('refuses on a PodDisruptionBudget with no disruptions left', () => {
    // `catalog-tight` is minAvailable 2 over 2 pods, so the API server reported
    // `disruptionsAllowed: 0`. Draining this node would have kubectl retry the
    // eviction every five seconds until the timeout.
    expect(named(a, 'pdb-exhausted')).toEqual(['shop/catalog-78f5dff949-bff58'])
    expect(a.blockers.find((b) => b.kind === 'pdb-exhausted')?.detail).toContain(
      'PodDisruptionBudget catalog-tight allows 0 disruptions right now'
    )
  })

  it('refuses on a selector it cannot evaluate rather than skipping it', () => {
    // `tier-web-expr` selects on matchExpressions. A list read cannot evaluate
    // those, and an unevaluated budget is an unknown — which in this module
    // never renders as "there is no budget".
    expect(named(a, 'pdb-unreadable-selector')).toEqual(['shop/tier-web-expr'])
    expect(a.blockers.find((b) => b.kind === 'pdb-unreadable-selector')?.detail).toContain(
      'an unknown budget is not a permission'
    )
  })

  it('refuses on an emptyDir rather than passing --delete-emptydir-data', () => {
    expect(named(a, 'local-storage')).toEqual(['edge/scratch-cache'])
    // Two volumes on that pod. jsonpath joins repeated matches with a SPACE —
    // the recorded line reads `{} {"sizeLimit":"1Gi"}` — so a parser that split
    // on whitespace would report one.
    expect(a.evictable.find((p) => p.name === 'scratch-cache')?.emptyDirs).toBe(2)
  })

  it('is not safe, and says so in the plan rather than in a louder dialog', () => {
    expect(a.safe).toBe(false)
    const plan = planK8sDrain(a)
    expect(plan.refusals.length).toBe(a.blockers.length)
    expect(plan.refusals.join(' ')).toContain('shop/orphan-debug')
  })
})

describe('the only Ready endpoint behind a Service', () => {
  // The case the file's original refusal named as the reason pod deletion did
  // not ship: `checkout` had one replica, so ownership says the pod comes back
  // and the EndpointSlice says the Service has nowhere to send traffic
  // meanwhile.
  const a = assess('preflight-sole-endpoint.txt', 'spk8s-worker2')

  it('blocks the one-replica pod', () => {
    expect(named(a, 'sole-ready-endpoint')).toEqual(['shop/checkout-6c99dcd7bb-29rw4'])
    expect(a.blockers.find((b) => b.kind === 'sole-ready-endpoint')?.detail).toContain(
      'the only Ready endpoint behind Service checkout'
    )
  })

  it('does not block a pod whose Service has another Ready endpoint', () => {
    // `catalog` has two Ready endpoints and only one of them is on this node.
    // Blocking it would make every drain of every multi-replica service
    // impossible, which is how a safety check gets turned off.
    expect(named(a, 'sole-ready-endpoint')).not.toContain('shop/catalog-78f5dff949-t6lmx')
  })

  it('counts a Ready endpoint that has no pod behind it', () => {
    // `default/kubernetes` is a Ready endpoint with no targetRef at all. A
    // Service kept up by one of those is not left with nothing when a pod goes.
    const single = assessK8sDrain('n1', {
      nodeState: { ok: true, items: [{ name: 'n1', unschedulable: false, ready: 'True' }] },
      pods: {
        ok: true,
        items: [
          {
            namespace: 'shop',
            name: 'api-1',
            ownerKind: 'ReplicaSet',
            ownerName: 'api',
            phase: 'Running',
            mirror: false,
            labels: {},
            emptyDirs: 0
          }
        ]
      },
      pdbs: { ok: true, items: [] },
      endpoints: {
        ok: true,
        items: [{ namespace: 'shop', service: 'api', readyPods: ['api-1'], readyWithoutPod: 1 }]
      }
    })
    expect(kinds(single)).not.toContain('sole-ready-endpoint')
  })
})

describe('a pod under two PodDisruptionBudgets cannot be evicted at all', () => {
  // Found by running it against a real cluster, not from documentation. The API
  // server answers
  //   This pod has more than one PodDisruptionBudget, which the eviction
  //   subresource does not support.
  // whatever either budget allows — so a check that only looked at
  // disruptionsAllowed would have cleared a drain that cannot make progress.
  const twoBudgets = (allowed: number): K8sDrainAssessment =>
    assessK8sDrain('n1', {
      nodeState: { ok: true, items: [{ name: 'n1', unschedulable: false, ready: 'True' }] },
      pods: {
        ok: true,
        items: [
          {
            namespace: 'shop',
            name: 'catalog-1',
            ownerKind: 'ReplicaSet',
            ownerName: 'catalog',
            phase: 'Running',
            mirror: false,
            labels: { app: 'catalog', tier: 'web' },
            emptyDirs: 0
          }
        ]
      },
      pdbs: {
        ok: true,
        items: [
          {
            namespace: 'shop',
            name: 'catalog-tight',
            disruptionsAllowed: allowed,
            currentHealthy: 3,
            desiredHealthy: 1,
            expectedPods: 3,
            matchLabels: { app: 'catalog' },
            hasMatchExpressions: false
          },
          {
            namespace: 'shop',
            name: 'tier-web',
            disruptionsAllowed: allowed,
            currentHealthy: 6,
            desiredHealthy: 1,
            expectedPods: 6,
            matchLabels: { tier: 'web' },
            hasMatchExpressions: false
          }
        ]
      },
      endpoints: { ok: true, items: [] }
    })

  it('blocks even when both budgets have disruptions to spare', () => {
    const a = twoBudgets(5)
    expect(kinds(a)).toContain('pdb-multiple')
    expect(a.blockers.find((b) => b.kind === 'pdb-multiple')?.detail).toContain(
      'covered by 2 PodDisruptionBudgets (catalog-tight, tier-web)'
    )
    expect(a.safe).toBe(false)
  })

  it('replays the real drain that proved it', () => {
    const r = parseK8sDrainResult('spk8s-worker', fixture('drain-two-pdbs.txt'), 1)
    expect(r.ok).toBe(false)
    expect(r.output).toContain(
      'This pod has more than one PodDisruptionBudget, which the eviction subresource does not support.'
    )
    // Nothing was evicted: the eviction subresource refused outright rather
    // than retrying, so this is the one blocked drain that IS all-or-nothing.
    expect(r.evicted).toEqual([])
    expect(r.partial).toBe(false)
  })
})

describe('an empty selector is not an empty budget', () => {
  it('treats a PDB with no selector fields as covering the whole namespace', () => {
    // The single most dangerous misreading available here. In Kubernetes a PDB
    // with `selector: {}` matches EVERY pod in its namespace. Reading empty as
    // "matches nothing" would silently clear a drain against a budget covering
    // everything.
    const a = assessK8sDrain('n1', {
      nodeState: { ok: true, items: [{ name: 'n1', unschedulable: false, ready: 'True' }] },
      pods: {
        ok: true,
        items: [
          {
            namespace: 'shop',
            name: 'anything',
            ownerKind: 'ReplicaSet',
            ownerName: 'r',
            phase: 'Running',
            mirror: false,
            labels: { totally: 'unrelated' },
            emptyDirs: 0
          }
        ]
      },
      pdbs: {
        ok: true,
        items: [
          {
            namespace: 'shop',
            name: 'namespace-wide',
            disruptionsAllowed: 0,
            currentHealthy: 1,
            desiredHealthy: 1,
            expectedPods: 1,
            matchLabels: {},
            hasMatchExpressions: false
          }
        ]
      },
      endpoints: { ok: true, items: [] }
    })
    expect(named(a, 'pdb-exhausted')).toEqual(['shop/anything'])
  })
})

describe('a Forbidden list is not an empty list', () => {
  it('refuses a drain when the PDB read alone was denied', () => {
    // The honesty rule, in its sharpest form. This fixture is a real
    // partially-denied read: pods, node and EndpointSlices all answered, and
    // `poddisruptionbudgets` came back Forbidden. An empty budget list from a
    // denied read is character-for-character the same as a cluster that has no
    // budgets, and only the carried failure tells them apart.
    const a = assess('preflight-pdb-denied.txt', 'spk8s-worker')
    expect(a.evictable.length).toBeGreaterThan(0)
    expect(a.unchecked.map((u) => u.read)).toEqual(['pdbs'])
    expect(a.unchecked[0].reason).toBe('forbidden')
    expect(a.unchecked[0].detail).toContain(
      'cannot list resource "poddisruptionbudgets" in API group "policy"'
    )
    expect(a.unchecked[0].meaning).toContain(
      'an empty budget list from a denied read looks exactly like a cluster that has none'
    )
    expect(a.safe).toBe(false)
  })

  it('a denied PDB read is refused even though it produces no blockers at all', () => {
    // The reason `safe` is not `blockers.length === 0`. This read found no
    // budgets — because it was not allowed to look — so a blocker-count check
    // would have cleared it.
    const a = assess('preflight-pdb-denied.txt', 'spk8s-worker')
    expect(kinds(a)).not.toContain('pdb-exhausted')
    expect(kinds(a)).not.toContain('pdb-multiple')
    expect(a.safe).toBe(false)
    expect(planK8sDrain(a).refusals.join(' ')).toContain('the pdbs read did not answer')
  })

  it('carries all four denials when the token can read nothing', () => {
    const a = assess('preflight-forbidden.txt', 'spk8s-worker')
    expect(a.unchecked.map((u) => u.read).sort()).toEqual(['endpoints', 'node', 'pdbs', 'pods'])
    expect(a.unchecked.every((u) => u.reason === 'forbidden')).toBe(true)
    // And not "this node has nothing on it".
    expect(a.evictable).toEqual([])
    expect(a.safe).toBe(false)
  })
})

describe('a node that can be drained', () => {
  const a = assess('preflight-clear.txt', 'spk8s-worker')

  it('is safe when every read answered and nothing blocks', () => {
    expect(a.unchecked).toEqual([])
    expect(a.blockers).toEqual([])
    expect(a.safe).toBe(true)
    expect(pods(a).sort()).toEqual([
      'shop/catalog-78f5dff949-bff58',
      'shop/checkout-6c99dcd7bb-n2bfx'
    ])
  })

  it('leaves a PDB with disruptions to spare alone', () => {
    // `search-loose` was present with disruptionsAllowed 2 and covered nothing
    // on this node. A check that blocked on the mere existence of a PDB would
    // never allow a drain anywhere.
    expect(a.blockers).toEqual([])
  })

  it('still demands a typed word', () => {
    const plan = planK8sDrain(a)
    expect(plan.confirmation).toEqual({ kind: 'type-to-confirm', phrase: 'DRAIN' })
    expect(plan.risk).toBe('destructive')
    expect(plan.refusals).toEqual([])
  })

  it('says the drain is not all-or-nothing, and does not uncordon afterwards', () => {
    const plan = planK8sDrain(a)
    expect(plan.caveats.join(' ')).toContain('does not uncordon it afterwards')
    expect(plan.caveats.join(' ')).toContain('is not all-or-nothing')
  })
})

describe('the drain command', () => {
  const cmd = buildK8sDrainCommand('spk8s-worker', 'kind-spk8s')

  it('never passes the two flags that destroy what blocked it', () => {
    expect(cmd).toContain('--force=false')
    expect(cmd).toContain('--delete-emptydir-data=false')
    expect(cmd).not.toContain('--force ')
    expect(cmd).not.toMatch(/--delete-emptydir-data(?!=false)/)
  })

  it('bounds the eviction retry loop', () => {
    // Without --timeout a drain blocked by a budget retries every five seconds
    // forever, holding the SSH exec open past every timeout this app has.
    expect(cmd).toContain(`--timeout=${K8S_DRAIN_TIMEOUT_SECONDS}s`)
    expect(K8S_DRAIN_TIMEOUT_SECONDS).toBe(120)
  })

  it('ignores DaemonSets, and reads the node back', () => {
    expect(cmd).toContain('--ignore-daemonsets')
    expect(cmd).toContain('get node spk8s-worker --no-headers')
  })
})

describe('what a real drain did', () => {
  it('reads a clean drain as done', () => {
    const r = parseK8sDrainResult('spk8s-worker', fixture('drain-ok.txt'), 0)
    expect(r.ok).toBe(true)
    expect(r.evicted.sort()).toEqual([
      'catalog-78f5dff949-bff58',
      'checkout-6c99dcd7bb-n2bfx'
    ])
    expect(r.pending).toEqual([])
    expect(r.partial).toBe(false)
    // The node is left cordoned. This is kubectl's behaviour and the panel must
    // show it, or an operator "cancels" a drain and leaves a node out of the
    // fleet.
    expect(r.node_status).toContain('Ready,SchedulingDisabled')
  })

  it('reads a budget-blocked drain as PARTIAL, not as a no-op', () => {
    // The recording that forced the field: three `search` pods were evicted and
    // then two `catalog` pods hit the budget and were retried until the 2m
    // timeout. Reporting this as a plain failure tells the operator the node is
    // untouched, which is how somebody reboots it.
    const r = parseK8sDrainResult('spk8s-worker', fixture('drain-blocked-by-pdb.txt'), 1)
    expect(r.ok).toBe(false)
    expect(r.partial).toBe(true)
    expect(r.evicted.sort()).toEqual([
      'search-698cd569f8-hhqrl',
      'search-698cd569f8-rh2df',
      'search-698cd569f8-sknhg'
    ])
    // `search-698cd569f8-hhqrl` was rejected by the budget once and then
    // evicted on a later retry. It is not in this list, because a pod the
    // budget let go of is not a pod the budget is holding.
    expect(r.pdbRejected.sort()).toEqual([
      'catalog-58dbc7bbbf-7m89p',
      'catalog-58dbc7bbbf-7pkxl'
    ])
    expect(r.output).toContain(
      'error when evicting pods/"search-698cd569f8-hhqrl" -n "shop" (will retry after 5s)'
    )
    expect(r.pending.sort()).toEqual([
      'catalog-58dbc7bbbf-7m89p',
      'catalog-58dbc7bbbf-7pkxl'
    ])
    expect(r.output).toContain("Cannot evict pod as it would violate the pod's disruption budget.")
  })

  it('reads kubectl’s bare-pod refusal, doubled wording and all', () => {
    const r = parseK8sDrainResult('spk8s-worker', fixture('drain-bare-pod.txt'), 1)
    expect(r.ok).toBe(false)
    expect(r.evicted).toEqual([])
    // kubectl really does say "cannot delete cannot delete" — recorded, not a
    // typo here.
    expect(r.output).toContain(
      'cannot delete cannot delete Pods that declare no controller (use --force to override): shop/orphan-debug'
    )
    // And the node was cordoned before the refusal, which the read-back shows.
    expect(r.node_status).toContain('SchedulingDisabled')
  })

  it('does not read a pending-pod line as an eviction', () => {
    // kubectl lists still-pending pods as bare `pod/<name>` lines with no verb
    // after them, right next to `pod/<name> evicted`. Reading those as
    // successes would report a stuck drain as a finished one.
    const r = parseK8sDrainResult('spk8s-worker', fixture('drain-two-pdbs.txt'), 1)
    expect(r.evicted).toEqual([])
  })
})

describe('the drain refuses before it runs, not after', () => {
  const cfg = {}
  const reader = (
    reply: (command: string) => { ok: boolean; code?: number | null; stdout?: string }
  ): { reader: KubernetesReader; sent: string[] } => {
    const sent: string[] = []
    return {
      sent,
      reader: new KubernetesReader({
        exec: async (_c, command) => {
          sent.push(command)
          return reply(command)
        }
      })
    }
  }

  it('never builds a drain command when the preflight says no', async () => {
    const { reader: r, sent } = reader(() => ({
      ok: true,
      code: 0,
      stdout: fixture('preflight-blocked.txt')
    }))
    const out = await r.drain(cfg, 'spk8s-worker', 'kind-spk8s', true)
    expect(out.ok).toBe(false)
    expect(out.detail).toContain('refusing to drain spk8s-worker')
    expect(out.detail).toContain('shop/orphan-debug')
    // Exactly one command reached the host, and it was the preflight.
    expect(sent).toHaveLength(1)
    expect(sent[0]).toContain('===SHELLPILOT-DPDB===')
    expect(sent.join(' ')).not.toContain('drain spk8s-worker')
  })

  it('re-takes the preflight itself rather than trusting the caller', async () => {
    // There is no assessment argument on this method at all, which is the point:
    // a plan that crossed IPC is a structured-clone value with no runtime type,
    // and it is stale by construction.
    const { reader: r, sent } = reader((command) => ({
      ok: true,
      code: 0,
      stdout: command.includes('DPDB') ? fixture('preflight-clear.txt') : fixture('drain-ok.txt')
    }))
    const out = await r.drain(cfg, 'spk8s-worker', 'kind-spk8s', true)
    expect(out.ok).toBe(true)
    expect(sent).toHaveLength(2)
    expect(sent[0]).toContain('===SHELLPILOT-DPDB===')
    expect(sent[1]).toContain('drain spk8s-worker --ignore-daemonsets')
  })

  it('the panel offers no drain control at all when the preflight says no', () => {
    // A source assertion. The refusal must be an ABSENCE of a button, not a
    // disabled one with a tooltip: the main process re-takes the same preflight
    // and refuses on its own reading, so a control that could be pressed would
    // be a control that cannot work.
    const panel = readFileSync(
      join(__dirname, '..', 'src/renderer/src/components/kubernetes/KubernetesPanel.tsx'),
      'utf8'
    )
    expect(panel).toMatch(/drainCheck\.assessment\.safe \? \(/)
    expect(panel).toContain('This drain will not be offered while any of the above is true')
    // The unchecked reads are rendered, and rendered as hard as a blocker.
    expect(panel).toMatch(/drainCheck\.assessment\.unchecked\.map/)
    expect(panel).toContain('read did not answer, so nobody can say')
    // And there is no override anywhere in the panel.
    expect(panel).not.toContain('--force')
    expect(panel).not.toContain('delete-emptydir-data')
  })

  it('refuses without an explicit confirmation, before reading anything', async () => {
    const { reader: r, sent } = reader(() => ({ ok: true, code: 0, stdout: '' }))
    const out = await r.drain(cfg, 'spk8s-worker', 'kind-spk8s', false)
    expect(out.ok).toBe(false)
    expect(out.detail).toBe('refusing to drain a node without an explicit confirmation')
    expect(sent).toEqual([])
  })

  it('a server that cannot be reached leaves every read unknown, not empty', async () => {
    const { reader: r } = reader(() => ({ ok: false }))
    const a = await r.drainPreflight(cfg, 'spk8s-worker', 'kind-spk8s')
    expect(a.unchecked.map((u) => u.read).sort()).toEqual([
      'endpoints',
      'node',
      'pdbs',
      'pods'
    ])
    expect(a.safe).toBe(false)
  })

  it('reports an unreachable server mid-drain as an UNKNOWN outcome', async () => {
    const { reader: r } = reader((command) =>
      command.includes('DPDB')
        ? { ok: true, code: 0, stdout: fixture('preflight-clear.txt') }
        : { ok: false }
    )
    const out = await r.drain(cfg, 'spk8s-worker', 'kind-spk8s', true)
    expect(out.ok).toBe(false)
    expect(out.detail).toContain('its outcome is unknown')
    expect(out.detail).toContain('some pods may already have moved')
  })
})
