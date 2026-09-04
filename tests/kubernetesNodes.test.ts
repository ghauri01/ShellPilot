import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import {
  buildK8sCordonCommand,
  parseK8sCordonResult,
  planK8sCordon,
  validateNodeName
} from '../src/shared/kubernetes'

// Roadmap item 22, part one: cordon and uncordon.
//
// Every fixture replayed here was recorded from a real three-node `kind`
// cluster (Kubernetes v1.33) through the command this module actually builds —
// section markers included. tests/fixtures/k8s/README.md records which command
// produced which file and what could not be captured.
const fixture = (name: string): string =>
  readFileSync(join(__dirname, 'fixtures', 'k8s', name), 'utf8')

describe('cordon and uncordon build one command', () => {
  it('names the node once for the action and once for the read back', () => {
    const cmd = buildK8sCordonCommand('spk8s-worker', 'cordon', 'kind-spk8s')
    expect(cmd).toContain('cordon spk8s-worker --context=kind-spk8s')
    expect(cmd).toContain('get node spk8s-worker --no-headers --context=kind-spk8s')
    expect(cmd).toContain('===SHELLPILOT-CORDON===')
    expect(cmd).toContain('===SHELLPILOT-NODE===')
  })

  it('puts --request-timeout on both calls', () => {
    // kubectl's default is to wait forever, and a cordon against an API server
    // that is not answering would otherwise hold the SSH exec open with no
    // output at all.
    const cmd = buildK8sCordonCommand('spk8s-worker', 'uncordon')
    expect(cmd.match(/--request-timeout=10s/g) ?? []).toHaveLength(2)
  })

  it('refuses a node name it cannot prove safe rather than escaping it', () => {
    expect(() => buildK8sCordonCommand('node-1; rm -rf /', 'cordon')).toThrow(
      /invalid node name/
    )
    expect(() => buildK8sCordonCommand('$(hostname)', 'cordon')).toThrow(/invalid node name/)
    expect(validateNodeName('node-1; rm -rf /')).toBe(false)
    expect(validateNodeName('ip-10-0-3-71.eu-west-1.compute.internal')).toBe(true)
  })

  it('refuses a context it cannot prove safe by dropping it, never by pasting it', () => {
    // Same rule the read builders follow: an unusable context is omitted, so
    // the command still runs against the current context rather than being
    // built with an injected one.
    const cmd = buildK8sCordonCommand('spk8s-worker', 'cordon', 'prod; curl evil.example')
    expect(cmd).not.toContain('curl evil.example')
    expect(cmd).not.toContain('--context=')
  })

  it('refuses an action outside the allowlist', () => {
    expect(() =>
      buildK8sCordonCommand('spk8s-worker', 'drain' as unknown as 'cordon')
    ).toThrow(/scheduling action this module does not know/)
    // The one that matters: `delete` takes a node name too, and this module
    // has never been willing to delete anything.
    expect(() =>
      buildK8sCordonCommand('spk8s-worker', 'delete' as unknown as 'cordon')
    ).toThrow(/scheduling action this module does not know/)
  })
})

describe('what a real cluster said', () => {
  it('reads a cordon back off the node row rather than assuming it worked', () => {
    const r = parseK8sCordonResult('cordon', 'spk8s-worker', fixture('cordon-ok.txt'), 0)
    expect(r.ok).toBe(true)
    expect(r.output).toBe('node/spk8s-worker cordoned')
    // The literal kubectl prints for a cordoned node. Asserted rather than
    // derived, because the whole value of the read-back is that it comes from
    // the cluster and not from our own optimistic update.
    expect(r.node_status).toContain('Ready,SchedulingDisabled')
    expect(r.alreadyInState).toBe(false)
  })

  it('"already cordoned" is a success that changed nothing, and says so', () => {
    // The distinction this field exists for: somebody else already opened a
    // maintenance window on this node. Reporting a plain "cordoned" would hide
    // that, and the person who gets paged is whoever is mid-reboot.
    const r = parseK8sCordonResult('cordon', 'spk8s-worker', fixture('cordon-already.txt'), 0)
    expect(r.ok).toBe(true)
    expect(r.alreadyInState).toBe(true)
    expect(r.output).toBe('node/spk8s-worker already cordoned')
  })

  it('an uncordon clears SchedulingDisabled off the node row', () => {
    const r = parseK8sCordonResult('uncordon', 'spk8s-worker', fixture('uncordon-ok.txt'), 0)
    expect(r.ok).toBe(true)
    expect(r.output).toBe('node/spk8s-worker uncordoned')
    expect(r.node_status).not.toContain('SchedulingDisabled')
    expect(r.node_status).toContain('Ready')
  })

  it('a node that is not there is a failure, not a silent success', () => {
    const r = parseK8sCordonResult('cordon', 'spk8s-nope', fixture('cordon-notfound.txt'), 1)
    expect(r.ok).toBe(false)
    expect(r.detail).toBe('Error from server (NotFound): nodes "spk8s-nope" not found')
    // NotFound has no class of its own and must not be dressed up as one that
    // sends the operator somewhere wrong — it is not a dead cluster and not a
    // missing binary.
    expect(r.reason).toBe('unknown')
  })

  it('a Forbidden cordon is classified as forbidden, and carries the RBAC sentence', () => {
    // The rule the whole module is shaped around. This was recorded by
    // impersonating a ServiceAccount that can only read pods in one namespace,
    // against the same cluster and in the same session as the successes above.
    const r = parseK8sCordonResult('cordon', 'spk8s-worker', fixture('cordon-forbidden.txt'), 1)
    expect(r.ok).toBe(false)
    expect(r.reason).toBe('forbidden')
    expect(r.detail).toContain('cannot get resource "nodes"')
    expect(r.detail).toContain('system:serviceaccount:shop:deployer')
    // And the node read-back is emptied rather than shown, because an error
    // line rendered in a "current state" slot reads as the node's status.
    expect(r.node_status).toBe('')
  })

  it('an empty answer is a failure here, unlike a list read', () => {
    // A list that comes back empty can be a genuinely empty cluster. A cordon
    // that prints nothing cannot be a cordon that worked.
    const r = parseK8sCordonResult(
      'cordon',
      'spk8s-worker',
      '===SHELLPILOT-CORDON===\n\n===SHELLPILOT-NODE===\n',
      0
    )
    expect(r.ok).toBe(false)
    expect(r.detail).toBe('kubectl returned nothing')
  })
})

describe('how hard you have to press', () => {
  const target = (o: Partial<Parameters<typeof planK8sCordon>[0]> = {}) =>
    planK8sCordon({ node: 'spk8s-worker', action: 'cordon', podCount: 6, context: null, ...o })

  it('is never a typed word, in either direction', () => {
    // The reason this has its own plan function instead of reusing the
    // rollout's: nothing is evicted, and the undo is the other button on the
    // same row. A typed word here is how the typed word stops meaning anything
    // by the time a drain asks for one.
    expect(target().confirmation).toEqual({ kind: 'confirm' })
    expect(target({ action: 'uncordon' }).confirmation).toEqual({ kind: 'confirm' })
    expect(target({ node: 'prod-worker-01' }).confirmation).toEqual({ kind: 'confirm' })
    expect(target({ context: 'prod-eks' }).confirmation).toEqual({ kind: 'confirm' })
  })

  it('says out loud that a cordon evicts nothing, with the count', () => {
    // The single most common misreading of this button. An operator who
    // believes a cordon moved the pods will cordon a node and walk away from a
    // machine that is still serving every request it was serving before.
    const p = target({ podCount: 6 })
    expect(p.reasons).toContain('the 6 pod(s) already running here keep running — a cordon evicts nothing')
  })

  it('still says it when the pod count was not read', () => {
    const p = target({ podCount: null })
    expect(p.reasons).toContain('pods already running here keep running — a cordon evicts nothing')
  })

  it('warns that a cordon has no expiry', () => {
    expect(target().caveats.join(' ')).toContain('stays unschedulable until somebody uncordons it')
  })

  it('warns that an uncordon is undoing somebody else’s decision', () => {
    const p = target({ action: 'uncordon' })
    expect(p.caveats.join(' ')).toContain('somebody is working on it')
    expect(p.reasons).toContain('the scheduler starts placing new pods on this node again')
  })

  it('escalates the wording, never the demand, on a production-looking name', () => {
    expect(target({ node: 'prod-worker-01' }).reasons).toContain('"prod-worker-01" reads as production')
    expect(target({ context: 'eks-production' }).reasons).toContain('"eks-production" reads as production')
    // Bounded by separators, so an ordinary node name is not read as prod.
    expect(target({ node: 'reproducible-builder-3' }).reasons.join(' ')).not.toContain(
      'reads as production'
    )
  })

  it('is elevated in both directions', () => {
    expect(target().risk).toBe('elevated')
    expect(target({ action: 'uncordon' }).risk).toBe('elevated')
  })
})
