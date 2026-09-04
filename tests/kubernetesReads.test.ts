import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import {
  buildK8sApiScanCommand,
  buildK8sHelmListCommand,
  buildK8sResourcesCommand,
  parseK8sApiScan,
  parseK8sHelmList,
  parseK8sResources,
  K8S_API_SCAN_BLIND_SPOTS,
  K8S_DEPRECATED_APIS
} from '../src/shared/kubernetes'
import { KubernetesReader } from '../src/main/services/kubernetes'

// Roadmap item 22, part four: the reads that were missing and are cheap.
//
// PVC capacity, ingress, RBAC bindings, secret EXISTENCE, a deprecated-API
// scan and a Helm release list — all recorded from the same real kind cluster
// on v1.33. See tests/fixtures/k8s/README.md.
const fixture = (name: string): string =>
  readFileSync(join(__dirname, 'fixtures', 'k8s', name), 'utf8')

// The two values that were deliberately put into the recording cluster's
// `shop/checkout-stripe` secret, so that "the fixtures do not contain them" is
// an assertion rather than an assurance. Neither is a real credential; both
// were invented for the recording.
const PLANTED_SECRET_VALUES = [
  'sk_test_not_a_real_key_recorded_for_fixtures',
  'whsec_also_not_real'
]

describe('secrets: existence, never values', () => {
  it('uses the one output form that cannot print a value', () => {
    // `-o custom-columns=…:.data` renders the whole map, base64 and all, and
    // jsonpath has no key-enumeration operator — so every jsonpath that reaches
    // a key also reaches its value. A go-template `range $k, $v` that emits
    // only `$k` is the only form where the value is structurally unreachable.
    const cmd = buildK8sResourcesCommand('kind-spk8s')
    expect(cmd).toContain('get secrets')
    expect(cmd).toContain('{{range $k,$v := .data}}{{$k}},{{end}}')
    // `$v` is bound because Go templates require both range variables, and it
    // is never emitted. If it ever is, this fails in the diff.
    expect(cmd).not.toContain('{{$v}}')
    expect(cmd).not.toContain('.data}}{{.}}')
    // And the two shapes that WOULD print values.
    expect(cmd).not.toMatch(/get secrets[^;]*custom-columns/)
    expect(cmd).not.toMatch(/get secrets[^;]*jsonpath/)
  })

  it('lists the keys of a real secret and none of its values', () => {
    const r = parseK8sResources(fixture('resources.txt'), 0)
    expect(r.secrets.ok).toBe(true)
    if (!r.secrets.ok) return
    const stripe = r.secrets.items.find((s) => s.name === 'checkout-stripe')
    expect(stripe?.namespace).toBe('shop')
    expect(stripe?.type).toBe('Opaque')
    expect(stripe?.keys).toEqual(['api-key', 'webhook-secret'])
  })

  it('the recorded output contains no value from the cluster it was taken on', () => {
    // The assertion the planted values exist for. The recording cluster's
    // secret really did hold both of these, and this file really did come from
    // that cluster — so this failing would mean the shipped query started
    // emitting values.
    const raw = fixture('resources.txt')
    for (const value of PLANTED_SECRET_VALUES) {
      expect(raw, value).not.toContain(value)
      // Not base64 either.
      expect(raw, `base64 of ${value}`).not.toContain(Buffer.from(value).toString('base64'))
    }
  })

  it('reads a system secret’s six key names without reading the token', () => {
    const r = parseK8sResources(fixture('resources.txt'), 0)
    if (!r.secrets.ok) throw new Error('expected the secret read to succeed')
    const boot = r.secrets.items.find((s) => s.name === 'bootstrap-token-abcdef')
    expect(boot?.type).toBe('bootstrap.kubernetes.io/token')
    expect(boot?.keys).toContain('token-secret')
    expect(boot?.keys).toHaveLength(6)
  })
})

describe('PVC capacity', () => {
  it('keeps what was requested AND what was got, separately', () => {
    // The recorded claim is Pending on a WaitForFirstConsumer StorageClass: it
    // has a 2Gi request and no capacity at all. A panel showing only
    // `.status.capacity` renders a blank where the size is, which reads as a
    // volume with no size rather than one that was never provisioned.
    const r = parseK8sResources(fixture('resources.txt'), 0)
    if (!r.pvcs.ok) throw new Error('expected the PVC read to succeed')
    const pvc = r.pvcs.items.find((p) => p.name === 'catalog-data')
    expect(pvc?.status).toBe('Pending')
    expect(pvc?.requested).toBe('2Gi')
    expect(pvc?.capacity).toBe('')
    expect(pvc?.volume).toBe('')
    expect(pvc?.storageClass).toBe('standard')
  })
})

describe('ingress', () => {
  it('reads host, path, backend and TLS secret name', () => {
    const r = parseK8sResources(fixture('resources.txt'), 0)
    if (!r.ingresses.ok) throw new Error('expected the ingress read to succeed')
    const ing = r.ingresses.items[0]
    expect(ing.namespace).toBe('shop')
    expect(ing.name).toBe('shop-public')
    expect(ing.className).toBe('nginx')
    expect(ing.tlsSecrets).toEqual(['shop-tls'])
    expect(ing.rules).toEqual([
      'shop.example.com /checkout->checkout:80 /catalog->catalog:80'
    ])
  })

  it('an empty ADDRESS is a real state, not a truncation', () => {
    // No ingress controller was installed on the recording cluster, so nothing
    // has claimed this Ingress. That is exactly what a misconfigured
    // ingressClassName looks like in production, and it is worth seeing.
    const r = parseK8sResources(fixture('resources.txt'), 0)
    if (!r.ingresses.ok) throw new Error('expected the ingress read to succeed')
    expect(r.ingresses.items[0].address).toBe('')
  })
})

describe('RBAC bindings', () => {
  const r = parseK8sResources(fixture('resources.txt'), 0)

  it('does not drop bindings whose names are not RFC 1123', () => {
    // The trap. Real clusters are full of `kubeadm:bootstrap-signer-clusterinfo`
    // and `system::extension-apiserver-authentication-reader`, which no name
    // validator accepts — running one here would silently drop most of a
    // cluster's bindings while reporting success.
    if (!r.roleBindings.ok) throw new Error('expected the RBAC read to succeed')
    const names = r.roleBindings.items.map((b) => b.name)
    expect(names).toContain('kubeadm:bootstrap-signer-clusterinfo')
    expect(names).toContain('system::extension-apiserver-authentication-reader')
  })

  it('finds the cluster-admin grant, with its subject', () => {
    if (!r.roleBindings.ok) throw new Error('expected the RBAC read to succeed')
    const admin = r.roleBindings.items.find((b) => b.name === 'cluster-admin')
    expect(admin?.clusterScoped).toBe(true)
    expect(admin?.namespace).toBe('')
    expect(admin?.roleKind).toBe('ClusterRole')
    expect(admin?.subjects).toEqual(['Group:/system:masters'])
  })

  it('keeps several subjects on one binding', () => {
    if (!r.roleBindings.ok) throw new Error('expected the RBAC read to succeed')
    const b = r.roleBindings.items.find(
      (x) => x.name === 'system::extension-apiserver-authentication-reader'
    )
    expect(b?.subjects).toEqual([
      'User:/system:kube-controller-manager',
      'User:/system:kube-scheduler'
    ])
  })
})

describe('a Forbidden read is not an empty one, for every one of these', () => {
  it('carries all five denials rather than five empty tables', () => {
    const r = parseK8sResources(fixture('resources-forbidden.txt'), 1)
    for (const [name, read] of [
      ['pvcs', r.pvcs],
      ['ingresses', r.ingresses],
      ['roleBindings', r.roleBindings],
      ['secrets', r.secrets]
    ] as const) {
      expect(read.ok, name).toBe(false)
      if (read.ok) continue
      expect(read.reason, name).toBe('forbidden')
    }
  })

  it('fails the whole RBAC read when only the CLUSTER half was denied', () => {
    // The case that decided the merge. This token can list RoleBindings and not
    // ClusterRoleBindings, so a merge that dropped the failed half would show a
    // namespace's bindings and silently omit the cluster-admin grant — the
    // single most important row in the table, missing, with no error anywhere.
    const r = parseK8sResources(fixture('resources-crb-denied.txt'), 1)
    expect(r.pvcs.ok).toBe(true)
    expect(r.ingresses.ok).toBe(true)
    expect(r.roleBindings.ok).toBe(false)
    if (r.roleBindings.ok) return
    expect(r.roleBindings.reason).toBe('forbidden')
    expect(r.roleBindings.detail).toContain('cannot list resource "clusterrolebindings"')
  })
})

describe('the deprecated-API scan', () => {
  const scan = parseK8sApiScan(fixture('api-scan.txt'), 0)

  it('asks the server what it serves, and does not pass --client', () => {
    // `kubectl version --client` is what the pod read uses and it never
    // contacts the cluster — using it here would report the laptop's opinion of
    // which APIs exist.
    const cmd = buildK8sApiScanCommand('kind-spk8s')
    expect(cmd).toContain('version -o json')
    expect(cmd).not.toContain('--client')
    expect(cmd).toContain('api-versions')
    expect(cmd.match(/--request-timeout=10s/g) ?? []).toHaveLength(2)
  })

  it('reads the SERVER version, not the client’s', () => {
    // `kubectl version -o json` prints both, and the client's is the one that
    // says nothing about what the cluster will still serve next year.
    // The recording cluster's client was v1.33.2 and its API server v1.33.1 —
    // which is exactly why this assertion is worth having.
    expect(scan.serverVersion).toBe('v1.33.1')
    expect(fixture('api-scan.txt')).toContain('"gitVersion": "v1.33.2"')
  })

  it('finds nothing on a 1.33 server, because there is nothing to find', () => {
    expect(scan.served.ok).toBe(true)
    if (scan.served.ok) expect(scan.served.items).toContain('policy/v1')
    expect(scan.findings).toEqual([])
  })

  it('reports what it could not check, always', () => {
    // The point of the whole read. "No findings" is the answer people will act
    // on, and it is only honest next to the four things it did not look at.
    expect(scan.notChecked).toEqual([...K8S_API_SCAN_BLIND_SPOTS])
    expect(scan.notChecked.join(' ')).toContain('This scan reads the server, not your repository')
    expect(scan.notChecked.join(' ')).toContain('CustomResourceDefinitions')
    expect(scan.notChecked.join(' ')).toContain('It is a snapshot taken at Kubernetes 1.33')
  })

  it('finds a served API the table knows about, and says what replaced it', () => {
    const older = parseK8sApiScan(
      [
        '===SHELLPILOT-SRVVER===',
        '{"serverVersion":{"gitVersion":"v1.21.14"}}',
        '===SHELLPILOT-APIVER===',
        'apps/v1',
        'batch/v1beta1',
        'policy/v1beta1',
        'networking.k8s.io/v1beta1'
      ].join('\n'),
      0
    )
    expect(older.findings.map((f) => f.groupVersion).sort()).toEqual([
      'batch/v1beta1',
      'networking.k8s.io/v1beta1',
      'policy/v1beta1'
    ])
    expect(older.findings.find((f) => f.groupVersion === 'batch/v1beta1')?.replacement).toBe(
      'batch/v1'
    )
    // 1.21 has not reached any of these removals yet.
    expect(older.findings.every((f) => f.pastRemoval === false)).toBe(true)
  })

  it('flags a server already PAST a removal release that still serves it', () => {
    const patched = parseK8sApiScan(
      [
        '===SHELLPILOT-SRVVER===',
        '{"serverVersion":{"gitVersion":"v1.28.9+vendor.3"}}',
        '===SHELLPILOT-APIVER===',
        'policy/v1beta1'
      ].join('\n'),
      0
    )
    expect(patched.findings[0].pastRemoval).toBe(true)
    expect(patched.findings[0].removedIn).toBe('1.25')
  })

  it('says the scan found nothing BECAUSE it was denied, not because nothing is there', () => {
    const denied = parseK8sApiScan(
      [
        '===SHELLPILOT-SRVVER===',
        'error: You must be logged in to the server (Unauthorized)',
        '===SHELLPILOT-APIVER===',
        'Error from server (Forbidden): forbidden: User "x" cannot get path "/apis"'
      ].join('\n'),
      1
    )
    expect(denied.findings).toEqual([])
    expect(denied.served.ok).toBe(false)
    expect(denied.serverVersion).toBe(null)
    expect(denied.notChecked[0]).toContain('the server version could not be read')
    expect(denied.notChecked[1]).toContain(
      'the findings below are empty because nothing was looked at'
    )
  })

  it('has no duplicate groupVersions in the table', () => {
    const seen = K8S_DEPRECATED_APIS.map((d) => d.groupVersion)
    expect(new Set(seen).size).toBe(seen.length)
  })
})

describe('helm, which most hosts do not have', () => {
  it('resolves the binary the way kubectl is resolved', () => {
    // `ssh host cmd` runs a non-login shell whose PATH has no /usr/local/bin,
    // which is where helm usually lives.
    const cmd = buildK8sHelmListCommand('kind-spk8s')
    expect(cmd).toContain('/usr/local/bin/helm')
    expect(cmd).toContain('--kube-context=kind-spk8s')
    expect(cmd).toContain('--all-namespaces --output json')
  })

  it('reads a missing helm as its own answer about the HOST, not the cluster', () => {
    const r = parseK8sHelmList(fixture('helm-missing.txt'), 127)
    expect(r.ok).toBe(false)
    if (r.ok) return
    expect(r.reason).toBe('not-installed')
    // The wording matters: an empty release table would read as "nothing is
    // installed by Helm", which is a claim about the cluster this host is in no
    // position to make.
    expect(r.detail).toContain('That is not a statement about the cluster')
  })

  it('reads a release list', () => {
    // NOT a recording — no helm binary was available on the machine that wrote
    // this, and tests/fixtures/k8s/README.md says so. This is the documented
    // shape of `helm list -o json`, and the parse of a real one is unproven.
    const r = parseK8sHelmList(
      [
        '===SHELLPILOT-HELM===',
        JSON.stringify([
          {
            name: 'ingress-nginx',
            namespace: 'ingress-nginx',
            revision: '3',
            updated: '2026-08-14 10:11:12.13 +0000 UTC',
            status: 'deployed',
            chart: 'ingress-nginx-4.11.2',
            app_version: '1.11.2'
          }
        ])
      ].join('\n'),
      0
    )
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.releases[0].chart).toBe('ingress-nginx-4.11.2')
    // `app_version`, not `appVersion` — helm's JSON uses the snake_case key.
    expect(r.releases[0].appVersion).toBe('1.11.2')
  })
})

describe('a host that cannot be reached says so', () => {
  const reader = (ok: boolean): KubernetesReader =>
    new KubernetesReader({ exec: async () => ({ ok, error: ok ? undefined : 'connect ETIMEDOUT' }) })

  it('does not report an unreachable host as a helm-less one', () => {
    // Two completely different fixes: install helm, or fix the network.
    return reader(false)
      .helm({}, 'kind-spk8s')
      .then((r) => {
        expect(r.ok).toBe(false)
        if (r.ok) return
        expect(r.reason).toBe('failed')
        expect(r.reason).not.toBe('not-installed')
      })
  })

  it('does not report an unreachable host as a cluster with no deprecated APIs', async () => {
    const scan = await reader(false).apiScan({}, 'kind-spk8s')
    expect(scan.findings).toEqual([])
    expect(scan.notChecked[0]).toContain('the scan did not run at all')
    expect(scan.notChecked[0]).toContain('connect ETIMEDOUT')
  })

  it('fails all four resource reads together rather than as four cluster problems', async () => {
    const r = await reader(false).resources({}, 'kind-spk8s')
    for (const read of [r.pvcs, r.ingresses, r.roleBindings, r.secrets]) {
      expect(read.ok).toBe(false)
      if (!read.ok) expect(read.detail).toBe('connect ETIMEDOUT')
    }
  })
})
