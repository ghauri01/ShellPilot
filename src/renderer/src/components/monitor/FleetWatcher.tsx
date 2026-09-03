import { useEffect, useMemo, useRef } from 'react'
import { useApp, useWorkspaceServers } from '../../store/app'
import { useFleet } from '../../store/fleet'
import { useFleetStatus } from '../../store/fleetStatus'
import {
  checkResourceAlerts,
  checkStateAlert,
  checkUnitAlerts,
  hydrateAlerts,
  noteAlertEvent
} from '../../store/alerts'
import { bridgeHas, bridgeOn } from '../../lib/bridge'
import { sshHopsFor } from '../../lib/ssh'
import type { FleetTarget } from '../../../../shared/fleet'
import type { Server } from '../../types'

// Mounted once at the app root, for the same reason ApprovalWatcher is: the
// thing it watches for does not wait until you are looking at the right tab.
//
// Sampling used to be owned by mounted ServerMonitorCards, so leaving the
// monitor stopped it and the estate's state was known only while somebody was
// watching. This component owns none of the sampling — main does — but it is
// what tells main WHICH servers to watch, and what receives the results.

// Servers are described here exactly as a terminal session describes them.
// Secrets are deliberately absent: main resolves them per sweep, so a target
// configured while the vault was locked starts working the moment it is
// unlocked, with no reconfigure.
function toTarget(s: Server): FleetTarget {
  return {
    serverId: s.id,
    serverName: s.name,
    cfg: {
      // SshConnectConfig is the terminal-connect shape, so it carries a
      // sessionId and a window size that a metrics exec has no use for. The
      // foreground metrics hook fills them in the same way; the values are
      // inert here, and inventing a narrower type for one caller would mean
      // metricsSample took two shapes.
      sessionId: `fleet-${s.id}`,
      cols: 80,
      rows: 24,
      serverId: s.id,
      host: s.host,
      port: s.port,
      username: s.username,
      auth: s.auth === 'password' || s.auth === 'agent' ? s.auth : 'key',
      hops: sshHopsFor(s)
    }
  }
}

export function FleetWatcher(): null {
  const servers = useWorkspaceServers()
  // Read through a ref inside the subscription. The handler is registered once
  // on purpose -- resubscribing on every server edit would drop events during
  // the gap -- but that means a plain closure over `servers` goes stale, and a
  // server added after mount would alert under its raw UUID instead of the
  // name its owner chose.
  const serversRef = useRef(servers)
  serversRef.current = servers
  const enabled = useApp((s) => s.settings.fleetSamplingEnabled)
  const intervalMs = useApp((s) => s.settings.fleetSamplingIntervalMs)
  const webhookEnabled = useApp((s) => s.settings.webhookAlertsEnabled)
  const webhookOnResolved = useApp((s) => s.settings.webhookNotifyOnResolved)
  const report = useFleet((s) => s.report)
  const reportError = useFleet((s) => s.reportError)
  const reportFacts = useFleet((s) => s.reportFacts)
  const reportFactsError = useFleet((s) => s.reportFactsError)

  // Demo servers have nothing to sample, and an offline one is a connection
  // attempt per sweep that will not succeed — main reports the failure rather
  // than hiding it, but there is no reason to generate it every interval.
  const targets = useMemo(
    () => servers.filter((s) => s.demo === false).map(toTarget),
    [servers]
  )

  // Read the durable alert log back before anything is allowed to speak.
  //
  // Everything the alert store remembers — the repeat window, the value last
  // announced, whether the endpoint is holding an alarm from us — used to live
  // only in renderer memory, so a disk that has been at 91% for a month
  // announced itself once per app launch forever. Until this resolves the store
  // updates its chips and says nothing out loud; see hydrateAlerts.
  //
  // Here rather than at module scope because this component is the one thing
  // mounted once at the app root that already owns the alerting path, and a
  // module-scope IPC call would fire in every test that imports the store.
  useEffect(() => {
    void hydrateAlerts()
  }, [])

  // Results arrive whether or not anything is on screen, so the subscription
  // is separate from the configuration below and is never torn down by a
  // settings change.
  useEffect(() => {
    const off = bridgeOn('fleet.onSample', window.shellpilot?.fleet?.onSample, (e) => {
      // Host facts ride on roughly one sweep in thirty — they are collected
      // hourly, metrics every couple of minutes. Handled BEFORE the `!e.host`
      // return and independently of it, because the two are independent: a
      // sweep can carry facts and an error, and a facts probe can fail on a
      // host whose metrics sample was perfect.
      //
      // Absence is never treated as news. An event with no `facts` means "not
      // collected on this sweep", and clearing on it would make the panel
      // forget the estate every two minutes.
      if (e.facts) reportFacts(e.serverId, e.facts, e.at)
      else if (e.factsError) reportFactsError(e.serverId, e.factsError, e.at)
      if (!e.host) {
        // Recorded, not dropped. A host refusing SSH for six hours used to be
        // indistinguishable from one that is fine, because this returned here.
        if (e.error) {
          reportError(e.serverId, e.error, e.at)
          // And now said out loud. Recording it made the Fleet Monitor honest;
          // it still reached nobody who was not looking at that screen, which
          // is the failure this whole item exists to end — and a host that will
          // not answer is the one condition under which every OTHER alert for
          // it goes silent, so silence here is silence everywhere.
          //
          // The host's own error text is deliberately not passed as a detail.
          // It is remote output, `summary` is rendered by Slack, and "did not
          // answer" is the whole of what a person needs to act on.
          checkStateAlert(
            e.serverId,
            serversRef.current.find((s) => s.id === e.serverId)?.name ?? e.serverId,
            'host-unreachable',
            true
          )
        }
        // No error and no host is a sweep that did not reach this server at
        // all. Not a failure, not a success — nothing is said, which is the
        // null case rather than a false all-clear.
        return
      }
      // The sampler's own timestamp, not arrival time: a sweep that took 40s
        // to reach this host was taken 40s ago, and search reports the age.
        report(e.serverId, e.host, e.at)
      // Thresholds live in the renderer because that is where the settings
      // and the toast surface are. Before this, they were evaluated inside
      // the monitor's own poll — so an alert could only fire while the user
      // was already looking at the screen that would have shown the problem.
      const name = serversRef.current.find((s) => s.id === e.serverId)?.name ?? e.serverId
      // A sample arrived, so the host answered. Before any threshold is looked
      // at, because "it is reachable again" is true whatever the numbers say.
      checkStateAlert(e.serverId, name, 'host-unreachable', false)
      // `null`, not 0, when df reported nothing: a failed probe yields diskPct
      // 0, and passing that would resolve a disk alert on a host that is still
      // full — a false all-clear manufactured out of a measurement failure.
      checkResourceAlerts(e.serverId, name, {
        // Already null when the probe read no CPU section and no MemTotal, and
        // passed through unchanged. `?? null` covers a sample taken by an older
        // build of main, where the fields are a bare number and cannot be
        // absent — which costs nothing and cannot turn a reading into one.
        cpu: e.host.cpu ?? null,
        ram: e.host.memPct ?? null,
        disk: e.host.diskTotal > 0 ? e.host.diskPct : null,
        // Null, not zero, for both. `df -i` is absent on some busybox
        // userlands and btrfs and zfs honestly report no inode table; a
        // container without /proc has no load average. Zero for either would be
        // an empty filesystem and an idle machine.
        inode: e.host.inodePct ?? null,
        load:
          e.host.load1 === null || e.host.load1 === undefined
            ? null
            : e.host.load1 / Math.max(1, e.host.cores)
      })
      // The reason the feature exists. A failed unit does not move a CPU or
      // memory graph, so thresholds would never have caught the case this was
      // built for. `null` stays null: "systemd was not visible" is not "nothing
      // is failing", and flattening it would post a false all-clear.
      checkUnitAlerts(
        e.serverId,
        name,
        e.host.services === null
          ? null
          : e.host.services.filter((u) => u.active === 'failed' || u.sub === 'failed').map((u) => u.name)
      )
    })
    return () => off?.()
  }, [report, reportError, reportFacts, reportFactsError])

  // Seed the facts the sampler ALREADY holds.
  //
  // The subscription above only ever sees the next hourly collection, so
  // without this a freshly started app shows "not collected yet" for an estate
  // main has had facts for since its first sweep — up to an hour of the
  // inventory and of fleet search being wrong about what is known.
  //
  // Keyed on the server set rather than run once, so a server added to the
  // workspace picks up whatever main has for it. Cheap by construction: it is a
  // read of an in-memory map in main, not a connection, and `fleet.facts` is
  // documented as never being a trigger.
  useEffect(() => {
    if (!bridgeHas(window.shellpilot?.fleet as Record<string, unknown> | undefined, 'facts')) return
    let live = true
    for (const t of targets) {
      void window.shellpilot?.fleet?.facts(t.serverId).then((r) => {
        if (!live || !r) return
        if (r.facts && r.at !== undefined) reportFacts(t.serverId, r.facts, r.at)
        if (r.error) reportFactsError(t.serverId, r.error, r.errorAt ?? Date.now())
      })
    }
    return () => {
      live = false
    }
  }, [targets, reportFacts, reportFactsError])

  // Reconfigure whenever what should be watched changes. Main treats this as
  // the complete desired state, so removing a server here stops sampling it.
  useEffect(() => {
    void window.shellpilot?.fleet?.configure({ enabled, intervalMs, targets })
  }, [enabled, intervalMs, targets])

  // A job step that failed.
  //
  // The one alert kind whose signal is already being pushed at the renderer:
  // main emits a progress event on every host transition, so there is nothing
  // to poll and nothing to sample. Registered once, like the sample handler
  // above and for the same reason — resubscribing would drop transitions.
  //
  // `failed` raises and `ok` resolves. Everything else is null: `pending`,
  // `waiting`, `running`, `detached` and `rebooting` are a host that has not
  // answered yet, and `orphaned` is the honest "nobody will ever know how this
  // ended". None of them is a success, so none of them may clear an alert —
  // 19a's rule, applied to a state machine instead of a measurement.
  useEffect(() => {
    // `as unknown` first: JobsBridge is a named interface with no index
    // signature, which is the point of the annotation on it in the preload.
    if (
      !bridgeHas(
        window.shellpilot?.jobs as unknown as Record<string, unknown> | undefined,
        'onProgress'
      )
    ) {
      return
    }
    // Job titles arrive on the event that changed the JOB, and the events that
    // change a HOST do not repeat them. Held here so the alert can say which
    // job failed rather than quoting a UUID at somebody.
    const titles = new Map<string, string>()
    const off = window.shellpilot?.jobs?.onProgress((p) => {
      if (p.job) titles.set(p.jobId, p.job.title)
      const host = p.host
      if (!host) return
      const bad = host.state === 'failed' ? true : host.state === 'ok' ? false : null
      checkStateAlert(host.serverId, host.serverName, 'job-failed', bad, titles.get(p.jobId) ?? '')
      if (p.done) titles.delete(p.jobId)
    })
    return () => off?.()
  }, [])

  // A tunnel sitting in error.
  //
  // Polled rather than subscribed because `tunnel.onStatus` is per tunnel id
  // and this component would have to add and drop subscriptions as tunnels come
  // and go — a subscription set that can be wrong is worse than a read that is
  // ten seconds late for a condition measured in minutes.
  //
  // `starting` is null on purpose: a tunnel that has not finished coming up is
  // neither in error nor carrying traffic, and calling it either would announce
  // a failure every time somebody starts one.
  useEffect(() => {
    if (!bridgeHas(window.shellpilot?.tunnel as Record<string, unknown> | undefined, 'list')) return
    let live = true
    const read = (): void => {
      void window.shellpilot?.tunnel?.list().then((list) => {
        if (!live || !Array.isArray(list)) return
        const named = useApp.getState().tunnels
        for (const t of list) {
          const bad = t.state === 'error' ? true : t.state === 'active' ? false : null
          if (bad === null) continue
          checkStateAlert(t.id, named.find((n) => n.id === t.id)?.name ?? t.id, 'tunnel-down', bad)
        }
      })
    }
    // The first read waits for hydration, rather than being fired and swallowed.
    // Nothing is said before the durable log is back, so an eager read here
    // would be one poll's worth of silence for no reason — and for the database
    // poll below, that is a minute.
    void hydrateAlerts().then(() => {
      if (live) read()
    })
    const timer = setInterval(read, 10_000)
    return () => {
      live = false
      clearInterval(timer)
    }
  }, [])

  // Item 18's database verdicts.
  //
  // Read from the history store, where `notableDbEvents` already wrote them
  // with the level decided and the numbers attached. Nothing here recomputes a
  // verdict: an alert that re-derived "is this replication lag bad" could
  // disagree with the screen item 18 renders, which is the trap the disk alert
  // avoided by making `isDiskCritical` the only comparison in the app.
  //
  // A minute, not ten seconds. These rows only appear when a database
  // operations read runs, which happens when somebody opens that page — there
  // is nothing here that moves between polls on its own.
  useEffect(() => {
    if (!bridgeHas(window.shellpilot?.alerts as Record<string, unknown> | undefined, 'dbEvents')) {
      return
    }
    let live = true
    const read = (): void => {
      void window.shellpilot?.alerts?.dbEvents().then((rows) => {
        if (!live || !Array.isArray(rows)) return
        const named = useApp.getState().databases
        // Oldest first, so the flap counter sees the occurrences in the order
        // they happened rather than the order they were read back.
        for (const row of [...rows].reverse()) {
          noteAlertEvent(
            row.connectionId,
            named.find((d) => d.id === row.connectionId)?.name ?? row.connectionId,
            row.kind,
            row.question,
            row.at
          )
        }
      })
    }
    void hydrateAlerts().then(() => {
      if (live) read()
    })
    const timer = setInterval(read, 60_000)
    return () => {
      live = false
      clearInterval(timer)
    }
  }, [])

  // Push webhook settings to main on mount, not only when the toggle moves.
  //
  // The service holds them in memory; the persisted copy lives here. Without
  // this effect the only thing that ever told main they were on was the
  // settings switch, so a restart silently disabled a feature whose whole job
  // is noticing failures while nobody is looking at the app.
  useEffect(() => {
    void window.shellpilot?.webhook?.configure({
      enabled: webhookEnabled,
      notifyOnResolved: webhookOnResolved
    })
  }, [webhookEnabled, webhookOnResolved])

  // Poll the sampler's real state app-wide, not only while Settings is open.
  //
  // This is what makes the status-bar chip possible. Before it, `fleet.status()`
  // was called from exactly one file — the Settings pane — so background
  // checking could be paused for hours and the only place that said so was a
  // screen nobody had reason to open.
  //
  // Ten seconds because these numbers move on the order of a sweep, and a vault
  // unlocked in another window should clear the warning without the user
  // wondering whether it is stuck. Cheap: one IPC call to main, no connection.
  useEffect(() => {
    if (!bridgeHas(window.shellpilot?.fleet as Record<string, unknown> | undefined, 'status')) return
    let live = true
    const read = (): void => {
      void window.shellpilot?.fleet?.status().then((s) => {
        if (live && s) useFleetStatus.getState().setStatus(s)
      })
    }
    read()
    const t = setInterval(read, 10_000)
    return () => {
      live = false
      clearInterval(t)
    }
  }, [])

  return null
}
