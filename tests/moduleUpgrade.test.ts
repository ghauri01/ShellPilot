import { describe, it, expect } from 'vitest'
import { backfillModules, MODULES, type ModuleState } from '../src/shared/modules'

// The upgrade path, modelled at the REAL call site rather than on the function
// in isolation.
//
// tests/moduleBoundaries.test.ts already asserts backfillModules leaves new
// modules off for an existing install, and it passed the whole time this was
// broken — because it called the function with a partial object, which is not
// what persist.ts actually had.
//
// What persist.ts actually had: `replaceAll` merges
// `{ ...DEFAULT_SETTINGS, ...data.settings }`, and DEFAULT_SETTINGS carries
// defaultModuleState(). So by the time anything asked the store, every module
// key was present with the fresh-install default, and backfillModules — which
// only fills ABSENT keys — had nothing to do. Three modules switched themselves
// on for every existing install.
//
// These model both sides of that merge so the distinction cannot be lost again.

/** What DEFAULT_SETTINGS.modules holds. */
const defaults = (): ModuleState =>
  Object.fromEntries(MODULES.map((m) => [m.id, m.defaultEnabled])) as ModuleState

/** What replaceAll leaves in the store: defaults under whatever was saved. */
const afterReplaceAll = (savedSettingsModules: ModuleState | undefined): ModuleState => ({
  ...defaults(),
  ...(savedSettingsModules ?? {})
})

describe('upgrading an install that predates the module system', () => {
  const savedByOldVersion = undefined // no `modules` key at all

  it('leaves every new module off when backfilled from what was SAVED', () => {
    // The fix: read the saved object, not the merged store.
    const result = backfillModules(savedByOldVersion, false)
    for (const m of MODULES) expect(result[m.id], m.id).toBe(false)
  })

  it('switches modules on if backfilled from the merged store instead', () => {
    // The bug, pinned. If this ever starts returning all-false, the merge in
    // replaceAll changed and the comment in persist.ts needs revisiting — but
    // while it holds, backfilling from the store is provably the wrong source.
    const merged = afterReplaceAll(savedByOldVersion)
    const result = backfillModules(merged, false)
    const enabled = MODULES.filter((m) => result[m.id]).map((m) => m.id)
    expect(enabled.length).toBeGreaterThan(0)
    // Which is exactly what an existing install must NOT get.
    expect(enabled).toEqual(MODULES.filter((m) => m.defaultEnabled).map((m) => m.id))
  })
})

describe('upgrading an install that already had some modules', () => {
  it('keeps what the user chose and leaves the rest off', () => {
    const saved: ModuleState = { cron: true, docker: false }
    const result = backfillModules(saved, false)
    expect(result.cron).toBe(true)
    expect(result.docker).toBe(false)
    for (const m of MODULES.filter((m) => m.id !== 'cron' && m.id !== 'docker')) {
      expect(result[m.id], m.id).toBe(false)
    }
  })

  it('never re-enables something explicitly turned off, even if it defaults on', () => {
    const onByDefault = MODULES.find((m) => m.defaultEnabled)
    expect(onByDefault, 'no module defaults on — this test needs updating').toBeTruthy()
    const result = backfillModules({ [onByDefault!.id]: false }, false)
    expect(result[onByDefault!.id]).toBe(false)
  })
})

describe('a genuinely fresh install', () => {
  it('gets the defaults, so the app is useful out of the box', () => {
    const result = backfillModules(undefined, true)
    for (const m of MODULES) expect(result[m.id], m.id).toBe(m.defaultEnabled)
  })
})
