import { beforeEach, describe, expect, it } from 'vitest'
import { useApp } from '../src/renderer/src/store/app'
import { openAi, openSettings, useNav } from '../src/renderer/src/store/nav'

// A button on an error message is only worth having if it lands on the page
// that resolves the error. Both panels used to hold their current page in local
// state, so "Open AI settings" could switch to AI & MCP and still show
// Overview, and "Review saved keys" could open Settings on Appearance — one
// page short, which is the same dead end the message was trying to remove.

beforeEach(() => {
  useApp.setState({ activity: 'connections' })
  useNav.setState({ aiSection: 'overview', aiGroupId: null, settingsSection: 'appearance' })
})

describe('openAi', () => {
  it('opens the panel and the page inside it', () => {
    openAi('security')
    expect(useApp.getState().activity).toBe('ai')
    expect(useNav.getState().aiSection).toBe('security')
  })

  it('can name the access group to open on', () => {
    openAi('groups', 'grp-read-only')
    expect(useNav.getState().aiGroupId).toBe('grp-read-only')
  })

  it('forgets that group once the user navigates by hand', () => {
    openAi('groups', 'grp-read-only')
    useNav.getState().setAiSection('audit')
    // Otherwise coming back to Access Groups later would silently re-select a
    // group the user had moved on from.
    expect(useNav.getState().aiGroupId).toBeNull()
  })
})

describe('openSettings', () => {
  it('opens Settings on the page asked for, not on whatever was last shown', () => {
    useNav.setState({ settingsSection: 'terminal' })
    openSettings('security')
    expect(useApp.getState().activity).toBe('settings')
    expect(useNav.getState().settingsSection).toBe('security')
  })
})
