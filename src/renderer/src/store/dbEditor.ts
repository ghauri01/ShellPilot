import { create } from 'zustand'
import { useApp } from './app'
import type { DatabaseConn } from '../types'

// Which database connection the add/edit dialog is working on.
//
// A connection that fails because a port or a username is wrong is not a
// problem the user can fix from an error message — before this, the only way
// to change a saved database was to delete it and type it all again. The
// dialog needs to know what it is editing before it mounts, hence a store
// rather than a prop.

interface DbEditorState {
  editId: string | null
}

export const useDbEditor = create<DbEditorState>(() => ({ editId: null }))

/** Opens the dialog on a blank profile. */
export function openDatabaseCreator(): void {
  useDbEditor.setState({ editId: null })
  useApp.getState().setModal('add-database')
}

/** Opens the dialog on an existing profile, so a connection that is wrong can
 *  be corrected where it is wrong. */
export function openDatabaseEditor(id: string): void {
  useDbEditor.setState({ editId: id })
  useApp.getState().setModal('add-database')
}

/** Writes changed fields back. `replaceAll` is the store's own bulk setter and
 *  replaces the `databases` reference, which is what persist.ts watches, so an
 *  edit is saved exactly like an add or a delete. */
export function saveDatabaseEdit(id: string, patch: Partial<DatabaseConn>): void {
  const state = useApp.getState()
  state.replaceAll({
    databases: state.databases.map((d) => (d.id === id ? { ...d, ...patch } : d))
  })
}
