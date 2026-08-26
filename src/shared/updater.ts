// Shared between main (updater.ts, the only thing that produces these) and
// the renderer (the Settings UI that displays them).
export type UpdaterStatus =
  | { state: 'idle' }
  | { state: 'checking' }
  | { state: 'available'; version: string }
  | { state: 'not-available' }
  | { state: 'downloading'; percent: number }
  | { state: 'downloaded'; version: string }
  | { state: 'error'; message: string }
  // macOS-only: a newer version exists, but is not downloaded automatically —
  // see CAN_AUTO_INSTALL in updater.ts for why.
  | { state: 'manual'; version: string }
