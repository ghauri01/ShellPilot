import type { ShellPilotApi } from './index'

declare global {
  interface Window {
    shellpilot: ShellPilotApi
  }
}

export {}
