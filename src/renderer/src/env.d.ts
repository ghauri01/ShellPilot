/// <reference types="vite/client" />
import type { ShellPilotApi } from '../../preload/index'

declare global {
  interface Window {
    shellpilot: ShellPilotApi
  }
}

export {}
