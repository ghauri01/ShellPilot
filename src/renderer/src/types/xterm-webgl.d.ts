// Minimal stub for @xterm/addon-webgl.
//
// The package is declared in package.json; this only exists so typecheck works
// in an environment where node_modules has not been installed for the current
// platform yet. Once `npm install` has run, the package ships its own types
// and this file can be deleted.
declare module '@xterm/addon-webgl' {
  import type { ITerminalAddon } from '@xterm/xterm'

  export class WebglAddon implements ITerminalAddon {
    constructor(preserveDrawingBuffer?: boolean)
    activate(terminal: unknown): void
    dispose(): void
    onContextLoss(handler: () => void): { dispose(): void }
  }
}
