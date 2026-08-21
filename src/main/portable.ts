import { app } from 'electron'
import { join } from 'node:path'

// electron-builder's portable target sets PORTABLE_EXECUTABLE_DIR to the folder
// the .exe was launched from. When present, keep all app data beside the
// executable instead of in %APPDATA%, so copying the exe carries the servers,
// vault and settings with it.
//
// This MUST be imported before any service module: they resolve their file
// paths from app.getPath('userData') at import time, and ES module imports run
// in declaration order.
const portableDir = process.env.PORTABLE_EXECUTABLE_DIR

if (portableDir) {
  app.setPath('userData', join(portableDir, 'ShellPilot-data'))
}

export const isPortable = !!portableDir
