// Result of one line entered into a database shell. The renderer prints
// whichever payload is present; several may be set at once (e.g. rows + note).
export interface DbShellResult {
  ok: boolean
  error?: string
  // Verbatim text, already shell-formatted (used for `show dbs`, help, ...).
  text?: string
  // Structured payload — the renderer pretty-prints it as JSON.
  json?: unknown
  // Tabular payload — the renderer aligns it into columns.
  columns?: string[]
  rows?: unknown[][]
  // Dim status line printed under the output, e.g. "3 document(s)".
  note?: string
  elapsedMs?: number
  // Side effects for the renderer to apply after printing.
  useDatabase?: string
  refreshSchema?: boolean
  clear?: boolean
}

// The prompt shown for each engine, e.g. "mydb> " or "postgres=# ".
export function shellPrompt(kind: string, database?: string, user?: string): string {
  switch (kind) {
    case 'mongodb':
      return `${database || 'test'}> `
    case 'postgres':
      return `${database || user || 'postgres'}=# `
    case 'mysql':
      return 'mysql> '
    case 'mssql':
      return `${database || 'master'}> `
    default:
      return '> '
  }
}
