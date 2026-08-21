// A parser for the JavaScript-object-literal syntax the mongo shell accepts:
// unquoted keys, single quotes, trailing commas, regex literals and helper
// calls like ObjectId('...') / ISODate('...').
//
// This is a real recursive-descent parser rather than eval/vm on purpose —
// shell input never becomes executable code.

export type HelperFn = (name: string, args: unknown[]) => unknown

class Parser {
  readonly src: string
  i = 0
  private readonly helper?: HelperFn

  constructor(src: string, helper?: HelperFn) {
    this.src = src
    this.helper = helper
  }

  eof(): boolean {
    return this.i >= this.src.length
  }

  peek(): string {
    return this.src[this.i]
  }

  fail(what: string): never {
    const near = this.src.slice(Math.max(0, this.i - 12), this.i + 12).replace(/\s+/g, ' ')
    throw new Error(`${what} at position ${this.i} near "${near}"`)
  }

  // Skip whitespace plus // and /* */ comments.
  ws(): void {
    for (;;) {
      while (!this.eof() && /\s/.test(this.peek())) this.i++
      if (this.src.startsWith('//', this.i)) {
        const nl = this.src.indexOf('\n', this.i)
        this.i = nl === -1 ? this.src.length : nl
        continue
      }
      if (this.src.startsWith('/*', this.i)) {
        const end = this.src.indexOf('*/', this.i + 2)
        this.i = end === -1 ? this.src.length : end + 2
        continue
      }
      return
    }
  }

  expect(ch: string): void {
    this.ws()
    if (this.peek() !== ch) this.fail(`Expected "${ch}"`)
    this.i++
  }

  value(): unknown {
    this.ws()
    if (this.eof()) this.fail('Unexpected end of input')
    const c = this.peek()
    if (c === '{') return this.object()
    if (c === '[') return this.array()
    if (c === '"' || c === "'" || c === '`') return this.string()
    if (c === '/') return this.regex()
    if (c === '-' || c === '+' || (c >= '0' && c <= '9')) return this.number()
    return this.word()
  }

  object(): Record<string, unknown> {
    this.expect('{')
    const out: Record<string, unknown> = {}
    this.ws()
    if (this.peek() === '}') {
      this.i++
      return out
    }
    for (;;) {
      this.ws()
      const key = this.key()
      this.expect(':')
      out[key] = this.value()
      this.ws()
      if (this.peek() === ',') {
        this.i++
        this.ws()
        if (this.peek() === '}') {
          this.i++
          return out
        }
        continue
      }
      if (this.peek() === '}') {
        this.i++
        return out
      }
      this.fail('Expected "," or "}"')
    }
  }

  key(): string {
    const c = this.peek()
    if (c === '"' || c === "'" || c === '`') return this.string()
    const m = /^[A-Za-z_$][\w$]*|^\d+/.exec(this.src.slice(this.i))
    if (!m) this.fail('Expected a property name')
    this.i += m[0].length
    return m[0]
  }

  array(): unknown[] {
    this.expect('[')
    const out: unknown[] = []
    this.ws()
    if (this.peek() === ']') {
      this.i++
      return out
    }
    for (;;) {
      out.push(this.value())
      this.ws()
      if (this.peek() === ',') {
        this.i++
        this.ws()
        if (this.peek() === ']') {
          this.i++
          return out
        }
        continue
      }
      if (this.peek() === ']') {
        this.i++
        return out
      }
      this.fail('Expected "," or "]"')
    }
  }

  string(): string {
    const quote = this.src[this.i++]
    let out = ''
    while (!this.eof()) {
      const c = this.src[this.i++]
      if (c === quote) return out
      if (c !== '\\') {
        out += c
        continue
      }
      const esc = this.src[this.i++]
      if (esc === 'n') out += '\n'
      else if (esc === 't') out += '\t'
      else if (esc === 'r') out += '\r'
      else if (esc === 'b') out += '\b'
      else if (esc === 'f') out += '\f'
      else if (esc === '0') out += '\0'
      else if (esc === 'u') {
        out += String.fromCharCode(parseInt(this.src.slice(this.i, this.i + 4), 16))
        this.i += 4
      } else out += esc
    }
    this.fail('Unterminated string')
  }

  regex(): RegExp {
    this.i++ // opening slash
    let body = ''
    let escaped = false
    let inClass = false
    while (!this.eof()) {
      const c = this.src[this.i++]
      if (escaped) {
        body += c
        escaped = false
        continue
      }
      if (c === '\\') {
        body += c
        escaped = true
        continue
      }
      if (c === '[') inClass = true
      else if (c === ']') inClass = false
      else if (c === '/' && !inClass) {
        const fm = /^[gimsuy]*/.exec(this.src.slice(this.i))
        const flags = fm ? fm[0] : ''
        this.i += flags.length
        return new RegExp(body, flags)
      }
      body += c
    }
    this.fail('Unterminated regular expression')
  }

  number(): number {
    const m = /^[+-]?(?:0[xX][0-9a-fA-F]+|\d*\.?\d+(?:[eE][+-]?\d+)?)/.exec(this.src.slice(this.i))
    if (!m) this.fail('Invalid number')
    this.i += m[0].length
    return Number(m[0])
  }

  // Bare words: literals, and helper calls such as ObjectId('..') or new Date().
  word(): unknown {
    const m = /^[A-Za-z_$][\w$]*/.exec(this.src.slice(this.i))
    if (!m) this.fail('Unexpected character')
    let name = m[0]
    this.i += name.length

    if (name === 'new') {
      this.ws()
      const n2 = /^[A-Za-z_$][\w$]*/.exec(this.src.slice(this.i))
      if (!n2) this.fail('Expected a constructor after "new"')
      name = n2[0]
      this.i += name.length
    } else {
      if (name === 'true') return true
      if (name === 'false') return false
      if (name === 'null') return null
      if (name === 'undefined') return undefined
      if (name === 'Infinity') return Infinity
      if (name === 'NaN') return NaN
    }

    this.ws()
    if (this.peek() !== '(') this.fail(`Unknown identifier "${name}"`)
    const args = this.argList()
    if (!this.helper) this.fail(`Unsupported helper "${name}()"`)
    return this.helper(name, args)
  }

  // Parses "( a, b, c )" and returns the argument values.
  argList(): unknown[] {
    this.expect('(')
    const args: unknown[] = []
    this.ws()
    if (this.peek() === ')') {
      this.i++
      return args
    }
    for (;;) {
      args.push(this.value())
      this.ws()
      if (this.peek() === ',') {
        this.i++
        this.ws()
        if (this.peek() === ')') {
          this.i++
          return args
        }
        continue
      }
      if (this.peek() === ')') {
        this.i++
        return args
      }
      this.fail('Expected "," or ")"')
    }
  }
}

// Parse a single relaxed-JSON value, requiring the whole string to be consumed.
export function parseRelaxed(src: string, helper?: HelperFn): unknown {
  const p = new Parser(src, helper)
  const v = p.value()
  p.ws()
  if (!p.eof()) p.fail('Trailing input')
  return v
}

export interface ChainCall {
  name: string
  args: unknown[]
}

export interface ParsedChain {
  // Path segments before the first call: ["db", "users"] for db.users.find().
  path: string[]
  calls: ChainCall[]
}

// Parse "db.users.find({a:1}).sort({b:-1}).limit(5)" into its path and the
// chained calls, using the value parser for every argument.
export function parseChain(src: string, helper?: HelperFn): ParsedChain {
  const p = new Parser(src, helper)
  const path: string[] = []
  const calls: ChainCall[] = []

  p.ws()
  for (;;) {
    const m = /^[A-Za-z_$][\w$]*/.exec(p.src.slice(p.i))
    if (!m) throw p.fail('Expected a name')
    p.i += m[0].length
    p.ws()
    if (p.peek() === '(') {
      calls.push({ name: m[0], args: p.argList() })
      break
    }
    path.push(m[0])
    p.ws()
    if (p.peek() !== '.') p.fail('Expected "." or "("')
    p.i++
    p.ws()
  }

  for (;;) {
    p.ws()
    if (p.eof()) break
    if (p.peek() === ';') {
      p.i++
      continue
    }
    if (p.peek() !== '.') p.fail('Expected "." or end of command')
    p.i++
    p.ws()
    const m = /^[A-Za-z_$][\w$]*/.exec(p.src.slice(p.i))
    if (!m) throw p.fail('Expected a method name')
    p.i += m[0].length
    p.ws()
    if (p.peek() !== '(') p.fail(`Expected "(" after .${m[0]}`)
    calls.push({ name: m[0], args: p.argList() })
  }

  return { path, calls }
}
