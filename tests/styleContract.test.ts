import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

// The gap every other test in this repo has, written down once.
//
// jsdom loads no stylesheet, so a renderer test renders `className="warn"`,
// finds the element, asserts the text and passes -- whether or not `.warn`
// resolves to anything. That is not a hypothetical: on the day this was
// written, `.warn`, `.ok` and `.danger` had no bare rule anywhere, and 42 call
// sites across 13 components had been marking things as warnings and drawing
// them in ordinary body text. `.s-desc` had the same shape -- defined only as
// `.setting-row .s-desc`, used 60 times outside a settings row -- so every
// explanatory paragraph in the fleet panels rendered at the same size and
// colour as the controls beside it. Both were invisible to 4,600 passing tests.
//
// So this reads the stylesheets as TEXT and asserts the contract the markup
// depends on. It cannot tell you a colour is legible. It can tell you a class
// the components rely on resolves to a rule at all, which is the failure that
// actually happened.

const CSS_DIR = join(__dirname, '..', 'src', 'renderer', 'src', 'styles')
const css = ['global.css', 'tokens.css']
  .map((f) => readFileSync(join(CSS_DIR, f), 'utf8'))
  .join('\n')

/**
 * Whether the stylesheet carries a rule for this class STANDING ALONE, rather
 * than only in a compound or descendant form.
 *
 * `.chip.warn` and `.alerts .warn` do not help an element that is just
 * `class="warn"`, and the distinction is the entire bug: the compound forms
 * existed, which is why this looked styled to anyone grepping for the name.
 */
function hasBareRule(cls: string): boolean {
  // A selector position is "bare" when the class is preceded by the start of a
  // selector -- a `{`, `}`, `,` or line start -- and followed by something that
  // ends the simple selector, rather than by another `.` or `:`-less compound.
  const re = new RegExp(`(^|[},])\\s*\\.${cls}\\s*(,|\\{|:hover|::before)`, 'm')
  return re.test(css)
}

function definesToken(name: string): boolean {
  return new RegExp(`^\\s*--${name}\\s*:`, 'm').test(css)
}

describe('classes the components style themselves with must resolve', () => {
  // Each of these is used as a bare class in the renderer. A bare use with only
  // a compound rule defined is an element the author marked and the stylesheet
  // ignored.
  it.each(['warn', 'ok', 'danger'])('.%s has a rule of its own', (cls) => {
    expect(hasBareRule(cls)).toBe(true)
  })

  it('the status classes are actually used, so the rules are not dead weight', () => {
    // The mirror of the assertion above: if these fall to zero the rules should
    // go, and this test should be deleted rather than left asserting nothing.
    const used = readFileSync(
      join(__dirname, '..', 'src', 'renderer', 'src', 'components', 'monitor', 'PosturePanel.tsx'),
      'utf8'
    )
    expect(/className=(\{[^}]*['"]warn['"][^}]*\}|"warn")/.test(used)).toBe(true)
  })
})

describe('the theme tokens the rules resolve against', () => {
  it.each(['accent', 'accent-text'])('--%s is defined', (name) => {
    expect(definesToken(name)).toBe(true)
  })

  it('accent-text is defined per theme, not once', () => {
    // `.btn.primary` and the broadcast chip both paint text on `--accent`. A
    // single definition means one of the two themes is wrong, which is exactly
    // what a hard-coded #fff was doing before it became this token.
    const matches = css.match(/^\s*--accent-text\s*:/gm) ?? []
    expect(matches.length).toBeGreaterThanOrEqual(2)
  })

  it('nothing paints on the accent with a hard-coded white', () => {
    // The specific regression: `color: #fff` beside `background: var(--accent)`
    // is right in one theme by coincidence and wrong in the other.
    const onAccent = css.match(/background:\s*var\(--accent\);[^}]*color:\s*#f{3,6}\b/gi) ?? []
    expect(onAccent).toEqual([])
  })
})
