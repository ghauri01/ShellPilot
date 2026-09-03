import { defineConfig } from 'vitest/config'
import { resolve } from 'node:path'

// The default stays `node`, and that is the whole point.
//
// 2319 of these tests are main-process tests. They open sqlite, spawn helpers
// and parse command output; none of them wants a DOM, and building one for each
// costs real time across 111 files. Renderer tests opt IN, per file, with a
//
//     // @vitest-environment jsdom
//
// docblock at the top. That is a per-file mechanism rather than
// `environmentMatchGlobs` because Vitest 4 no longer HAS
// `environmentMatchGlobs` — it was deprecated in v3 and removed in v4, and
// nothing in `node_modules/vitest` responds to it any more. The docblock is
// also the honest form of the statement: the file that needs a DOM is the file
// that says so, and a test moved to another directory keeps working.
export default defineConfig({
  test: {
    environment: 'node',
    // `.tsx` as well as `.ts`: a component test is JSX, and the previous glob
    // would have silently ignored one.
    include: ['tests/**/*.test.ts', 'tests/**/*.test.tsx'],
    // Deliberately one file, and deliberately cheap in the node environment —
    // see the comment at the top of tests/setup/global.ts.
    setupFiles: ['./tests/setup/global.ts'],
    testTimeout: 15000
  },
  // The root tsconfig.json is a project-references stub with no
  // compilerOptions, so esbuild finds no `jsx` setting to inherit and would
  // fall back to the classic `React.createElement` transform — which fails,
  // because no component in this codebase imports React. Stating the automatic
  // runtime here is cheaper than adding @vitejs/plugin-react to the test
  // pipeline for a Fast Refresh transform no test can use.
  esbuild: { jsx: 'automatic' },
  resolve: {
    alias: {
      electron: resolve(__dirname, 'tests/mocks/electron.ts')
    }
  }
})
