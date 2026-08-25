import { defineConfig } from 'vitest/config'
import { resolve } from 'node:path'

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    testTimeout: 15000
  },
  resolve: {
    alias: {
      electron: resolve(__dirname, 'tests/mocks/electron.ts')
    }
  }
})
