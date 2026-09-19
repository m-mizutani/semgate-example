import { defineConfig } from '@playwright/test'

// The E2E suite runs against a fully built single binary (SPA embedded) started
// by scripts/e2e.sh, which sets PLAYWRIGHT_BASE_URL.
const baseURL = process.env.PLAYWRIGHT_BASE_URL ?? 'http://127.0.0.1:8091'

export default defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  use: {
    baseURL,
    headless: true,
  },
  reporter: [['list']],
})
