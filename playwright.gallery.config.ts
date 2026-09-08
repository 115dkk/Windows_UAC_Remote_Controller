// SPDX-License-Identifier: GPL-2.0-or-later
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from '@playwright/test';

const root = fileURLToPath(new URL('.', import.meta.url));
const runId = randomUUID();

export default defineConfig({
  testDir: './tools/ui-gallery',
  testMatch: 'gallery.spec.ts',
  outputDir: './target/ui-gallery/results',
  globalSetup: './tools/ui-gallery/preflight.ts',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: true,
  timeout: 30_000,
  globalTimeout: 600_000,
  expect: { timeout: 7_000 },
  metadata: { galleryRunId: runId },
  reporter: [
    ['line'],
    ['./tools/ui-gallery/reporter.ts', { runId }],
  ],
  use: {
    browserName: 'chromium',
    headless: true,
    baseURL: 'http://127.0.0.1:4173',
    locale: 'ko-KR',
    timezoneId: 'Asia/Seoul',
    colorScheme: 'light',
    reducedMotion: 'reduce',
    deviceScaleFactor: 1,
    viewport: { width: 980, height: 740 },
    actionTimeout: 7_000,
    navigationTimeout: 15_000,
    screenshot: { mode: 'only-on-failure', fullPage: false },
    trace: 'retain-on-failure',
    video: 'off',
  },
  projects: [{ name: 'chromium-client-synthetic' }],
  webServer: {
    command: `"${process.execPath}" "${resolve(root, 'node_modules/vite/bin/vite.js')}" preview --host 127.0.0.1 --port 4173 --strictPort --outDir ../target/ui-qa`,
    cwd: root,
    url: 'http://127.0.0.1:4173/qa.html',
    reuseExistingServer: false,
    timeout: 30_000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
});
