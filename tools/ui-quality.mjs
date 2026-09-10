// SPDX-License-Identifier: GPL-2.0-or-later
// ROOT/CI only. Real client checks/build, not browser or native-device QA.
import { spawnSync } from 'node:child_process';
import { statSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repository = fileURLToPath(new URL('../', import.meta.url));
if (process.argv.length !== 2) {
  throw new Error('usage: node tools/ui-quality.mjs');
}

// Invoke the installed JS entry points with this exact Node executable. Spawning
// npm/npm.cmd without a shell is not portable on Windows; no shell is needed here.
// Dependencies must already have been installed from package-lock.json with npm ci.
const commands = [
  ['Production/QA build boundary', ['--test', 'tools/ui-build-policy.test.mjs']],
  ['Bundled Korean font contracts', ['--test', 'tools/ui-fonts.test.mjs']],
  ['Native-authored consumer copy policy', ['--test', 'tools/consumer-copy.test.mjs']],
  ['Strict TypeScript project checks', ['node_modules/typescript/bin/tsc', '-b', '--pretty', 'false']],
  ['ESLint (warnings fail)', ['node_modules/eslint/bin/eslint.js', 'ui', '--max-warnings', '0']],
  ['Vitest client behavior tests', ['node_modules/vitest/vitest.mjs', 'run']],
  ['Production client build (not the QA fixture entry)', ['node_modules/vite/bin/vite.js', 'build', '--mode', 'production']],
  ['Bundled production font bytes and notices', ['tools/ui-fonts.mjs', '--built=production']],
];

for (const [label, args] of commands) {
  process.stdout.write(`\nUI quality: ${label}\n> ${process.execPath} ${args.join(' ')}\n`);
  const result = spawnSync(process.execPath, args, { cwd: repository, stdio: 'inherit', timeout: 300_000 });
  if (result.error || result.signal || result.status !== 0) {
    process.stderr.write(`UI quality failed (${label}): ${result.error?.message ?? result.signal ?? result.status}\n`);
    process.exit(result.status && result.status > 0 ? result.status : 1);
  }
}

// Tauri's custom-protocol build consumes ../dist. A successful process without
// that real production entry must not be treated as a completed frontend build.
const entry = statSync(resolve(repository, 'dist', 'index.html'));
if (!entry.isFile() || entry.size === 0) {
  throw new Error('The production UI build did not produce a non-empty dist/index.html.');
}
process.stdout.write('UI source checks, client tests and production build completed. Browser/native behavior is not verified by this command.\n');
