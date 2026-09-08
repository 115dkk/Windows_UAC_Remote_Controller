// SPDX-License-Identifier: GPL-2.0-or-later
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const cwd = fileURLToPath(new URL('../', import.meta.url));
const mode = process.argv[2];
if (process.argv.length !== 3 || !['dev', 'build'].includes(mode)) {
  throw new Error('usage: node tools/build-ui.mjs dev|build');
}
if (mode === 'dev') {
  const child = spawn(process.execPath, ['node_modules/vite/bin/vite.js', '--host', '127.0.0.1', '--port', '1420', '--strictPort'], { cwd, stdio: 'inherit' });
  child.on('error', (error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
  child.on('exit', (code, signal) => { process.exitCode = signal ? 1 : (code ?? 1); });
} else {
  for (const args of [['node_modules/typescript/bin/tsc', '-b'], ['node_modules/vite/bin/vite.js', 'build']]) {
    const result = spawnSync(process.execPath, args, { cwd, stdio: 'inherit', timeout: 300_000 });
    if (result.error || result.signal || result.status !== 0) process.exit(result.status && result.status > 0 ? result.status : 1);
  }
}
