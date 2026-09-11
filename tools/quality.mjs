// SPDX-License-Identifier: GPL-2.0-or-later
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repository = fileURLToPath(new URL('../', import.meta.url));
const flags = process.argv.slice(2);
if (flags.length > 1 || (flags.length === 1 && flags[0] !== '--extended')) {
  throw new Error('usage: node tools/quality.mjs [--extended]');
}
const commands = [
  // Build the real production UI before Rust's Tauri/custom-protocol targets
  // inspect frontendDist. The UI runner also enforces TS, ESLint and Vitest.
  [process.execPath, ['tools/ui-quality.mjs']],
  [process.execPath, ['--test', 'tools/rust-analyzer.test.mjs', 'tools/android-abi.test.mjs', 'tools/android-core-check.test.mjs', 'tools/build-android-bindings.test.mjs', 'tools/verify-android-apk.test.mjs']],
  [process.execPath, ['--test', 'tools/protocol-security.test.mjs', 'tools/prover-process.test.mjs', 'tools/protocol-diagnostic.test.mjs', 'tools/verify-android-boot-manifest.test.mjs']],
  [process.execPath, ['--test', 'tools/windows-packaging.test.mjs', 'tools/windows-installer-contract.test.mjs', 'tools/tauri-capability.test.mjs']],
  ['cargo', ['fmt', '--all', '--', '--check']],
  ['cargo', ['clippy', '--workspace', '--all-targets', '--all-features', '--locked', '--', '-D', 'warnings']],
  ['cargo', ['test', '--workspace', '--all-targets', '--all-features', '--locked']],
  ['cargo', ['test', '--workspace', '--doc', '--all-features', '--locked']],
  [process.execPath, ['tools/rust-analyzer.mjs']],
  [process.execPath, ['tools/verify-analyzer-gate.mjs']],
];

if (flags[0] === '--extended') {
  process.stdout.write('Extended scope: Android runtime/core Clippy; excludes the Tauri shell and host-only binding generator. The full host workspace above checks the generator. Not an APK/device check.\n');
  commands.push(
    // A full Android shell build needs its own SDK/NDK/Gradle/app quality job.
    // Exclude the shell and the explicitly host-only generator, checked above.
    [process.execPath, ['tools/android-core-check.mjs']],
  );
}

for (const [command, args] of commands) {
  process.stdout.write(`\n> ${command} ${args.join(' ')}\n`);
  const result = spawnSync(command, args, { cwd: repository, stdio: 'inherit', timeout: 900_000 });
  if (result.error || result.signal || result.status !== 0) {
    process.stderr.write(`Quality gate failed: ${result.error?.message ?? result.signal ?? result.status}\n`);
    process.exit(result.status && result.status > 0 ? result.status : 1);
  }
}

process.stdout.write('Quality commands completed. Installed application, UAC and Android device journeys require separate evidence.\n');
