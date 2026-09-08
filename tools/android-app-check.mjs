// SPDX-License-Identifier: GPL-2.0-or-later
// ROOT/CI only: compile/lint the actual Android Tauri Rust shell, not an APK.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { resolveAndroidNdk, buildAndroidCompilerEnvironment, commandExitCode } from './android-core-check.mjs';

if (process.argv.length !== 2) throw new Error('usage: node tools/android-app-check.mjs');
const cwd = fileURLToPath(new URL('../', import.meta.url));
const ndk = resolveAndroidNdk();
const env = buildAndroidCompilerEnvironment(process.env, ndk, process.platform);
const args = ['clippy', '--locked', '--package', 'controller-app', '--target', 'aarch64-linux-android', '--lib', '--all-features', '--', '-D', 'warnings'];
process.stdout.write(`Android Tauri Rust shell Clippy: NDK ${ndk.revision}; no APK packaging or device invocation.\n`);
const result = spawnSync('cargo', args, { cwd, env, stdio: 'inherit', timeout: 900_000 });
process.exitCode = commandExitCode(result);
