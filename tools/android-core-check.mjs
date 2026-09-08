// SPDX-License-Identifier: GPL-2.0-or-later
// ROOT/CI only. Locates an installed pinned NDK; never installs or updates it.
import { spawnSync } from 'node:child_process';
import { readFileSync, realpathSync, statSync } from 'node:fs';
import { posix, resolve, win32 } from 'node:path';
import { fileURLToPath } from 'node:url';

export const NDK_REVISION = '28.2.13676358';
export const ANDROID_API = 30;
export const RUST_TARGET = 'aarch64-linux-android';
export const CLANG_TARGET_FLAG = `--target=${RUST_TARGET}${ANDROID_API}`;
export const ANDROID_CORE_ARGS = Object.freeze([
  'clippy', '--workspace', '--exclude', 'controller-app',
  '--exclude', 'controller-uniffi-bindgen', '--all-targets',
  '--all-features', '--locked', '--target', RUST_TARGET, '--', '-D', 'warnings',
]);

const repository = fileURLToPath(new URL('../', import.meta.url));

function pathRules(platform) {
  if (platform === 'win32') return { paths: win32, hostTag: 'windows-x86_64', extension: '.exe' };
  if (platform === 'linux') return { paths: posix, hostTag: 'linux-x86_64', extension: '' };
  throw new Error('Android core checking supports Windows and Linux hosts only.');
}

function environmentKey(environment, name, platform) {
  return platform === 'win32'
    ? Object.keys(environment).sort().find((key) => key.toUpperCase() === name.toUpperCase()) ?? name
    : name;
}

function valueOf(environment, name, platform) {
  return environment[environmentKey(environment, name, platform)];
}

function absolutePath(path, label, platform) {
  const { paths } = pathRules(platform);
  if (typeof path !== 'string' || path.length === 0) throw new Error(`${label} is not configured.`);
  const normalized = paths.normalize(path);
  // win32.isAbsolute also accepts a drive-root-relative path such as \Android;
  // those are not a fully qualified, reproducible NDK location.
  const absolute = platform === 'win32'
    ? /^(?:[a-z]:[\\/]|\\\\[^\\/]+[\\/][^\\/]+(?:[\\/]|$))/i.test(normalized)
    : paths.isAbsolute(normalized);
  if (!absolute) throw new Error(`${label} must be an absolute path.`);
  return normalized;
}

/** Pure selection, without fallback past an explicitly selected invalid NDK. */
export function selectNdkRoot(environment, platform) {
  const { paths } = pathRules(platform);
  for (const name of ['NDK_HOME', 'ANDROID_NDK_HOME']) {
    const value = valueOf(environment, name, platform);
    if (value !== undefined && value !== '') return { root: absolutePath(value, name, platform), source: name };
  }
  for (const name of ['ANDROID_HOME', 'ANDROID_SDK_ROOT']) {
    const value = valueOf(environment, name, platform);
    if (value !== undefined && value !== '') {
      const sdk = absolutePath(value, name, platform);
      return { root: paths.join(sdk, 'ndk', NDK_REVISION), source: name };
    }
  }
  if (platform === 'win32') {
    const localAppData = valueOf(environment, 'LOCALAPPDATA', platform);
    if (localAppData !== undefined && localAppData !== '') {
      const base = absolutePath(localAppData, 'LOCALAPPDATA', platform);
      return { root: paths.join(base, 'Android', 'Sdk', 'ndk', NDK_REVISION), source: 'LOCALAPPDATA' };
    }
  }
  throw new Error(`No NDK location is configured. Set NDK_HOME or an Android SDK path containing NDK ${NDK_REVISION}.`);
}

/** Pure host-specific path derivation. The resolver below checks actual files. */
export function ndkToolPaths(root, platform) {
  const { paths, hostTag, extension } = pathRules(platform);
  root = absolutePath(root, 'NDK root', platform);
  const bin = paths.join(root, 'toolchains', 'llvm', 'prebuilt', hostTag, 'bin');
  return {
    root, hostTag,
    sourceProperties: paths.join(root, 'source.properties'),
    clang: paths.join(bin, `clang${extension}`),
    ar: paths.join(bin, `llvm-ar${extension}`),
  };
}

export function parseNdkRevision(source) {
  const revisions = [...source.replace(/^\uFEFF/, '').matchAll(/^[ \t]*Pkg\.Revision[ \t]*=[ \t]*([^\r\n]*?)[ \t]*$/gm)];
  if (revisions.length !== 1 || revisions[0][1] !== NDK_REVISION) {
    throw new Error(`NDK source.properties must specify exactly one Pkg.Revision = ${NDK_REVISION}.`);
  }
  return NDK_REVISION;
}

function canonicalDirectory(path) {
  try {
    if (!statSync(path).isDirectory()) throw new Error('not a directory');
    return realpathSync(path);
  } catch {
    throw new Error(`Selected NDK directory is unavailable. Install NDK ${NDK_REVISION} or correct the explicit SDK/NDK location.`);
  }
}

function requireContainedFile(root, path, label, platform) {
  const { paths } = pathRules(platform);
  try {
    const metadata = statSync(path);
    const canonical = realpathSync(path);
    const relative = paths.relative(root, canonical);
    if (!metadata.isFile() || relative === '' || relative === '..' || relative.startsWith(`..${paths.sep}`) || paths.isAbsolute(relative)) {
      throw new Error('not a contained file');
    }
    return metadata;
  } catch {
    throw new Error(`Pinned NDK ${label} must be an existing file inside the selected NDK.`);
  }
}

/** Read-only installed SDK inspection. Metadata validation is not a binary audit. */
export function resolveAndroidNdk(environment = process.env, platform = process.platform) {
  const selected = selectNdkRoot(environment, platform);
  const root = absolutePath(canonicalDirectory(selected.root), 'Resolved NDK root', platform);
  const tools = ndkToolPaths(root, platform);
  const metadata = requireContainedFile(root, tools.sourceProperties, 'source.properties', platform);
  if (metadata.size > 16 * 1024) throw new Error('NDK source.properties exceeds its metadata size bound.');
  let source;
  try { source = readFileSync(tools.sourceProperties, 'utf8'); }
  catch { throw new Error('Pinned NDK source.properties could not be read.'); }
  const revision = parseNdkRevision(source);
  requireContainedFile(root, tools.clang, 'clang', platform);
  requireContainedFile(root, tools.ar, 'llvm-ar', platform);
  return { ...tools, revision, source: selected.source };
}

/** Pure child-only compiler environment; all host/general settings stay intact. */
export function buildAndroidCompilerEnvironment(incoming, tools, platform = 'linux') {
  const environment = { ...incoming };
  const set = (name, value) => { environment[environmentKey(incoming, name, platform)] = value; };
  for (const target of [RUST_TARGET, RUST_TARGET.replaceAll('-', '_')]) {
    // cc-rs checks the hyphen form before the underscore form. Both name the
    // same Android target, and both must select the pinned toolchain.
    set(`CC_${target}`, tools.clang);
    set(`AR_${target}`, tools.ar);
  }
  const appendFlag = (value) => value ? `${value} ${CLANG_TARGET_FLAG}` : CLANG_TARGET_FLAG;
  const underscore = `CFLAGS_${RUST_TARGET.replaceAll('-', '_')}`;
  set(underscore, appendFlag(valueOf(incoming, underscore, platform)));
  const hyphen = `CFLAGS_${RUST_TARGET}`;
  if (valueOf(incoming, hyphen, platform) !== undefined) {
    // cc-rs combines CFLAGS in ascending specificity, with this form last.
    // Preserve it too, while keeping API 30 as the final target selection.
    set(hyphen, appendFlag(valueOf(incoming, hyphen, platform)));
  }
  return environment;
}

export function commandExitCode(result) {
  if (result.error || result.signal || !Number.isInteger(result.status) || result.status < 0) return 1;
  return result.status;
}

export function runAndroidCoreCheck({
  environment = process.env, platform = process.platform, cwd = repository,
  spawn = spawnSync, stdout = process.stdout, stderr = process.stderr,
} = {}) {
  const ndk = resolveAndroidNdk(environment, platform);
  const childEnvironment = buildAndroidCompilerEnvironment(environment, ndk, platform);
  stdout.write(`Android Rust core Clippy: NDK ${ndk.revision}, API ${ANDROID_API}, ${ndk.hostTag}; excludes the Tauri shell and host-only binding generator, not an APK/device check.\n`);
  stdout.write(`> cargo ${ANDROID_CORE_ARGS.join(' ')}\n`);
  const result = spawn('cargo', [...ANDROID_CORE_ARGS], {
    cwd, env: childEnvironment, stdio: 'inherit', timeout: 900_000,
  });
  const code = commandExitCode(result);
  if (code !== 0) {
    stderr.write(`Android core gate failed: ${result.error?.code ?? result.signal ?? result.status ?? 'process did not complete'}\n`);
  } else {
    stdout.write('Android Rust core Clippy completed. No Android app/APK or device behavior was validated.\n');
  }
  return code;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 2) throw new Error('usage: node tools/android-core-check.mjs');
    process.exitCode = runAndroidCoreCheck();
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : 'Android core toolchain setup failed.'}\n`);
    process.exitCode = 1;
  }
}
