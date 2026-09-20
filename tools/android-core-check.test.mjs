// SPDX-License-Identifier: GPL-2.0-or-later
// Pure/metadata fixtures only; fake compiler files are NEVER executed.
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative, resolve } from 'node:path';
import test from 'node:test';
import {
  ANDROID_CORE_ARGS, CLANG_TARGET_FLAG, NDK_REVISION, RUST_TARGET,
  buildAndroidCompilerEnvironment, commandExitCode, ndkToolPaths,
  parseNdkRevision, resolveAndroidNdk, runAndroidCoreCheck, selectNdkRoot,
  androidCoreArguments, parseAndroidCoreArguments,
} from './android-core-check.mjs';
import { ANDROID_ABIS, selectAndroidAbi } from './android-abi.mjs';

function fixture(t, { revision = NDK_REVISION, missing = null, toolsAsDirectories = false } = {}) {
  const temporaryRoot = realpathSync(tmpdir());
  const directory = mkdtempSync(join(temporaryRoot, 'wuac-android-ndk-test-'));
  t.after(() => {
    const canonical = realpathSync(directory);
    const contained = relative(temporaryRoot, canonical);
    if (canonical !== resolve(directory) || isAbsolute(contained) || !/^wuac-android-ndk-test-[^\\/]+$/.test(contained)) {
      throw new Error('Refusing to remove an unexpected NDK test fixture directory.');
    }
    rmSync(canonical, { recursive: true });
  });
  const root = join(directory, 'Synthetic Android SDK', 'ndk', NDK_REVISION);
  const tools = ndkToolPaths(root, process.platform);
  mkdirSync(join(root, 'toolchains', 'llvm', 'prebuilt', tools.hostTag, 'bin'), { recursive: true });
  if (missing !== 'source.properties') writeFileSync(tools.sourceProperties, `Pkg.Desc = Synthetic test metadata only\nPkg.Revision = ${revision}\n`);
  for (const [label, path] of [['clang', tools.clang], ['ar', tools.ar]]) {
    if (missing === label) continue;
    if (toolsAsDirectories) mkdirSync(path);
    else writeFileSync(path, 'SYNTHETIC METADATA FIXTURE. NEVER EXECUTE THIS FILE.\n');
  }
  return { directory, root, tools, sdk: join(directory, 'Synthetic Android SDK') };
}

test('explicit NDK roots take precedence over SDK roots', () => {
  assert.deepEqual(selectNdkRoot({ NDK_HOME: '/explicit/ndk', ANDROID_NDK_HOME: '/second/ndk', ANDROID_HOME: '/sdk' }, 'linux'), { root: '/explicit/ndk', source: 'NDK_HOME' });
  assert.deepEqual(selectNdkRoot({ ANDROID_NDK_HOME: '/second/ndk', ANDROID_HOME: '/sdk' }, 'linux'), { root: '/second/ndk', source: 'ANDROID_NDK_HOME' });
  assert.deepEqual(selectNdkRoot({ ANDROID_HOME: '/sdk', ANDROID_SDK_ROOT: '/other' }, 'linux'), { root: `/sdk/ndk/${NDK_REVISION}`, source: 'ANDROID_HOME' });
  assert.deepEqual(selectNdkRoot({ ANDROID_SDK_ROOT: '/sdk' }, 'linux'), { root: `/sdk/ndk/${NDK_REVISION}`, source: 'ANDROID_SDK_ROOT' });
});

test('Windows standard LOCALAPPDATA SDK fallback does not need SDK environment variables', () => {
  assert.deepEqual(selectNdkRoot({ LOCALAPPDATA: 'C:\\Users\\Synthetic\\AppData\\Local' }, 'win32'), {
    root: `C:\\Users\\Synthetic\\AppData\\Local\\Android\\Sdk\\ndk\\${NDK_REVISION}`,
    source: 'LOCALAPPDATA',
  });
  assert.deepEqual(selectNdkRoot({ Android_Home: 'C:\\Synthetic SDK' }, 'win32'), {
    root: `C:\\Synthetic SDK\\ndk\\${NDK_REVISION}`, source: 'ANDROID_HOME',
  });
});

test('missing, relative and unsupported-host locations reject rather than searching or installing', () => {
  assert.throws(() => selectNdkRoot({}, 'linux'), /No NDK location/);
  assert.throws(() => selectNdkRoot({ NDK_HOME: 'relative', ANDROID_HOME: '/valid/sdk' }, 'linux'), /absolute/);
  assert.throws(() => selectNdkRoot({ NDK_HOME: 'C:relative' }, 'win32'), /absolute/);
  assert.throws(() => selectNdkRoot({ NDK_HOME: '\\root-relative' }, 'win32'), /absolute/);
  assert.throws(() => selectNdkRoot({ NDK_HOME: '/ndk' }, 'darwin'), /Windows and Linux/);
});

test('compiler layouts use direct clang and llvm-ar, never a Windows target .cmd wrapper', () => {
  const windows = ndkToolPaths('C:\\Synthetic NDK', 'win32');
  assert.equal(windows.hostTag, 'windows-x86_64');
  assert.equal(windows.clang, 'C:\\Synthetic NDK\\toolchains\\llvm\\prebuilt\\windows-x86_64\\bin\\clang.exe');
  assert.equal(windows.ar, 'C:\\Synthetic NDK\\toolchains\\llvm\\prebuilt\\windows-x86_64\\bin\\llvm-ar.exe');
  const linux = ndkToolPaths('/synthetic/ndk', 'linux');
  assert.equal(linux.hostTag, 'linux-x86_64');
  assert.equal(linux.clang, '/synthetic/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/clang');
  assert.equal(linux.ar, '/synthetic/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar');
});

test('source.properties must contain one exact pinned revision', () => {
  assert.equal(parseNdkRevision(`Pkg.Desc = Android NDK\nPkg.Revision = ${NDK_REVISION}\n`), NDK_REVISION);
  assert.equal(parseNdkRevision(`\uFEFFPkg.Revision=${NDK_REVISION}\r\n`), NDK_REVISION);
  for (const source of ['', 'Pkg.Revision = 27.0.0\n', `Pkg.Revision=${NDK_REVISION}-preview\n`, `Pkg.Revision=${NDK_REVISION}\nPkg.Revision=${NDK_REVISION}\n`]) {
    assert.throws(() => parseNdkRevision(source), /exactly one Pkg.Revision/);
  }
});

test('resolver reads an installed metadata fixture without mutating it', (t) => {
  const data = fixture(t);
  const before = readFileSync(data.tools.sourceProperties, 'utf8');
  const selected = resolveAndroidNdk({ NDK_HOME: data.root }, process.platform);
  assert.equal(selected.revision, NDK_REVISION);
  assert.equal(selected.root, realpathSync(data.root));
  assert.equal(selected.source, 'NDK_HOME');
  assert.equal(readFileSync(data.tools.sourceProperties, 'utf8'), before);
  assert.equal(resolveAndroidNdk({ ANDROID_HOME: data.sdk }, process.platform).root, selected.root);
  assert.equal(resolveAndroidNdk({ ANDROID_NDK_HOME: data.root }, process.platform).root, selected.root);
});

test('resolver rejects missing or wrong-version selected NDK without falling back', (t) => {
  const good = fixture(t);
  const wrong = fixture(t, { revision: '27.0.0' });
  assert.throws(() => resolveAndroidNdk({ NDK_HOME: join(good.directory, 'missing'), ANDROID_HOME: good.sdk }, process.platform), /directory is unavailable/);
  assert.throws(() => resolveAndroidNdk({ NDK_HOME: wrong.root, ANDROID_HOME: good.sdk }, process.platform), /exactly one Pkg.Revision/);
});

test('resolver requires properties, clang and llvm-ar to be files', (t) => {
  for (const missing of ['source.properties', 'clang', 'ar']) {
    const data = fixture(t, { missing });
    assert.throws(() => resolveAndroidNdk({ NDK_HOME: data.root }, process.platform), /must be an existing file/);
  }
  const data = fixture(t, { toolsAsDirectories: true });
  assert.throws(() => resolveAndroidNdk({ NDK_HOME: data.root }, process.platform), /must be an existing file/);
});

test('target-only environment preserves all host settings, inherited flags and input object', () => {
  const incoming = Object.freeze({
    CC: 'host-cc', AR: 'host-ar', HOST_CC: 'explicit-host-cc', HOST_AR: 'explicit-host-ar',
    CFLAGS: '-DHOST_BASE', HOST_CFLAGS: '-DHOST_ONLY', TARGET_CFLAGS: '-DTARGET_BASE',
    PATH: '/synthetic/host/bin', RUSTFLAGS: '-Dwarnings', CARGO_ENCODED_RUSTFLAGS: '-Dwarnings\u001f-Cdebuginfo=1',
    CFLAGS_aarch64_linux_android: '  -DANDROID_ONLY -Werror  ',
    'CFLAGS_aarch64-linux-android': '-DOVERRIDE --target=old-target',
    'CC_aarch64-linux-android': 'old-target-cc', AR_aarch64_linux_android: 'old-target-ar',
  });
  const tools = ndkToolPaths('/synthetic/pinned', 'linux');
  const environment = buildAndroidCompilerEnvironment(incoming, tools, 'linux');
  assert.notEqual(environment, incoming);
  for (const name of ['CC', 'AR', 'HOST_CC', 'HOST_AR', 'CFLAGS', 'HOST_CFLAGS', 'TARGET_CFLAGS', 'PATH', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS']) {
    assert.equal(environment[name], incoming[name]);
  }
  for (const target of [RUST_TARGET, 'aarch64_linux_android']) {
    assert.equal(environment[`CC_${target}`], tools.clang);
    assert.equal(environment[`AR_${target}`], tools.ar);
  }
  assert.equal(environment.CFLAGS_aarch64_linux_android, `${incoming.CFLAGS_aarch64_linux_android} ${CLANG_TARGET_FLAG}`);
  assert.equal(environment['CFLAGS_aarch64-linux-android'], `${incoming['CFLAGS_aarch64-linux-android']} ${CLANG_TARGET_FLAG}`);
  assert.equal(incoming['CC_aarch64-linux-android'], 'old-target-cc');
});

test('empty target flags and Windows key spelling preserve global compiler isolation', () => {
  const tools = ndkToolPaths('C:\\Synthetic NDK', 'win32');
  const incoming = Object.freeze({ Path: 'C:\\Host Tools', Cc: 'host-cl', cflags_aarch64_linux_android: '', cc_aarch64_linux_android: 'old-clang' });
  const environment = buildAndroidCompilerEnvironment(incoming, tools, 'win32');
  assert.equal(environment.Path, incoming.Path);
  assert.equal(environment.Cc, incoming.Cc);
  assert.equal(environment.cc_aarch64_linux_android, tools.clang);
  assert.equal(environment.cflags_aarch64_linux_android, CLANG_TARGET_FLAG);
  assert.equal(Object.hasOwn(environment, 'CC_aarch64_linux_android'), false);
  assert.equal(Object.hasOwn(environment, 'CFLAGS'), false);
  assert.equal(Object.hasOwn(environment, 'CFLAGS_aarch64-linux-android'), false);
});

test('positive failure exits propagate and timeout/signal/missing completion never pass', () => {
  assert.equal(commandExitCode({ status: 0, signal: null }), 0);
  assert.equal(commandExitCode({ status: 37, signal: null }), 37);
  assert.equal(commandExitCode({ status: 0, signal: 'SIGTERM' }), 1);
  assert.equal(commandExitCode({ status: 0, error: { code: 'ETIMEDOUT' } }), 1);
  assert.equal(commandExitCode({ status: null, signal: null }), 1);
  assert.equal(commandExitCode({ status: -1 }), 1);
});

test('runner keeps all core coverage and passes only a child environment without using a shell', (t) => {
  const data = fixture(t);
  const incoming = Object.freeze({ NDK_HOME: data.root, CC: 'host-cc', CFLAGS: '-DHOST_BASE' });
  const calls = [];
  const output = { write() {} };
  const code = runAndroidCoreCheck({
    environment: incoming, platform: process.platform, cwd: data.directory, stdout: output, stderr: output,
    // This is an explicit spawn-result unit fixture, NOT an executed compiler.
    spawn(command, args, options) { calls.push({ command, args, options }); return { status: 37, signal: null }; },
  });
  assert.equal(code, 37);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, 'cargo');
  assert.deepEqual(calls[0].args, ANDROID_CORE_ARGS);
  assert.deepEqual(calls[0].args, ['clippy', '--workspace', '--exclude', 'controller-app', '--exclude', 'controller-uniffi-bindgen', '--all-targets', '--all-features', '--locked', '--target', 'aarch64-linux-android', '--', '-D', 'warnings']);
  assert.equal(calls[0].options.cwd, data.directory);
  assert.equal(calls[0].options.timeout, 900_000);
  assert.equal(calls[0].options.shell, undefined);
  assert.equal(calls[0].options.env.CC, 'host-cc');
  assert.equal(calls[0].options.env.CFLAGS, '-DHOST_BASE');
  assert.notEqual(calls[0].options.env, incoming);
  assert.equal(Object.hasOwn(incoming, 'CC_aarch64_linux_android'), false);
});

test('core CLI defaults to arm64 and admits only one explicit closed ABI selection', () => {
  assert.equal(parseAndroidCoreArguments([]), 'arm64-v8a');
  assert.deepEqual(androidCoreArguments(), ANDROID_CORE_ARGS);
  for (const abi of ANDROID_ABIS) assert.equal(parseAndroidCoreArguments(['--abi', abi]), abi);
  for (const args of [null, ['--abi'], ['--abi', undefined], ['--abi', ''], ['--abi', 'arm64'],
    ['--abi', 'arm64-v8a,x86_64'], ['--abi', '__proto__'], ['--abi', 'constructor'],
    ['--abi=x86_64'], ['--abi', 'x86_64', '--abi', 'arm64-v8a'], ['--abi', 'x86_64', '--target', 'other']]) {
    assert.throws(() => parseAndroidCoreArguments(args));
  }
});

test('both Android targets modify only their own compiler environment and preserve other ABI/host settings', () => {
  for (const platform of ['linux', 'win32']) for (const abi of ANDROID_ABIS) {
    const { rustTarget } = selectAndroidAbi(abi), underscored = rustTarget.replaceAll('-', '_');
    const other = selectAndroidAbi(ANDROID_ABIS.find((value) => value !== abi)).rustTarget.replaceAll('-', '_');
    const tools = ndkToolPaths(platform === 'win32' ? 'C:\\Synthetic NDK' : '/synthetic/ndk', platform);
    const incoming = Object.freeze({ CC: 'host-cc', AR: 'host-ar', HOST_CC: 'host-only', CFLAGS: '-DHOST', PATH: 'host-path',
      RUSTFLAGS: '-Dwarnings', CARGO_BUILD_TARGET: 'host-default',
      [`CC_${other}`]: 'other-cc', [`AR_${other}`]: 'other-ar', [`CFLAGS_${other}`]: '-DOTHER',
      [`CFLAGS_${underscored}`]: '-DSELECTED', [`CFLAGS_${rustTarget}`]: '--target=wrong -DUSER',
    });
    const result = buildAndroidCompilerEnvironment(incoming, tools, platform, abi);
    for (const key of ['CC', 'AR', 'HOST_CC', 'CFLAGS', 'PATH', 'RUSTFLAGS', 'CARGO_BUILD_TARGET', `CC_${other}`, `AR_${other}`, `CFLAGS_${other}`]) {
      assert.equal(result[key], incoming[key]);
    }
    for (const spelling of [rustTarget, underscored]) {
      assert.equal(result[`CC_${spelling}`], tools.clang); assert.equal(result[`AR_${spelling}`], tools.ar);
      assert.ok(result[`CFLAGS_${spelling}`].endsWith(`--target=${rustTarget}30`));
    }
    assert.equal(incoming[`CFLAGS_${underscored}`], '-DSELECTED');
    assert.equal(Object.hasOwn(incoming, `CC_${underscored}`), false);
    assert.deepEqual(androidCoreArguments(abi), ANDROID_CORE_ARGS.map((value) => value === RUST_TARGET ? rustTarget : value));
  }
});

test('x86_64 core runner chooses its real target without host environment contamination', (t) => {
  const data = fixture(t), calls = [], output = { write() {} };
  const incoming = Object.freeze({ NDK_HOME: data.root, CC: 'host-cc' });
  assert.equal(runAndroidCoreCheck({ args: ['--abi', 'x86_64'], environment: incoming, platform: process.platform,
    stdout: output, stderr: output, spawn(command, args, options) { calls.push({ command, args, options }); return { status: 0 }; } }), 0);
  assert.deepEqual(calls[0].args, androidCoreArguments('x86_64'));
  assert.equal(calls[0].options.env.CFLAGS_x86_64_linux_android, '--target=x86_64-linux-android30');
  assert.equal(calls[0].options.env.CC, 'host-cc');
  assert.equal(Object.hasOwn(incoming, 'CC_x86_64_linux_android'), false);
  assert.throws(() => runAndroidCoreCheck({ args: ['--abi', 'unknown'], environment: {},
    spawn() { throw new Error('must not spawn'); } }), /ABI must be/);
});
