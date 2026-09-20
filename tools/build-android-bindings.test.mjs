// SPDX-License-Identifier: GPL-2.0-or-later
// Pure decisions and explicit system-boundary fakes only. No Cargo, compiler,
// NDK binary, generator, APK, or device is executed by these tests.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { ndkToolPaths, NDK_REVISION } from './android-core-check.mjs';
import { ANDROID_ABIS, selectAndroidAbi } from './android-abi.mjs';
import {
  createBuildPlan, parseArguments, parseRustHost, runAndroidBindings,
  validateGeneratedEntries, bindingFailureDiagnostic, validateBuiltLibraryHeader,
} from './build-android-bindings.mjs';

function planFixture({ platform = 'linux', environment = {}, options = parseArguments([]) } = {}) {
  const root = platform === 'win32' ? 'C:\\Synthetic NDK' : '/synthetic/ndk';
  const cwd = platform === 'win32' ? 'E:\\Synthetic Workspace' : '/synthetic/workspace';
  const ndk = { ...ndkToolPaths(root, platform), revision: NDK_REVISION };
  const hostTarget = platform === 'win32' ? 'x86_64-pc-windows-msvc' : 'x86_64-unknown-linux-gnu';
  return createBuildPlan({ options, cwd, platform, environment, ndk, hostTarget });
}

function runnerFixture({ results = null, environment = {}, files = {} } = {}) {
  const calls = [];
  const events = [];
  const output = [];
  const ndk = { ...ndkToolPaths('/synthetic/ndk', 'linux'), revision: NDK_REVISION };
  const queued = results ?? [
    { status: 0, stdout: 'rustc 1.97.0\nhost: x86_64-unknown-linux-gnu\n', signal: null },
    { status: 0, signal: null }, { status: 0, signal: null },
  ];
  return {
    calls, events, output,
    options: {
      args: [], environment, platform: 'linux', cwd: '/synthetic/workspace',
      stdout: { write(value) { output.push(value); } }, stderr: { write(value) { output.push(value); } },
      ndkResolver() { events.push('resolve installed NDK'); return ndk; },
      files: {
        prepareOutput() { events.push('prepare owned generated output'); },
        requireLibrary() { events.push('verify actual built library'); },
        requireGenerated() { events.push('verify generated Kotlin'); },
        ...files,
      },
      // Explicit process boundary result fixture, NOT a real compiler result.
      spawn(command, args, options) {
        calls.push({ command, args, options });
        return queued[calls.length - 1];
      },
    },
  };
}

test('the arm64 plan builds the actual Android library then generates for the host', () => {
  const ndk = { ...ndkToolPaths('/synthetic/ndk', 'linux'), revision: NDK_REVISION };
  const plan = createBuildPlan({
    options: parseArguments([]), cwd: '/synthetic/workspace', platform: 'linux',
    environment: {}, ndk, hostTarget: 'x86_64-unknown-linux-gnu',
  });
  assert.equal(plan.abi, 'arm64-v8a');
  assert.equal(plan.variant, 'debug');
  assert.equal(plan.library, '/synthetic/workspace/target/aarch64-linux-android/debug/libuac_android_controller.so');
  assert.deepEqual(plan.build.args.slice(0, 6), ['rustc', '--locked', '--package', 'android-bindings', '--lib', '--target']);
  assert.deepEqual(plan.build.args.slice(-4), ['-C', `linker=${ndk.clang}`, '-C', 'link-arg=--target=aarch64-linux-android30']);
  assert.equal(plan.generate.args[plan.generate.args.indexOf('--target') + 1], 'host-tuple');
  assert.ok(plan.generate.args.includes(plan.library));
  assert.equal(plan.generatorArtifact, '/synthetic/workspace/target/x86_64-unknown-linux-gnu/debug/controller-uniffi-bindgen');
  assert.ok(!plan.generatorArtifact.includes('/host-tuple/'));
});

test('only closed ABI and debug/release values are accepted, never output paths or shell fragments', () => {
  assert.deepEqual(parseArguments(['--abi', 'arm64-v8a', '--variant', 'release', '--dry-run']),
    { help: false, dryRun: true, abi: 'arm64-v8a', variant: 'release' });
  for (const args of [
    ['--abi', 'arm64-v8a,x86_64'], ['--abi', 'all'], ['--abi'], ['--variant', '../release'],
    ['--variant', 'debug; echo unexpected'], ['--variant'], ['--out-dir', '/elsewhere'],
    ['--dry-run', '--dry-run'], ['--help', '--dry-run'], ['--variant', 'debug', '--variant', 'release'],
  ]) assert.throws(() => parseArguments(args));
  assert.equal(parseArguments(['--help']).help, true);
});

test('release/native and host debug artifact paths remain separate and inside their selected parents', () => {
  const plan = planFixture({ options: parseArguments(['--variant', 'release']), environment: { CARGO_TARGET_DIR: '/selected/build cache' } });
  assert.equal(plan.library, '/selected/build cache/aarch64-linux-android/release/libuac_android_controller.so');
  assert.equal(plan.generatorArtifact, '/selected/build cache/x86_64-unknown-linux-gnu/debug/controller-uniffi-bindgen');
  assert.equal(plan.output, '/synthetic/workspace/src-tauri/gen/android/app/build/generated/controllerUniffi/release/arm64-v8a');
  assert.equal(plan.build.args[plan.build.args.indexOf('--profile') + 1], 'release');
  assert.equal(plan.generate.args[plan.generate.args.indexOf('--profile') + 1], 'dev');
  assert.equal(plan.generate.args[plan.generate.args.indexOf('--config') + 1], plan.config);
  assert.equal(plan.generate.args[plan.generate.args.indexOf('--out-dir') + 1], plan.kotlinDirectory);
  assert.ok(plan.configText.includes('[defaults.bindings.kotlin]'));
  assert.ok(plan.configText.includes('[crates.uac_android_controller.bindings.kotlin]'));
  assert.ok(plan.configText.includes('omit_checksums = false'));
  assert.ok(!plan.configText.includes('omit_checksums = true'));
  assert.ok(!plan.generate.args.includes('--metadata-no-deps'));
  assert.ok(!plan.build.args.includes('--all-features'));
});

test('native compiler and linker settings are child-scoped; host flags are preserved', () => {
  const incoming = Object.freeze({
    CC: 'host-cc', AR: 'host-ar', CFLAGS: '-DHOST_ONLY', RUSTFLAGS: '-Dwarnings',
    CARGO_ENCODED_RUSTFLAGS: '-Dwarnings\u001f-Cdebuginfo=1', CARGO_BUILD_TARGET: 'aarch64-linux-android',
    CFLAGS_aarch64_linux_android: '-DNATIVE_ONLY',
  });
  const plan = planFixture({ environment: incoming });
  for (const key of ['CC', 'AR', 'CFLAGS', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_TARGET']) {
    assert.equal(plan.build.environment[key], incoming[key]);
    assert.equal(plan.generate.environment[key], incoming[key]);
  }
  assert.equal(plan.build.environment.CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER,
    '/synthetic/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/clang');
  assert.equal(plan.build.environment.CFLAGS_aarch64_linux_android,
    '-DNATIVE_ONLY --target=aarch64-linux-android30');
  assert.equal(plan.generate.environment.CFLAGS_aarch64_linux_android, '-DNATIVE_ONLY');
  assert.equal(Object.hasOwn(incoming, 'CC_aarch64_linux_android'), false);
  assert.equal(Object.hasOwn(plan.generate.environment, 'CC_aarch64_linux_android'), false);
  assert.notEqual(plan.build.environment, incoming);
  assert.notEqual(plan.generate.environment, incoming);
});

test('Windows environment keys, host metadata and paths with spaces are not shell-split', () => {
  const incoming = Object.freeze({
    cargo_target_dir: 'C:\\Selected Build; Not A Shell', Rustc: 'C:\\Rust Tools\\rustc.exe',
    cargo_target_aarch64_linux_android_linker: 'old-linker', Path: 'C:\\Host Tools',
  });
  const plan = planFixture({ platform: 'win32', environment: incoming });
  assert.equal(plan.targetDirectory, 'C:\\Selected Build; Not A Shell');
  assert.equal(plan.probe.command, 'C:\\Rust Tools\\rustc.exe');
  assert.equal(plan.build.environment.cargo_target_aarch64_linux_android_linker,
    'C:\\Synthetic NDK\\toolchains\\llvm\\prebuilt\\windows-x86_64\\bin\\clang.exe');
  assert.equal(Object.hasOwn(plan.build.environment, 'CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER'), false);
  assert.ok(plan.build.args.includes('C:\\Selected Build; Not A Shell'));
  assert.ok(plan.generatorArtifact.endsWith('\\x86_64-pc-windows-msvc\\debug\\controller-uniffi-bindgen.exe'));
  assert.equal(plan.generate.environment.Path, incoming.Path);
});

test('ambiguous, broad and traversal target directories reject before any side effect', () => {
  assert.equal(planFixture({ environment: { CARGO_TARGET_DIR: 'build-cache' } }).targetDirectory,
    '/synthetic/workspace/build-cache');
  for (const path of ['/', '/synthetic', '/synthetic/workspace', '../outside', 'bad\npath']) {
    assert.throws(() => planFixture({ environment: { CARGO_TARGET_DIR: path } }));
  }
  for (const path of ['C:', 'C:relative', '\\root-relative', '\\\\server\\share', 'C:\\', 'C:\\build:stream', 'C:\\build.']) {
    assert.throws(() => planFixture({ platform: 'win32', environment: { CARGO_TARGET_DIR: path } }));
  }
});

test('host discovery is bounded, unique and platform-specific, with no literal alias directory', () => {
  assert.equal(parseRustHost('rustc 1.97.0\r\nhost: x86_64-pc-windows-msvc\r\n', 'win32'), 'x86_64-pc-windows-msvc');
  assert.equal(parseRustHost('host: x86_64-unknown-linux-musl\n', 'linux'), 'x86_64-unknown-linux-musl');
  for (const text of ['', 'host: host-tuple\n', 'host: aarch64-linux-android\n',
    'host: x86_64-linux-android\n', 'host: x86_64-unknown-linux-gnu\nhost: ../../wrong\n',
    'host: x86_64-unknown-linux-gnu\nhost: x86_64-unknown-linux-gnu\n', 'x'.repeat(16 * 1024 + 1)]) {
    assert.throws(() => parseRustHost(text, 'linux'));
  }
  assert.throws(() => parseRustHost('host: x86_64-unknown-linux-gnu\n', 'win32'));
});

test('owned generated tree requires its exact marker and refuses unknown/link/nonregular/oversized entries', () => {
  const plan = planFixture();
  const marker = { path: '.controller-uniffi.generated.json', kind: 'file', links: 1,
    size: Buffer.byteLength(plan.markerText), text: plan.markerText };
  const kotlin = { path: 'kotlin/dev/dkk115/uacremote/nativecore/uac_android_controller.kt', kind: 'file', links: 1, size: 100 };
  const config = { path: 'uniffi-global.toml', kind: 'file', links: 1,
    size: Buffer.byteLength(plan.configText), text: plan.configText };
  assert.doesNotThrow(() => validateGeneratedEntries([], plan.markerText));
  assert.doesNotThrow(() => validateGeneratedEntries([marker, config, kotlin], plan.markerText));
  for (const entries of [
    [kotlin], [{ ...marker, text: 'not this generated directory' }],
    [marker, { ...kotlin, path: '../personal.txt' }], [marker, { ...kotlin, path: 'personal.txt' }],
    [marker, { ...kotlin, kind: 'link' }], [marker, { ...kotlin, links: 2 }],
    [marker, { ...kotlin, kind: 'directory' }], [marker, { ...kotlin, size: 4 * 1024 * 1024 + 1 }],
    [marker, { ...config, text: '[bindings.kotlin]\nomit_checksums=true\n' }],
    [marker, marker], Array(17).fill(marker),
  ]) assert.throws(() => validateGeneratedEntries(entries, plan.markerText));
});

test('a Gradle-precreated known directory-only scaffold can receive a new exclusive marker', () => {
  const plan = planFixture();
  const directories = [
    'kotlin', 'kotlin/dev', 'kotlin/dev/dkk115', 'kotlin/dev/dkk115/uacremote',
    'kotlin/dev/dkk115/uacremote/nativecore',
  ].map((path) => ({ path, kind: 'directory' }));
  assert.equal(validateGeneratedEntries([], plan.markerText), true);
  assert.equal(validateGeneratedEntries(directories.slice(0, 1), plan.markerText), true);
  assert.equal(validateGeneratedEntries(directories, plan.markerText), true);
  const marker = { path: '.controller-uniffi.generated.json', kind: 'file', links: 1,
    size: Buffer.byteLength(plan.markerText), text: plan.markerText };
  assert.equal(validateGeneratedEntries([...directories, marker], plan.markerText), false);
});

test('an unowned scaffold never adopts even an empty known file or any unknown/link entry', () => {
  const plan = planFixture();
  const directories = [{ path: 'kotlin', kind: 'directory' }];
  const knownKotlin = { path: 'kotlin/dev/dkk115/uacremote/nativecore/uac_android_controller.kt',
    kind: 'file', links: 1, size: 0 };
  const validConfig = { path: 'uniffi-global.toml', kind: 'file', links: 1,
    size: Buffer.byteLength(plan.configText), text: plan.configText };
  for (const extra of [knownKotlin, validConfig,
    { path: 'kotlin/private', kind: 'directory' },
    { path: 'kotlin/private.txt', kind: 'file', links: 1, size: 0 },
    { path: 'kotlin/dev', kind: 'link' },
    { ...knownKotlin, links: 2 },
  ]) assert.throws(() => validateGeneratedEntries([...directories, extra], plan.markerText));
  const marker = { path: '.controller-uniffi.generated.json', kind: 'file', links: 1,
    size: Buffer.byteLength(plan.markerText), text: plan.markerText };
  assert.throws(() => validateGeneratedEntries([...directories, { ...marker, text: 'wrong marker' }], plan.markerText));
  assert.throws(() => validateGeneratedEntries([...directories, marker, { ...knownKotlin, links: 2 }], plan.markerText));
  assert.throws(() => validateGeneratedEntries([...directories, marker, { ...validConfig, text: 'changed config' }], plan.markerText));
});

test('build preflight diagnostics expose only bounded fixed reasons, never raw error details', () => {
  for (const message of [
    'Existing output has no matching generated ownership marker.',
    'Generated output ownership marker does not match this build.',
    'Generated configuration changed; inspect it before rebuilding.',
    'Build directory aliases, symlinks and non-directory entries are not supported.',
    'The built cdylib has an unexpected hard-link relationship.',
    `NDK source.properties must specify exactly one Pkg.Revision = ${NDK_REVISION}.`,
  ]) {
    const diagnostic = bindingFailureDiagnostic(new Error(message));
    assert.ok(diagnostic.includes(message));
    assert.ok(diagnostic.length <= 512);
  }
  const secret = 'SYNTHETIC_ENV_VALUE_MUST_NOT_APPEAR';
  const denied = Object.assign(new Error(`EACCES at /private/${secret}`), { code: 'EACCES', path: secret });
  for (const error of [denied, new Error(secret), new Error(`Existing output has no matching generated ownership marker. ${secret}`),
    new Error(secret.repeat(1024)), secret, { message: secret },
  ]) {
    const diagnostic = bindingFailureDiagnostic(error);
    assert.ok(!diagnostic.includes(secret));
    assert.ok(diagnostic.length <= 512);
    assert.ok(!diagnostic.includes('\n'));
  }
  assert.ok(bindingFailureDiagnostic(denied).includes('Filesystem access was denied'));
});

test('runner invokes exactly host probe, locked Android build and locked host generation without a shell', () => {
  const fixture = runnerFixture({ environment: Object.freeze({ RUSTFLAGS: '-Dwarnings' }) });
  assert.equal(runAndroidBindings(fixture.options), 0);
  assert.equal(fixture.calls.length, 3);
  assert.deepEqual(fixture.calls[0].args, ['-vV']);
  assert.equal(fixture.calls[0].options.maxBuffer, 16 * 1024);
  assert.equal(fixture.calls[0].options.timeout, 10_000);
  assert.equal(fixture.calls[1].command, 'cargo');
  assert.equal(fixture.calls[2].command, 'cargo');
  for (const call of fixture.calls) {
    assert.equal(call.options.shell, false);
    assert.equal(call.options.windowsHide, true);
    assert.equal(call.options.cwd, '/synthetic/workspace');
  }
  for (const call of fixture.calls.slice(1)) {
    assert.ok(call.args.includes('--locked'));
    assert.equal(call.options.stdio, 'inherit');
    assert.equal(call.options.timeout, 900_000);
  }
  assert.deepEqual(fixture.events, [
    'resolve installed NDK', 'prepare owned generated output',
    'verify actual built library', 'verify generated Kotlin',
  ]);
});

test('native build failure stops before library/generator access and preserves its nonzero exit', () => {
  const fixture = runnerFixture({ results: [
    { status: 0, stdout: 'host: x86_64-unknown-linux-gnu\n' }, { status: 37 },
  ] });
  assert.equal(runAndroidBindings(fixture.options), 37);
  assert.equal(fixture.calls.length, 2);
  assert.deepEqual(fixture.events, ['resolve installed NDK', 'prepare owned generated output']);
  assert.ok(!fixture.output.join('').includes('generation completed'));
});

test('generator failure does not report generated output success', () => {
  const fixture = runnerFixture({ results: [
    { status: 0, stdout: 'host: x86_64-unknown-linux-gnu\n' }, { status: 0 }, { status: 41 },
  ] });
  assert.equal(runAndroidBindings(fixture.options), 41);
  assert.ok(!fixture.events.includes('verify generated Kotlin'));
});

test('timeouts, signals, thrown spawn and absent completion do not pass', () => {
  for (const result of [{ status: 0, error: { code: 'ETIMEDOUT' } }, { status: 0, signal: 'SIGTERM' }, { status: null }, undefined]) {
    const fixture = runnerFixture({ results: [result] });
    assert.equal(runAndroidBindings(fixture.options), 1);
    assert.equal(fixture.calls.length, 1);
    assert.deepEqual(fixture.events, ['resolve installed NDK']);
  }
  const fixture = runnerFixture();
  fixture.options.spawn = () => { throw new Error('synthetic process boundary failure'); };
  assert.equal(runAndroidBindings(fixture.options), 1);
});

test('artifact/preparation verification failures have no alternate build, library or copy path', () => {
  const prepare = runnerFixture({ files: { prepareOutput() { throw new Error('foreign output fixture'); } } });
  assert.throws(() => runAndroidBindings(prepare.options), /foreign output fixture/);
  assert.equal(prepare.calls.length, 1);
  const missingLibrary = runnerFixture({ files: { requireLibrary() { throw new Error('missing actual Android library fixture'); } } });
  assert.throws(() => runAndroidBindings(missingLibrary.options), /missing actual Android library/);
  assert.equal(missingLibrary.calls.length, 2);
  const missingKotlin = runnerFixture({ files: { requireGenerated() { throw new Error('missing expected Kotlin fixture'); } } });
  assert.throws(() => runAndroidBindings(missingKotlin.options), /missing expected Kotlin/);
  assert.ok(!missingKotlin.output.join('').includes('generation completed'));
});

test('help and dry-run do not resolve installed tools, spawn processes or mutate generated files', () => {
  const forbidden = () => { throw new Error('side effect must not run'); };
  for (const args of [['--help'], ['--dry-run'], ['--variant', 'release', '--dry-run'], ['--abi', 'x86_64', '--dry-run']]) {
    const output = [];
    assert.equal(runAndroidBindings({
      args, cwd: '/synthetic/workspace', platform: 'linux', environment: { NDK_HOME: '/planned/ndk' },
      spawn: forbidden, ndkResolver: forbidden,
      files: { prepareOutput: forbidden, requireLibrary: forbidden, requireGenerated: forbidden },
      stdout: { write(value) { output.push(value); } }, stderr: { write: forbidden },
    }), 0);
    if (args.includes('--dry-run')) assert.ok(output.join('').includes('were not verified'));
  }
});

test('both selected ABIs keep target, linker, library, Kotlin and ownership marker coherent for each variant', () => {
  for (const abi of ANDROID_ABIS) for (const variant of ['debug', 'release']) for (const platform of ['linux', 'win32']) {
    const selected = selectAndroidAbi(abi), plan = planFixture({ platform, options: parseArguments(['--abi', abi, '--variant', variant]) });
    const normalized = (value) => value.replaceAll('\\', '/');
    assert.equal(plan.abi, abi); assert.equal(plan.rustTarget, selected.rustTarget);
    assert.ok(normalized(plan.library).endsWith(`/${selected.rustTarget}/${variant}/libuac_android_controller.so`));
    assert.ok(normalized(plan.output).endsWith(`/generated/controllerUniffi/${variant}/${abi}`));
    assert.equal(plan.build.args[plan.build.args.indexOf('--target') + 1], selected.rustTarget);
    assert.equal(plan.build.args.at(-1), `link-arg=--target=${selected.rustTarget}30`);
    assert.equal(plan.generate.args[plan.generate.args.indexOf('--target') + 1], 'host-tuple');
    assert.ok(plan.generate.args.includes(plan.library));
    assert.equal(plan.build.environment[`CARGO_TARGET_${selected.rustTarget.replaceAll('-', '_').toUpperCase()}_LINKER`],
      platform === 'win32' ? 'C:\\Synthetic NDK\\toolchains\\llvm\\prebuilt\\windows-x86_64\\bin\\clang.exe' : '/synthetic/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/clang');
    const marker = JSON.parse(plan.markerText);
    assert.equal(marker.abi, abi); assert.equal(marker.variant, variant); assert.equal(marker.uniffi, '0.32.0');
    assert.equal(marker.library, 'uac_android_controller');
    assert.ok(plan.configText.includes('omit_checksums = false'));
  }
  for (const abi of [undefined, null, '', 'arm64', 'aarch64', 'x86', 'x86_64 ', 'x86_64\n', 'constructor', '__proto__', 'arm64-v8a,x86_64']) {
    assert.throws(() => planFixture({ options: { abi, variant: 'debug' } }), /Unsupported Android binding plan/);
    assert.throws(() => parseArguments(['--abi', abi]));
  }
});

test('x86_64 native environment leaves host/generator and preexisting arm64 settings intact, including Windows key spelling', () => {
  for (const platform of ['linux', 'win32']) {
    const linkerKey = platform === 'win32' ? 'cargo_target_x86_64_linux_android_linker' : 'CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER';
    const incoming = Object.freeze({ [linkerKey]: 'old-x86-linker', CC: 'host-cc', AR: 'host-ar', CFLAGS: '-DHOST',
      CARGO_BUILD_TARGET: 'aarch64-linux-android', RUSTFLAGS: '-Dwarnings',
      CFLAGS_x86_64_linux_android: '-DSELECTED', CC_aarch64_linux_android: 'other-cc', CFLAGS_aarch64_linux_android: '-DOTHER',
    });
    const plan = planFixture({ platform, environment: incoming, options: parseArguments(['--abi', 'x86_64']) });
    assert.deepEqual(plan.generate.environment, incoming);
    assert.deepEqual(plan.probe.environment, incoming);
    assert.notEqual(plan.build.environment[linkerKey], incoming[linkerKey]);
    assert.equal(plan.build.environment.CFLAGS_x86_64_linux_android, '-DSELECTED --target=x86_64-linux-android30');
    for (const key of ['CC', 'AR', 'CFLAGS', 'CARGO_BUILD_TARGET', 'RUSTFLAGS', 'CC_aarch64_linux_android', 'CFLAGS_aarch64_linux_android']) {
      assert.equal(plan.build.environment[key], incoming[key]);
    }
    assert.equal(Object.hasOwn(plan.generate.environment, 'CC_x86_64_linux_android'), false);
  }
});

test('ABI and variant marker mismatches cannot adopt or overwrite another generated tree', () => {
  const plans = ANDROID_ABIS.flatMap((abi) => ['debug', 'release'].map((variant) => planFixture({ options: parseArguments(['--abi', abi, '--variant', variant]) })));
  assert.equal(new Set(plans.map((plan) => plan.output)).size, 4);
  for (const plan of plans) for (const other of plans.filter((entry) => entry !== plan)) {
    const marker = { path: '.controller-uniffi.generated.json', kind: 'file', links: 1, size: Buffer.byteLength(other.markerText), text: other.markerText };
    assert.throws(() => validateGeneratedEntries([marker], plan.markerText), /does not match/);
  }
});

test('built-library identity rejects a wrong ABI or non-Android library before Kotlin generation', () => {
  for (const abi of ANDROID_ABIS) {
    const bytes = Buffer.alloc(64), selected = selectAndroidAbi(abi);
    bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]); bytes.writeUInt16LE(3, 16); bytes.writeUInt16LE(selected.elfMachine, 18); bytes.writeUInt32LE(1, 20);
    assert.doesNotThrow(() => validateBuiltLibraryHeader(bytes, abi));
    assert.throws(() => validateBuiltLibraryHeader(bytes, ANDROID_ABIS.find((value) => value !== abi)), /selected Android ABI/);
    assert.throws(() => validateBuiltLibraryHeader(bytes.subarray(0, 63), abi), /selected Android ABI/);
    const wrong = Buffer.from(bytes); wrong.write('MZ', 0);
    assert.throws(() => validateBuiltLibraryHeader(wrong, abi), /selected Android ABI/);
  }
  const fixture = runnerFixture({ files: { requireLibrary(plan) {
    assert.equal(plan.abi, 'x86_64'); validateBuiltLibraryHeader(Buffer.alloc(64), plan.abi);
  } } });
  fixture.options.args = ['--abi', 'x86_64'];
  assert.throws(() => runAndroidBindings(fixture.options), /selected Android ABI/);
  assert.equal(fixture.calls.length, 2, 'no generator runs after a mismatched actual library');
});

test('x86_64 runner generates Kotlin from its exact Android output rather than host or arm64 artifacts', () => {
  const fixture = runnerFixture(); fixture.options.args = ['--abi', 'x86_64'];
  assert.equal(runAndroidBindings(fixture.options), 0);
  assert.equal(fixture.calls.length, 3);
  assert.equal(fixture.calls[1].args[fixture.calls[1].args.indexOf('--target') + 1], 'x86_64-linux-android');
  assert.ok(fixture.calls[2].args.includes('/synthetic/workspace/target/x86_64-linux-android/debug/libuac_android_controller.so'));
  assert.ok(!fixture.calls[2].args.some((arg) => arg.includes('/aarch64-linux-android/')));
  assert.ok(fixture.output.join('').includes('Android x86_64 cdylib'));
});

test('Gradle source contract uses the same closed tuples, immutable selection and ABI-specific native/Kotlin outputs', () => {
  const plugin = readFileSync(new URL('../src-tauri/gen/android/buildSrc/src/main/java/dev/dkk115/uacremote/kotlin/RustPlugin.kt', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
  assert.match(plugin, /ControllerAbi\.values\(\)\.singleOrNull/);
  assert.doesNotMatch(plugin, /ControllerAbi\.entries/);
  const app = readFileSync(new URL('../src-tauri/gen/android/app/build.gradle.kts', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
  const tuples = [...plugin.matchAll(/^\s+(?:ARM64|X86_64)\("([^"]+)", "([^"]+)", "([^"]+)", "([^"]+)"\),$/gm)]
    .map(([, abi, arch, target, rustTarget]) => ({ abi, arch, target, rustTarget }));
  assert.deepEqual(tuples, ANDROID_ABIS.map((abi) => {
    const selected = selectAndroidAbi(abi); return { abi, arch: selected.tauriArch, target: selected.tauriTarget, rustTarget: selected.rustTarget };
  }));
  assert.ok(plugin.includes('controllerAbi ?: abiList ?: "arm64-v8a"'));
  for (const [list, field] of [['abiList', 'abi'], ['archList', 'arch'], ['targetList', 'target']]) {
    assert.ok(plugin.includes(`${list} == null || ${list} == selected.${field}`));
  }
  assert.ok(plugin.includes('require(value is String && value.length <= 64)'));
  assert.ok(plugin.includes('open class Config(val controllerAbi: ControllerAbi)'));
  assert.ok(plugin.includes('config = extensions.create("rust", Config::class.java, selected)'));
  assert.ok(plugin.includes('val archList = listOf(selected.arch)'));
  assert.ok(plugin.includes('val targetsList = listOf(selected.target)'));
  assert.ok(plugin.includes('create("universal")'));
  assert.ok(plugin.includes('target = targetName'));
  assert.doesNotMatch(plugin, /split\(',\)|defaultAbiList|defaultArchList/);
  assert.ok(app.includes('extensions.getByType<Config>().controllerAbi'));
  assert.ok(app.includes('ndk { abiFilters += controllerSelectedAbi.abi }'));
  assert.ok(app.includes('"--abi", controllerSelectedAbi.abi, "--variant", variant'));
  assert.ok(app.includes('generated/controllerUniffi/$variant/${controllerSelectedAbi.abi}/kotlin'));
  assert.ok(app.includes('${controllerSelectedAbi.rustTarget}/$variant/libuac_android_controller.so'));
  assert.ok(app.includes('generated/controllerNative/$variant/${controllerSelectedAbi.abi}'));
  assert.ok(app.includes('controllerRepository.resolve("tools/android-abi.mjs")'));
  assert.ok(app.includes('testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"'));
  for (const dependency of ['androidx.test:core:1.7.0', 'androidx.test:runner:1.7.0', 'androidx.test.ext:junit:1.3.0']) assert.ok(app.includes(dependency));
  assert.ok(app.includes('getByName("release")'));
  assert.ok(app.includes('isMinifyEnabled = true'));
  assert.ok(app.includes('jniLibs.useLegacyPackaging = true'));
  assert.ok(app.includes('net.java.dev.jna:jna:5.19.1@aar'));
  assert.doesNotMatch(app, /androidx.test.ext:junit:1.1.4|espresso-core:3.5.0/);
});
