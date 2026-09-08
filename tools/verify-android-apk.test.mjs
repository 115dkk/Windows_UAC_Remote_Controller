// SPDX-License-Identifier: GPL-2.0-or-later
// Pure buffers and fake child-process results only. No APK/unzip/library is executed.
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  EXPECTED_LIBRARIES, LIMITS, ApkInspectionError, apkPathFromArguments,
  checkElf64Arm64, inspectArchiveListing, readUnzipOutput, unzipEnvironment,
} from './verify-android-apk.mjs';

function elf() {
  const bytes = Buffer.alloc(0x8000);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  bytes.writeUInt16LE(3, 16);
  bytes.writeUInt16LE(183, 18);
  bytes.writeUInt32LE(1, 20);
  bytes.writeBigUInt64LE(64n, 32);
  bytes.writeUInt16LE(64, 52);
  bytes.writeUInt16LE(56, 54);
  bytes.writeUInt16LE(2, 56);
  for (const [index, offset, address, files, memory] of [
    [0, 0n, 0n, 0x4000n, 0x4000n], [1, 0x4000n, 0x8000n, 0x40n, 0x80n],
  ]) {
    const at = 64 + index * 56;
    bytes.writeUInt32LE(1, at);
    bytes.writeUInt32LE(index === 0 ? 5 : 6, at + 4);
    bytes.writeBigUInt64LE(offset, at + 8);
    bytes.writeBigUInt64LE(address, at + 16);
    bytes.writeBigUInt64LE(files, at + 32);
    bytes.writeBigUInt64LE(memory, at + 40);
    bytes.writeBigUInt64LE(0x4000n, at + 48);
  }
  return bytes;
}
const listing = (names = EXPECTED_LIBRARIES) => Buffer.from(`${names.join('\n')}\n`);
const goodResult = (stdout) => ({ status: 0, signal: null, stdout, stderr: Buffer.alloc(0) });

test('synthetic ELF64LE shared object reports exact bounded PT_LOAD metadata', () => {
  const input = elf();
  const before = Buffer.from(input);
  const result = checkElf64Arm64(input);
  assert.equal(result.machine, 183);
  assert.equal(result.programHeaderCount, 2);
  assert.equal(result.loadSegments.length, 2);
  assert.deepEqual(result.loadSegments[1], { index: 1, flags: 6, offset: '0x4000', virtualAddress: '0x8000', fileSize: '0x40', memorySize: '0x80', alignment: '0x4000' });
  assert.deepEqual(input, before);
});

test('wrong magic, class, byte order, ELF version, type or machine rejects', () => {
  for (const [offset, value] of [[0, 0], [4, 1], [5, 2], [6, 0], [16, 2], [18, 62], [20, 0]]) {
    const bytes = elf(); bytes[offset] = value;
    assert.throws(() => checkElf64Arm64(bytes), ApkInspectionError);
  }
  assert.throws(() => checkElf64Arm64(Buffer.alloc(63)), ApkInspectionError);
  assert.throws(() => checkElf64Arm64(new Uint8Array(64)), ApkInspectionError);
});

test('header/table offsets, counts and strides cannot escape the buffer', () => {
  for (const [offset, value] of [[52, 63], [54, 55], [56, 0], [56, LIMITS.programHeaders + 1], [56, 0xffff]]) {
    const bytes = elf(); bytes.writeUInt16LE(value, offset);
    assert.throws(() => checkElf64Arm64(bytes), /header|count|stride/);
  }
  for (const offset of [0n, 63n, 0x8000n - 55n, (1n << 64n) - 1n]) {
    const bytes = elf(); bytes.writeBigUInt64LE(offset, 32);
    assert.throws(() => checkElf64Arm64(bytes), /table/);
  }
});

test('PT_LOAD file and memory ranges reject truncation and unsigned overflow', () => {
  for (const [field, value] of [[8, 0x8001n], [32, 0x4001n], [40, 1n], [16, (1n << 64n) - 1n]]) {
    const bytes = elf(); bytes.writeBigUInt64LE(value, 64 + field);
    assert.throws(() => checkElf64Arm64(bytes), /range/);
  }
  const endOverflow = elf();
  endOverflow.writeBigUInt64LE(0x7fffn, 120 + 8);
  assert.throws(() => checkElf64Arm64(endOverflow), /range/);
});

test('16KiB minimum, powers of two and offset/address congruence are enforced', () => {
  for (const alignment of [0n, 1n, 4096n, 8192n, 16385n, 24576n]) {
    const bytes = elf(); bytes.writeBigUInt64LE(alignment, 64 + 48);
    assert.throws(() => checkElf64Arm64(bytes), /alignment|congruence/);
  }
  const mismatch = elf(); mismatch.writeBigUInt64LE(1n, 64 + 16);
  assert.throws(() => checkElf64Arm64(mismatch), /congruence/);
  const larger = elf(); larger.writeBigUInt64LE(0x10000n, 64 + 48);
  assert.equal(checkElf64Arm64(larger).loadSegments[0].alignment, '0x10000');
});

test('zero-file BSS is allowed but missing or unordered load segments reject', () => {
  const bss = elf(); bss.writeBigUInt64LE(0n, 120 + 32);
  assert.equal(checkElf64Arm64(bss).loadSegments[1].fileSize, '0x0');
  const missing = elf(); missing.writeUInt32LE(0, 64); missing.writeUInt32LE(0, 120);
  assert.throws(() => checkElf64Arm64(missing), /no PT_LOAD/);
  const unordered = elf(); unordered.writeBigUInt64LE(0xc000n, 64 + 16);
  assert.throws(() => checkElf64Arm64(unordered), /ascending/);
});

test('listing requires one copy of each target and allows other same-ABI libraries', () => {
  const result = inspectArchiveListing(listing(['AndroidManifest.xml', 'lib/', 'lib/arm64-v8a/', ...EXPECTED_LIBRARIES, 'lib/arm64-v8a/libc++_shared.so']));
  assert.equal(result.arm64LibraryCount, 4);
  assert.equal(result.additionalArm64Libraries, 1);
  assert.deepEqual(result.advertisedAbis, ['arm64-v8a']);
  assert.throws(() => inspectArchiveListing(listing(EXPECTED_LIBRARIES.slice(1))), /missing/);
  assert.throws(() => inspectArchiveListing(listing([...EXPECTED_LIBRARIES, EXPECTED_LIBRARIES[0]])), /duplicate/);
});

test('other advertised ABI, malformed paths and duplicate nonnative members reject', () => {
  for (const name of ['lib/x86/libother.so', 'lib/armeabi-v7a/', 'lib/arm64-v8a/nested/libother.so', '../secret', '/absolute', 'a//b', 'a/./b', 'lib\\arm64-v8a\\other.so', 'drive:name', '']) {
    assert.throws(() => inspectArchiveListing(listing([...EXPECTED_LIBRARIES, name])), ApkInspectionError);
  }
  assert.throws(() => inspectArchiveListing(listing([...EXPECTED_LIBRARIES, 'assets/a', 'assets/a'])), /duplicate/);
});

test('listing byte/count/name/control/encoding bounds reject excessive or ambiguous output', () => {
  assert.throws(() => inspectArchiveListing(Buffer.alloc(LIMITS.listingBytes + 1, 65)), /bound/);
  assert.throws(() => inspectArchiveListing(listing(Array.from({ length: LIMITS.entries + 1 }, (_, index) => `assets/${index}`))), /too many/);
  assert.throws(() => inspectArchiveListing(listing([...EXPECTED_LIBRARIES, 'x'.repeat(LIMITS.memberNameBytes + 1)])), /excessive/);
  assert.throws(() => inspectArchiveListing(Buffer.from('a\rb\n')), /control/);
  assert.throws(() => inspectArchiveListing(Buffer.from([0xff])), /UTF-8/);
});

test('CLI requires one explicit Linux APK, not unzip wildcards or flags', () => {
  assert.equal(apkPathFromArguments(['build/app-debug.apk'], '/workspace', 'linux'), '/workspace/build/app-debug.apk');
  assert.equal(apkPathFromArguments(['/tmp/a b.apk'], '/workspace', 'linux'), '/tmp/a b.apk');
  for (const args of [[], ['one.apk', 'two.apk'], ['*.apk'], ['a?.apk'], ['a[0].apk'], ['--help'], ['x\napk.apk'], ['x.zip']]) {
    assert.throws(() => apkPathFromArguments(args, '/workspace', 'linux'), ApkInspectionError);
  }
  assert.throws(() => apkPathFromArguments(['a.apk'], '/workspace', 'win32'), /Linux/);
});

test('unzip receives only argument arrays and isolated bounded passive options', () => {
  const incoming = Object.freeze({ PATH: '/synthetic/bin', UNZIP: '-d /synthetic', ZIPINFOOPT: '-h', LC_ALL: 'other', KEPT: 'synthetic' });
  const env = unzipEnvironment(incoming);
  assert.equal(env.UNZIP, ''); assert.equal(env.ZIPINFOOPT, ''); assert.equal(env.KEPT, 'synthetic'); assert.equal(env.LC_ALL, 'C');
  assert.equal(incoming.UNZIP, '-d /synthetic');
  const calls = [];
  const spawn = (command, args, options) => { calls.push({ command, args, options }); return goodResult(Buffer.from('synthetic output')); };
  readUnzipOutput('/workspace/app.apk', null, { spawn, environment: incoming });
  readUnzipOutput('/workspace/app.apk', EXPECTED_LIBRARIES[0], { spawn, environment: incoming });
  assert.deepEqual(calls[0].args, ['-Z1', '/workspace/app.apk']);
  assert.deepEqual(calls[1].args, ['-p', '/workspace/app.apk', EXPECTED_LIBRARIES[0]]);
  for (const call of calls) {
    assert.equal(call.command, 'unzip'); assert.equal(call.options.shell, false);
    assert.deepEqual(call.options.stdio, ['ignore', 'pipe', 'pipe']);
    assert.equal(call.options.timeout, 30_000); assert.equal(call.options.killSignal, 'SIGKILL');
  }
  assert.equal(calls[0].options.maxBuffer, LIMITS.listingBytes);
  assert.equal(calls[1].options.maxBuffer, LIMITS.libraryBytes);
  assert.throws(() => readUnzipOutput('/workspace/app.apk', 'assets/arbitrary', { spawn }), /fixed/);
  assert.throws(() => readUnzipOutput('/workspace/*.apk', null, { spawn }), /explicit/);
});

test('exit, signal, timeout, missing output and diagnostics cannot become success', () => {
  for (const result of [
    { ...goodResult(Buffer.from('x')), status: 1 },
    { ...goodResult(Buffer.from('x')), signal: 'SIGTERM' },
    { ...goodResult(Buffer.from('x')), error: { code: 'ETIMEDOUT', message: 'synthetic hidden detail' } },
    { ...goodResult(Buffer.from('x')), status: null },
    goodResult(Buffer.alloc(0)),
    { ...goodResult(Buffer.from('x')), stdout: 'not binary output' },
    { ...goodResult(Buffer.from('x')), stderr: Buffer.from('synthetic hidden diagnostic') },
  ]) {
    assert.throws(() => readUnzipOutput('/workspace/app.apk', null, { spawn: () => result }),
      (error) => error instanceof ApkInspectionError && !error.message.includes('hidden'));
  }
  assert.throws(() => readUnzipOutput('/workspace/app.apk', null, { spawn: () => { throw new Error('synthetic hidden path'); } }), /did not start/);
});
