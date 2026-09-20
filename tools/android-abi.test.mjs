// SPDX-License-Identifier: GPL-2.0-or-later
// Pure selection and synthetic ELF-header fixtures, not native-build evidence.
import assert from 'node:assert/strict';
import test from 'node:test';
import { ANDROID_ABIS, DEFAULT_ANDROID_ABI, androidElfIdentity, selectAndroidAbi } from './android-abi.mjs';

test('closed immutable ABI mapping preserves arm64 default and exact x86_64 identities', () => {
  assert.equal(DEFAULT_ANDROID_ABI, 'arm64-v8a');
  assert.deepEqual(ANDROID_ABIS, ['arm64-v8a', 'x86_64']);
  assert.ok(Object.isFrozen(ANDROID_ABIS));
  assert.deepEqual(selectAndroidAbi(), { abi: 'arm64-v8a', rustTarget: 'aarch64-linux-android', tauriTarget: 'aarch64', tauriArch: 'arm64', elfMachine: 183, elfArchitecture: 'AArch64' });
  assert.deepEqual(selectAndroidAbi('x86_64'), { abi: 'x86_64', rustTarget: 'x86_64-linux-android', tauriTarget: 'x86_64', tauriArch: 'x86_64', elfMachine: 62, elfArchitecture: 'x86_64' });
  for (const abi of ANDROID_ABIS) assert.ok(Object.isFrozen(selectAndroidAbi(abi)));
  for (const invalid of ['', null, 0, {}, [], 'constructor', '__proto__', 'arm64', 'aarch64', 'x86', 'X86_64', 'x86_64 ', 'x86_64\n', 'arm64-v8a,x86_64', '../x86_64']) {
    assert.throws(() => selectAndroidAbi(invalid), /ABI must be/);
  }
});

test('ELF identity requires the explicitly selected machine and exact ELF64LE shared-object shape', () => {
  for (const abi of ANDROID_ABIS) {
    const selected = selectAndroidAbi(abi), bytes = Buffer.alloc(64);
    bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
    bytes.writeUInt16LE(3, 16); bytes.writeUInt16LE(selected.elfMachine, 18); bytes.writeUInt32LE(1, 20);
    const before = Buffer.from(bytes);
    assert.equal(androidElfIdentity(bytes, abi), selected);
    assert.deepEqual(bytes, before);
    for (const other of ANDROID_ABIS.filter((value) => value !== abi)) assert.throws(() => androidElfIdentity(bytes, other));
    for (const [offset, value] of [[0, 0], [4, 1], [5, 2], [6, 0], [16, 2], [20, 0]]) {
      const changed = Buffer.from(bytes); changed[offset] = value;
      assert.throws(() => androidElfIdentity(changed, abi));
    }
    assert.throws(() => androidElfIdentity(bytes.subarray(0, 63), abi));
    assert.throws(() => androidElfIdentity(new Uint8Array(bytes), abi));
  }
});
