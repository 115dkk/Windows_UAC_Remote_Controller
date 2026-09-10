// SPDX-License-Identifier: GPL-2.0-or-later
// Closed build-time architecture mapping. No environment selection or I/O.
export const DEFAULT_ANDROID_ABI = 'arm64-v8a';
export const ANDROID_ABIS = Object.freeze(['arm64-v8a', 'x86_64']);
const TARGETS = Object.freeze({
  'arm64-v8a': Object.freeze({ abi: 'arm64-v8a', rustTarget: 'aarch64-linux-android', tauriTarget: 'aarch64', tauriArch: 'arm64', elfMachine: 183, elfArchitecture: 'AArch64' }),
  x86_64: Object.freeze({ abi: 'x86_64', rustTarget: 'x86_64-linux-android', tauriTarget: 'x86_64', tauriArch: 'x86_64', elfMachine: 62, elfArchitecture: 'x86_64' }),
});
export function selectAndroidAbi(abi = DEFAULT_ANDROID_ABI) {
  if (typeof abi !== 'string' || !ANDROID_ABIS.includes(abi)) throw new Error('ABI must be arm64-v8a or x86_64.');
  return TARGETS[abi];
}

/** Shared ELF identity check only; APK program-header/range checks remain separate. */
export function androidElfIdentity(bytes, abi = DEFAULT_ANDROID_ABI) {
  const selected = selectAndroidAbi(abi);
  if (!Buffer.isBuffer(bytes) || bytes.length < 64) throw new Error('Selected library has no complete ELF64 header.');
  if (bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46 || bytes[4] !== 2 || bytes[5] !== 1 || bytes[6] !== 1) {
    throw new Error('Selected library is not ELF64 little-endian version one.');
  }
  if (bytes.readUInt16LE(16) !== 3 || bytes.readUInt16LE(18) !== selected.elfMachine || bytes.readUInt32LE(20) !== 1) {
    throw new Error('Selected library ELF identity does not match the selected Android ABI.');
  }
  return selected;
}
