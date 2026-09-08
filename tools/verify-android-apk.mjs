// SPDX-License-Identifier: GPL-2.0-or-later
// ROOT/CI only. Passive Linux APK inspection; never extracts files or loads code.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream, lstatSync } from 'node:fs';
import { posix, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const EXPECTED_LIBRARIES = Object.freeze([
  'lib/arm64-v8a/libcontroller_app_lib.so',
  'lib/arm64-v8a/libuac_android_controller.so',
  'lib/arm64-v8a/libjnidispatch.so',
]);
export const LIMITS = Object.freeze({
  apkBytes: 512 * 1024 * 1024,
  libraryBytes: 256 * 1024 * 1024,
  listingBytes: 4 * 1024 * 1024,
  entries: 16_384,
  memberNameBytes: 1024,
  programHeaders: 128,
  commandMillis: 30_000,
});
const ELF_HEADER_BYTES = 64;
const PROGRAM_HEADER_BYTES = 56;
const U64_MAX = (1n << 64n) - 1n;
const MIN_LOAD_ALIGNMENT = 16_384n;

export class ApkInspectionError extends Error {
  constructor(message) { super(message); this.name = 'ApkInspectionError'; }
}
const reject = (message) => { throw new ApkInspectionError(message); };
const hex = (number) => `0x${number.toString(16)}`;

/** ELF program-header shape only, not relocation/symbol/runtime compatibility. */
export function checkElf64Arm64(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length < ELF_HEADER_BYTES || bytes.length > LIMITS.libraryBytes) {
    reject('Selected library is missing or exceeds the bounded ELF input size.');
  }
  if (bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46
      || bytes[4] !== 2 || bytes[5] !== 1 || bytes[6] !== 1) {
    reject('Selected library is not ELF64 little-endian version one.');
  }
  if (bytes.readUInt16LE(16) !== 3 || bytes.readUInt16LE(18) !== 183 || bytes.readUInt32LE(20) !== 1) {
    reject('Selected library is not an AArch64 ELF shared object.');
  }
  const headerSize = bytes.readUInt16LE(52);
  const entrySize = bytes.readUInt16LE(54);
  const entryCount = bytes.readUInt16LE(56);
  const tableOffset = bytes.readBigUInt64LE(32);
  if (headerSize !== ELF_HEADER_BYTES || entrySize !== PROGRAM_HEADER_BYTES
      || entryCount === 0 || entryCount > LIMITS.programHeaders) {
    reject('ELF header or program-header count/stride is unsupported.');
  }
  const tableEnd = tableOffset + BigInt(entrySize) * BigInt(entryCount);
  if (tableOffset < BigInt(headerSize) || tableEnd > BigInt(bytes.length)) {
    reject('ELF program-header table is outside the selected library.');
  }
  const loads = [];
  let previousAddress = null;
  for (let index = 0; index < entryCount; index += 1) {
    const at = Number(tableOffset) + index * entrySize;
    if (bytes.readUInt32LE(at) !== 1) continue;
    const flags = bytes.readUInt32LE(at + 4);
    const offset = bytes.readBigUInt64LE(at + 8);
    const address = bytes.readBigUInt64LE(at + 16);
    const fileSize = bytes.readBigUInt64LE(at + 32);
    const memorySize = bytes.readBigUInt64LE(at + 40);
    const alignment = bytes.readBigUInt64LE(at + 48);
    if (fileSize > memorySize || offset > BigInt(bytes.length)
        || offset + fileSize > BigInt(bytes.length) || address + memorySize > U64_MAX) {
      reject('ELF PT_LOAD has an invalid file or memory range.');
    }
    if (alignment < MIN_LOAD_ALIGNMENT || (alignment & (alignment - 1n)) !== 0n
        || address % alignment !== offset % alignment) {
      reject('ELF PT_LOAD does not have valid power-of-two 16KiB-or-greater alignment and congruence.');
    }
    if (previousAddress !== null && address < previousAddress) {
      reject('ELF PT_LOAD virtual addresses are not in ascending order.');
    }
    previousAddress = address;
    loads.push({ index, flags, offset: hex(offset), virtualAddress: hex(address),
      fileSize: hex(fileSize), memorySize: hex(memorySize), alignment: hex(alignment) });
  }
  if (loads.length === 0) reject('ELF contains no PT_LOAD segment.');
  return { format: 'ELF64LE', type: 'ET_DYN', machine: 183, architecture: 'AArch64',
    bytes: bytes.length, programHeaderCount: entryCount, loadSegments: loads };
}

/** Parses unzip's filename-only listing, not ZIP binary structures. */
export function inspectArchiveListing(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > LIMITS.listingBytes) {
    reject('APK member listing is empty or exceeds its bound.');
  }
  let listing;
  try { listing = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { reject('APK member listing is not valid UTF-8.'); }
  // Linux unzip -Z1 emits LF separators. CR/control bytes are not member names
  // accepted by this CI profile; no ambiguous platform filename rewriting.
  if (/[\u0000-\u0009\u000b-\u001f\u007f]/u.test(listing)) reject('APK member listing contains control characters.');
  const names = listing.endsWith('\n') ? listing.slice(0, -1).split('\n') : listing.split('\n');
  if (names.length > LIMITS.entries) reject('APK contains too many listed members.');
  const seen = new Set();
  let arm64LibraryCount = 0;
  for (const name of names) {
    if (name.length === 0 || Buffer.byteLength(name, 'utf8') > LIMITS.memberNameBytes
        || name.startsWith('/') || name.includes('\\') || name.includes(':')) {
      reject('APK member name is malformed or excessive.');
    }
    const parts = name.endsWith('/') ? name.slice(0, -1).split('/') : name.split('/');
    if (parts.some((part) => part === '' || part === '.' || part === '..')) reject('APK member path is not a normal relative path.');
    if (seen.has(name)) reject('APK has a duplicate member name, including possible duplicate native targets.');
    seen.add(name);
    if (parts[0] !== 'lib') continue;
    if (name === 'lib/') continue;
    if (parts[1] !== 'arm64-v8a') reject('APK advertises an ABI other than arm64-v8a.');
    if (name === 'lib/arm64-v8a/') continue;
    if (parts.length !== 3 || name.endsWith('/') || !/^lib[A-Za-z0-9_.+-]+\.so$/u.test(parts[2])) {
      reject('APK native library layout is unsupported.');
    }
    arm64LibraryCount += 1;
  }
  if (EXPECTED_LIBRARIES.some((name) => !seen.has(name))) reject('APK is missing a required arm64 native library.');
  return { entryCount: names.length, advertisedAbis: ['arm64-v8a'], arm64LibraryCount,
    additionalArm64Libraries: arm64LibraryCount - EXPECTED_LIBRARIES.length };
}

export function apkPathFromArguments(args, cwd = process.cwd(), platform = process.platform) {
  if (platform !== 'linux') reject('APK inspection CLI supports the CI Linux runner only.');
  if (!Array.isArray(args) || args.length !== 1 || typeof args[0] !== 'string') reject('Usage: node tools/verify-android-apk.mjs <one-explicit-apk-path>');
  const value = args[0];
  if (value.length === 0 || value.length > 4096 || /[\u0000-\u001f\u007f*?\[\]]/u.test(value)
      || value.startsWith('-') || !value.toLowerCase().endsWith('.apk') || !posix.isAbsolute(cwd)) {
    reject('APK path must be explicit, bounded, non-wildcard and end in .apk.');
  }
  return posix.resolve(cwd, value);
}

/** Preserve configured environment except unzip option injection and locale. */
export function unzipEnvironment(incoming) {
  return { ...incoming, UNZIP: '', UNZIPOPT: '', ZIPINFO: '', ZIPINFOOPT: '', LC_ALL: 'C' };
}

/** Only two passive command shapes, and only the three fixed extraction targets. */
export function readUnzipOutput(apk, member = null, { spawn = spawnSync, environment = process.env } = {}) {
  if (apkPathFromArguments([apk], '/', 'linux') !== apk) reject('unzip requires the validated absolute APK path.');
  if (member !== null && !EXPECTED_LIBRARIES.includes(member)) reject('Only fixed required library members may be streamed.');
  const args = member === null ? ['-Z1', apk] : ['-p', apk, member];
  const maximum = member === null ? LIMITS.listingBytes : LIMITS.libraryBytes;
  let result;
  try {
    result = spawn('unzip', args, {
      shell: false, env: unzipEnvironment(environment), stdio: ['ignore', 'pipe', 'pipe'],
      timeout: LIMITS.commandMillis, killSignal: 'SIGKILL', maxBuffer: maximum,
    });
  } catch { reject('unzip did not start or complete successfully.'); }
  if (!result || result.error || result.signal || result.status !== 0) reject('unzip failed, timed out, or exceeded its output limit.');
  if (!Buffer.isBuffer(result.stdout) || result.stdout.length === 0 || result.stdout.length > maximum) reject('unzip output is missing or exceeds its bound.');
  if (!Buffer.isBuffer(result.stderr) || result.stderr.length !== 0) reject('unzip emitted diagnostics; the archive was not accepted.');
  return result.stdout;
}

function apkMetadata(path) {
  let metadata;
  try { metadata = lstatSync(path, { bigint: true }); }
  catch { reject('The explicit APK file is unavailable.'); }
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size <= 0n || metadata.size > BigInt(LIMITS.apkBytes)) {
    reject('APK must be a bounded, nonempty regular file, not a symlink.');
  }
  return metadata;
}

async function apkHash(path, expectedSize) {
  const digest = createHash('sha256');
  let bytes = 0;
  const stream = createReadStream(path, { highWaterMark: 64 * 1024, signal: AbortSignal.timeout(LIMITS.commandMillis) });
  try {
    for await (const chunk of stream) {
      bytes += chunk.length;
      if (bytes > LIMITS.apkBytes || BigInt(bytes) > expectedSize) reject('APK changed or exceeded its bound during hashing.');
      digest.update(chunk);
    }
  } catch (error) {
    stream.destroy();
    if (error instanceof ApkInspectionError) throw error;
    reject('APK hashing failed or timed out.');
  }
  if (BigInt(bytes) !== expectedSize) reject('APK size changed during hashing.');
  return digest.digest('hex');
}

export async function inspectApk(path) {
  const apk = apkPathFromArguments([path]);
  const before = apkMetadata(apk);
  const sha256 = await apkHash(apk, before.size);
  const archive = inspectArchiveListing(readUnzipOutput(apk));
  const libraries = [];
  for (const member of EXPECTED_LIBRARIES) {
    const bytes = readUnzipOutput(apk, member);
    libraries.push({ member, sha256: createHash('sha256').update(bytes).digest('hex'), elf: checkElf64Arm64(bytes) });
  }
  const after = apkMetadata(apk);
  if (['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].some((field) => before[field] !== after[field])) {
    reject('APK metadata changed during inspection; no stable artifact was accepted.');
  }
  return {
    schemaVersion: 1, scope: 'passive APK selected-library structure only',
    apk: { bytes: Number(before.size), sha256 }, archive, libraries,
    limitations: ['No manifest/signature/release verification', 'Additional same-ABI libraries are counted but not ELF-inspected',
      'No ZIP mmap/zipalign proof', 'No native loading, 16KiB device behavior, authentication or UAC proof'],
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const apk = apkPathFromArguments(process.argv.slice(2));
    process.stdout.write(`${JSON.stringify(await inspectApk(apk), null, 2)}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof ApkInspectionError ? error.message : 'APK structural inspection failed; no artifact accepted.'}\n`);
    process.exitCode = 1;
  }
}
