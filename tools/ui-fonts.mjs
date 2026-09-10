// SPDX-License-Identifier: GPL-2.0-or-later
// ROOT/CI packaging checks only: no glyph decoder or rendered-font verdict.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repository = fileURLToPath(new URL('../', import.meta.url));
export const FONT_DIRECTORY = 'fonts/ibm-plex-sans-kr';
export const FONT_FAMILY = 'IBM Plex Sans KR';
export const FONT_STACK = '"IBM Plex Sans KR", "Noto Sans KR", "Malgun Gothic", sans-serif';
export const FONT_COMMIT = '1da12f02587b630c07e92692d21492d722f53614';
export const LICENSE_SHA256 = 'd741e57d5f865e294df801f96b7b5161a88b211df65887e4358d271c9fc5fb4f';
export const FONT_FILES = Object.freeze([
  { file: 'IBMPlexSansKR-Regular.woff2', weight: 400, style: 'normal', bytes: 438540, sha256: '055a35664c3c3965161c92292504c5633ba9604ec904edc1ed799bf2a436276d' },
  { file: 'IBMPlexSansKR-Medium.woff2', weight: 500, style: 'normal', bytes: 439816, sha256: 'c00dcd8a9c32a6b6ab8c6b3119e68b3d7aa6eba6f4441d5493019cc019dcdd1e' },
  { file: 'IBMPlexSansKR-SemiBold.woff2', weight: 600, style: 'normal', bytes: 434484, sha256: '5ad7db28ba74d59fe14c260205c62ddb701320f4f098d8a45ef2757bebc29666' },
  { file: 'IBMPlexSansKR-Bold.woff2', weight: 700, style: 'normal', bytes: 370492, sha256: 'cf874a368dc2c2c0e4d1933c35611b849e48942023bfdd1fa11128475dbc4860' },
].map(Object.freeze));

function readBounded(path, maximum) {
  const metadata = lstatSync(path);
  assert.ok(metadata.isFile() && !metadata.isSymbolicLink(), 'Font contract input must be a regular file.');
  assert.ok(metadata.size > 0 && metadata.size <= maximum, 'Font contract input size is out of bounds.');
  const bytes = readFileSync(path);
  assert.equal(bytes.length, metadata.size, 'Font contract input size changed.');
  return bytes;
}

function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

export function validateFontManifest(manifest) {
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.family, FONT_FAMILY);
  assert.equal(manifest.package, '@ibm/plex-sans-kr@1.1.0');
  assert.equal(manifest.upstreamRepository, 'https://github.com/IBM/plex');
  assert.equal(manifest.upstreamCommit, FONT_COMMIT);
  assert.equal(manifest.upstreamDirectory, 'packages/plex-sans-kr/fonts/complete/woff2/hinted');
  assert.equal(manifest.modified, false);
  assert.deepEqual(manifest.files, FONT_FILES, 'Manifest must preserve the exact four reviewed file/weight/byte/hash pins.');
  assert.deepEqual(manifest.license, {
    spdx: 'OFL-1.1', reservedFontName: 'Plex', file: 'LICENSE.txt', sha256: LICENSE_SHA256,
    upstreamSha256: '7e6b2818edbd8f6a01ae80641cc8f16a51080d08fb4e532be3a0b6f74adb07da',
    normalization: 'LF line endings and trailing-space removal only; notice text unchanged',
  });
  // Attribution is not a glyph-decoding check. The byte pins bind ROOT's
  // separately reported inspection; this tool never promotes it to CI proof.
  assert.equal(manifest.coverageObservation?.observer, 'ROOT');
  assert.equal(manifest.coverageObservation?.renderingVerifiedByThisObservation, false);
}

function declarations(body) {
  const result = new Map();
  for (const raw of body.split(';').filter((item) => item.trim())) {
    const colon = raw.indexOf(':');
    assert.ok(colon > 0, 'Malformed source CSS declaration.');
    const name = raw.slice(0, colon).trim();
    assert.ok(!result.has(name), 'Duplicate source CSS declaration.');
    result.set(name, raw.slice(colon + 1).trim());
  }
  return result;
}

/** Narrow contracts for this repository's ordinary, non-nested source rules. */
export function validateFontCss(source) {
  assert.ok(typeof source === 'string' && source.length <= 128 * 1024);
  const css = source.replace(/\/\*[\s\S]*?\*\//gu, '');
  assert.doesNotMatch(css, /@import\b|\blocal\s*\(|https?:|url\(\s*["']?\/\//iu, 'No imported/CDN/installed font source.');
  const faces = [...css.matchAll(/@font-face\s*\{([^{}]*)\}/gu)].map((match) => declarations(match[1]));
  assert.equal(faces.length, FONT_FILES.length, 'Exactly four local font faces are required.');
  for (const [index, font] of FONT_FILES.entries()) {
    const face = faces[index];
    assert.equal(face.get('font-family'), '"IBM Plex Sans KR"');
    assert.equal(face.get('font-style'), 'normal');
    assert.equal(face.get('font-weight'), String(font.weight));
    assert.equal(face.get('font-display'), 'swap');
    assert.equal(face.get('src'), `url("/${FONT_DIRECTORY}/${font.file}") format("woff2")`);
    assert.equal(face.size, 5, 'Do not silently subset or override a reviewed font face.');
  }
  const bodyFor = (selector) => {
    const escaped = selector.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
    const match = css.match(new RegExp(`(?:^|[}\\n])\\s*${escaped}\\s*\\{([^{}]*)\\}`, 'u'));
    assert.ok(match, `Missing font contract selector: ${selector}`);
    return declarations(match[1]);
  };
  const root = bodyFor(':root');
  assert.equal(root.get('--font-ui'), FONT_STACK);
  assert.equal(root.get('--weight-title'), '600');
  assert.equal(root.get('font-family'), 'var(--font-ui)');
  assert.equal(root.get('font-synthesis'), 'none');
  assert.equal(bodyFor('.phone-shell').get('font-family'), 'var(--font-ui)');
  for (const selector of ['h1', '.app-brand', '.program-name', '.launch-brand']) {
    assert.equal(bodyFor(selector).get('font-weight'), 'var(--weight-title)');
  }
  assert.doesNotMatch(css, /font-weight\s*:\s*650\b/u);
  assert.equal(bodyFor('p').get('word-break'), 'keep-all');
  assert.equal(bodyFor('body').get('word-break'), 'keep-all');
  assert.equal(bodyFor('p').get('overflow-wrap'), 'anywhere');
  assert.equal(bodyFor('.status-facts dt').get('word-break'), 'keep-all');
  assert.equal(bodyFor('.status-facts dt').get('overflow-wrap'), 'anywhere');
  assert.equal(bodyFor('.path-output, .command-region pre').get('font-family'), '"Cascadia Code", Consolas, "Noto Sans Mono CJK KR", "Malgun Gothic", monospace');
  assert.equal(bodyFor('.path-output, .command-region pre').get('word-break'), 'break-word');
}

export function verifyFontAssets(publicDirectory) {
  for (const font of FONT_FILES) {
    const bytes = readBounded(resolve(publicDirectory, FONT_DIRECTORY, font.file), 1024 * 1024);
    assert.equal(bytes.length, font.bytes, `Unexpected font length: ${font.file}`);
    assert.equal(sha256(bytes), font.sha256, `Unexpected font SHA-256: ${font.file}`);
  }
  const license = readBounded(resolve(publicDirectory, FONT_DIRECTORY, 'LICENSE.txt'), 16 * 1024);
  assert.equal(sha256(license), LICENSE_SHA256, 'The original font license must travel with every copy.');
  assert.match(license.toString('utf8'), /SIL OPEN FONT LICENSE Version 1\.1/u);
  assert.match(license.toString('utf8'), /Reserved Font Name "Plex"/u);
  const manifest = JSON.parse(readBounded(resolve(publicDirectory, FONT_DIRECTORY, 'manifest.json'), 16 * 1024).toString('utf8'));
  validateFontManifest(manifest);
  return { files: FONT_FILES.length, licenseSha256: LICENSE_SHA256 };
}

export function verifyUiFonts({ root = repository, built = 'none' } = {}) {
  assert.ok(['none', 'production', 'qa', 'both'].includes(built), 'Unknown built font target.');
  const source = verifyFontAssets(resolve(root, 'ui/public'));
  validateFontCss(readBounded(resolve(root, 'ui/src/styles.css'), 128 * 1024).toString('utf8'));
  const copies = {};
  if (built === 'production' || built === 'both') copies.production = verifyFontAssets(resolve(root, 'dist'));
  if (built === 'qa' || built === 'both') copies.qa = verifyFontAssets(resolve(root, 'target/ui-qa'));
  return { scope: 'FONT_BYTE_AND_SOURCE_CONTRACT_ONLY', source, copies, glyphsDecoded: false, renderingVerified: false };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  assert.ok(args.length <= 1 && (args.length === 0 || /^--built=(production|qa|both)$/u.test(args[0])),
    'usage: node tools/ui-fonts.mjs [--built=production|qa|both]');
  process.stdout.write(`${JSON.stringify(verifyUiFonts({ built: args[0]?.slice('--built='.length) ?? 'none' }), null, 2)}\n`);
}
