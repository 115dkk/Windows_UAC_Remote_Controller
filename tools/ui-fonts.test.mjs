// SPDX-License-Identifier: GPL-2.0-or-later
// Authored source/packaging contracts, not glyph decoding or browser proof.
import assert from 'node:assert/strict';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { FONT_DIRECTORY, FONT_FILES, validateFontCss, validateFontManifest, verifyFontAssets, verifyUiFonts } from './ui-fonts.mjs';

const repository = fileURLToPath(new URL('../', import.meta.url));
const stylesheet = readFileSync(resolve(repository, 'ui/src/styles.css'), 'utf8');
const manifest = JSON.parse(readFileSync(resolve(repository, 'ui/public', FONT_DIRECTORY, 'manifest.json'), 'utf8'));

test('the four reviewed offline files, original license, weights and CSS contracts match', () => {
  const result = verifyUiFonts();
  assert.equal(result.source.files, 4);
  assert.equal(result.glyphsDecoded, false);
  assert.equal(result.renderingVerified, false);
  assert.deepEqual(result.copies, {});
});

test('manifest rejects changed hash, weight, byte count, omitted face, license or source pin', () => {
  const mutations = [
    (value) => { value.files[0].sha256 = '0'.repeat(64); },
    (value) => { value.files[1].weight = 650; },
    (value) => { value.files[2].bytes += 1; },
    (value) => { value.files.pop(); },
    (value) => { value.license.sha256 = '0'.repeat(64); },
    (value) => { value.upstreamCommit = 'main'; },
    (value) => { value.coverageObservation.renderingVerifiedByThisObservation = true; },
  ];
  for (const mutate of mutations) {
    const altered = structuredClone(manifest);
    mutate(altered);
    assert.throws(() => validateFontManifest(altered));
  }
});

test('client family cannot silently return to platform-first or phone-only fallback', () => {
  assert.throws(() => validateFontCss(stylesheet.replace('--font-ui: "IBM Plex Sans KR",', '--font-ui: "Segoe UI",')));
  assert.throws(() => validateFontCss(stylesheet.replace('font-family: var(--font-ui);', 'font-family: "Segoe UI";')));
  assert.throws(() => validateFontCss(stylesheet.replace(/(\.phone-shell\s*\{[^}]*?)font-family: var\(--font-ui\)/u, '$1font-family: Roboto')));
});

test('font faces reject CDN, local discovery, foreign path, fake weight, subset and duplicates', () => {
  const localSource = `url("/${FONT_DIRECTORY}/${FONT_FILES[0].file}")`;
  const mutations = [
    stylesheet.replace(localSource, 'url("https://example.invalid/font.woff2")'),
    stylesheet.replace(localSource, 'local("IBM Plex Sans KR")'),
    stylesheet.replace(localSource, 'url("/fonts/other.woff2")'),
    stylesheet.replace('font-weight: 400;', 'font-weight: 450;'),
    stylesheet.replace('font-style: normal;', 'font-style: normal; unicode-range: U+0000-007F;'),
    stylesheet.replace('font-display: swap;', 'font-display: swap; font-display: block;'),
    `${stylesheet}\n@import url("/another.css");`,
  ];
  for (const altered of mutations) assert.throws(() => validateFontCss(altered));
});

test('titles use the real SemiBold token while command/path monospace is preserved', () => {
  assert.doesNotThrow(() => validateFontCss(stylesheet));
  assert.throws(() => validateFontCss(stylesheet.replace('--weight-title: 600;', '--weight-title: 650;')));
  assert.throws(() => validateFontCss(stylesheet.replace('font-weight: var(--weight-title);', 'font-weight: 650;')));
  assert.throws(() => validateFontCss(stylesheet.replace('"Cascadia Code", Consolas, "Noto Sans Mono CJK KR", "Malgun Gothic", monospace', 'var(--font-ui)')));
});

test('built copies are required only when selected and are checked, never silently skipped', (context) => {
  const temporary = mkdtempSync(join(tmpdir(), 'uac-ui-fonts-'));
  context.after(() => {
    const target = resolve(temporary);
    assert.ok(target.startsWith(`${resolve(tmpdir())}${sep}uac-ui-fonts-`));
    assert.notEqual(target, resolve(repository));
    rmSync(target, { recursive: true, force: true });
  });
  const publicRoot = resolve(temporary, 'ui/public');
  mkdirSync(resolve(temporary, 'ui/src'), { recursive: true });
  cpSync(resolve(repository, 'ui/public', FONT_DIRECTORY), resolve(publicRoot, FONT_DIRECTORY), { recursive: true });
  writeFileSync(resolve(temporary, 'ui/src/styles.css'), stylesheet);
  assert.doesNotThrow(() => verifyUiFonts({ root: temporary }));
  assert.throws(() => verifyUiFonts({ root: temporary, built: 'production' }));
  cpSync(publicRoot, resolve(temporary, 'dist'), { recursive: true });
  assert.equal(verifyUiFonts({ root: temporary, built: 'production' }).copies.production.files, 4);
  assert.throws(() => verifyUiFonts({ root: temporary, built: 'both' }));
  cpSync(publicRoot, resolve(temporary, 'target/ui-qa'), { recursive: true });
  assert.equal(verifyUiFonts({ root: temporary, built: 'both' }).copies.qa.files, 4);

  const regular = resolve(temporary, 'dist', FONT_DIRECTORY, FONT_FILES[0].file);
  const altered = readFileSync(regular);
  altered[altered.length - 1] ^= 1;
  writeFileSync(regular, altered);
  assert.throws(() => verifyFontAssets(resolve(temporary, 'dist')), /SHA-256/u);
  rmSync(resolve(temporary, 'target/ui-qa', FONT_DIRECTORY, 'LICENSE.txt'));
  assert.throws(() => verifyFontAssets(resolve(temporary, 'target/ui-qa')));
  assert.throws(() => verifyUiFonts({ root: temporary, built: '../dist' }));
});
