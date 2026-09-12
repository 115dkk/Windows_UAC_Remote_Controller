// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const locales = ['ko', 'en', 'fr', 'de', 'ja', 'zh-Hans', 'zh-Hant', 'es', 'pt-BR', 'pt-PT', 'ar'];
const catalogs = new Map(await Promise.all(locales.map(async locale => [
  locale, JSON.parse(await readFile(new URL(`../locales/${locale}.json`, import.meta.url), 'utf8')),
])));
const source = catalogs.get('ko');
const keys = Object.keys(source).sort();
const placeholders = text => [...text.matchAll(/\{[^{}]*\}/gu)].map(match => match[0]).sort();
const fixedTokens = text => [...text.matchAll(/\b(?:UAC|Windows|Android)\b|(?:\d{1,3}\.){3}\d{1,3}:\d+|\[2001:db8::10\]:443|\b7443\b|\[U\+[0-9A-F]{4,6}\]/gu)]
  .map(match => match[0]).sort();

test('all supported catalogs contain exactly the authored source keys', () => {
  assert.ok(keys.length >= 342, 'do not replace the product catalog with a partial fixture');
  for (const locale of locales) {
    const catalog = catalogs.get(locale);
    assert.ok(catalog !== null && typeof catalog === 'object' && !Array.isArray(catalog), locale);
    assert.deepEqual(Object.keys(catalog).sort(), keys, `${locale}: key coverage`);
  }
});

for (const locale of locales) {
  test(`${locale}: plain translated text preserves placeholders and authored technical tokens`, () => {
    const catalog = catalogs.get(locale);
    for (const key of keys) {
      const value = catalog[key];
      assert.equal(typeof value, 'string', `${locale}: ${key}`);
      assert.ok(value.trim().length > 0, `${locale}: empty translation for ${key}`);
      assert.doesNotMatch(value, /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u206f]/u, `${locale}: authored bidi control`);
      assert.doesNotMatch(value, /<\/?[A-Za-z][^>]*>|<!--|<!doctype/iu, `${locale}: authored HTML`);
      if (locale !== 'ko') assert.doesNotMatch(value, /[\u1100-\u11ff\u3130-\u318f\uac00-\ud7af]/u, `${locale}: untranslated Korean value for ${key}`);
      assert.deepEqual(placeholders(value), placeholders(source[key]), `${locale}: placeholder multiset for ${key}`);
      // Product names and literal addresses are fixed; common nouns/acronyms
      // such as PC/QR may legitimately use idiomatic local-language words.
      for (const token of new Set(fixedTokens(source[key]))) {
        assert.ok(value.includes(token), `${locale}: changed technical token ${token} in ${key}`);
      }
      assert.equal(value.split('\n').length, source[key].split('\n').length, `${locale}: explicit line breaks for ${key}`);
    }
  });
}

test('region variants remain distinct authored catalogs', () => {
  assert.notDeepEqual(catalogs.get('pt-BR'), catalogs.get('pt-PT'));
  assert.notDeepEqual(catalogs.get('zh-Hans'), catalogs.get('zh-Hant'));
  assert.equal(catalogs.get('pt-BR')['저장'], 'Salvar');
  assert.equal(catalogs.get('pt-PT')['저장'], 'Guardar');
});
