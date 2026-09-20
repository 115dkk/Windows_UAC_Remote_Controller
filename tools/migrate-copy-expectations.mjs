// SPDX-License-Identifier: GPL-2.0-or-later
// One-shot mechanical update of Korean UI expectations after catalog editing.
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
const catalog = JSON.parse(readFileSync('locales/ko.json', 'utf8'));
for (const name of readdirSync('ui/src')) {
  if (!name.endsWith('.test.tsx') || name.startsWith('i18n')) continue;
  const path = `ui/src/${name}`;
  let source = readFileSync(path, 'utf8').replaceAll("from './messages.ko'", "from './messages'");
  // Complete literals only: never modify original-data sentinels or regex code.
  source = source.replace(/'([^'\n]*)'/gu, (original, text) => {
    const value = catalog[text];
    return value && !value.includes("'") ? `'${value}'` : original;
  });
  writeFileSync(path, source);
}
for (const path of ['tools/ui-gallery/gallery.spec.ts', 'tools/ui-gallery/phone-service.ts']) {
  const source = readFileSync(path, 'utf8').replace(/'([^'\n]*)'/gu, (original, text) => {
    const value = catalog[text];
    return value && !value.includes("'") ? `'${value}'` : original;
  });
  writeFileSync(path, source);
}
