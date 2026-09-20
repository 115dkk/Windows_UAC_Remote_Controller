// SPDX-License-Identifier: GPL-2.0-or-later
// Build-policy tests do not launch a browser or a native application.
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { resolveConfig } from 'vite';

const repository = fileURLToPath(new URL('../', import.meta.url));
async function configuration(mode, build = {}) {
  return resolveConfig({ configFile: resolve(repository, 'vite.config.ts'), mode, build }, 'build');
}

test('QA defaults to its separate output; product defaults to dist', async () => {
  const qa = await configuration('qa');
  const product = await configuration('production');
  assert.equal(resolve(qa.root, qa.build.outDir), resolve(repository, 'target/ui-qa'));
  assert.equal(resolve(product.root, product.build.outDir), resolve(repository, 'dist'));
});

test('QA rejects production, case-variant and arbitrary output overrides before build', async () => {
  for (const outDir of ['../dist', '../DIST', '../other-gallery']) {
    await assert.rejects(configuration('qa', { outDir }), /may only build into target\/ui-qa/u);
  }
});

test('product output guard rejects either fixture module and accepts normal client code', async () => {
  const product = await configuration('production');
  const guard = product.plugins.find((plugin) => plugin.name === 'isolate-gallery-from-product');
  assert.equal(typeof guard?.generateBundle, 'function');
  const generate = guard.generateBundle;
  const bundle = (id) => ({ 'client.js': { type: 'chunk', modules: { [id]: {} } } });
  for (const id of ['/repo/ui/src/qa-fixtures.ts', 'C:\\repo\\ui\\src\\qa-preview.tsx']) {
    assert.throws(() => generate({}, bundle(id)), /forbidden in a product build/u);
  }
  assert.doesNotThrow(() => generate({}, bundle('/repo/ui/src/main.tsx')));
});
