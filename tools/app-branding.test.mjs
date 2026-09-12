// SPDX-License-Identifier: GPL-2.0-or-later
// Source/resource packaging contracts only, not an installed icon/launcher test.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const bytes = path => readFileSync(new URL(`../${path}`, import.meta.url));
const text = path => bytes(path).toString('utf8');
const res = 'src-tauri/gen/android/app/src/main/res';

test('PC, Android and client share the explicit UAC app name and source logo', () => {
  const config = JSON.parse(text('src-tauri/tauri.conf.json'));
  assert.equal(config.productName, 'UAC 원격 승인');
  assert.equal(config.app.windows[0].title, config.productName);
  assert.equal(config.identifier, 'dev.dkk115.uacremote');
  assert.match(text('ui/src/messages.ko.ts'), /appName: 'UAC 원격 승인'/u);
  assert.match(text(`${res}/values/strings.xml`), /name="app_name">"UAC 원격 승인"/u);
  assert.match(text('ui/index.html'), /<title>UAC 원격 승인<\/title>/u);
  assert.deepEqual(bytes('ui/public/app-logo.svg'), bytes('src-tauri/icons/source.svg'));
  assert.match(text('src-tauri/icons/source.svg'), /m40 51 12 12 22-23/u, 'approval check is present in the original vector');
});

test('every Android density uses generated project icons, including round and adaptive resources', () => {
  for (const density of ['mdpi', 'hdpi', 'xhdpi', 'xxhdpi', 'xxxhdpi']) {
    for (const name of ['ic_launcher', 'ic_launcher_round', 'ic_launcher_foreground']) {
      const path = `mipmap-${density}/${name}.png`;
      const png = bytes(`${res}/${path}`);
      assert.equal(png.subarray(1, 4).toString('ascii'), 'PNG');
      assert.ok(png.readUInt32BE(16) >= 48);
      assert.deepEqual(png, bytes(`src-tauri/icons/android/${path}`), path);
    }
  }
  for (const name of ['ic_launcher', 'ic_launcher_round']) {
    assert.deepEqual(bytes(`${res}/mipmap-anydpi-v26/${name}.xml`), bytes('src-tauri/icons/adaptive-icon.xml'));
  }
  assert.deepEqual(bytes(`${res}/drawable/ic_launcher_foreground_inset.xml`), bytes('src-tauri/icons/foreground-inset.xml'));
  assert.match(text(`${res}/values/ic_launcher_background.xml`), /#0b7285/u);
  assert.match(text('src-tauri/gen/android/app/src/main/AndroidManifest.xml'), /android:roundIcon="@mipmap\/ic_launcher_round"/u);
});

test('Windows bundle points to generated project PNG/ICO resources', () => {
  const config = JSON.parse(text('src-tauri/tauri.conf.json'));
  assert.equal(config.bundle.windows.nsis.installerIcon, 'icons/icon.ico');
  assert.equal(config.bundle.windows.nsis.uninstallerIcon, 'icons/icon.ico');
  for (const path of config.bundle.icon) assert.ok(bytes(`src-tauri/${path}`).length > 100, path);
  const ico = bytes('src-tauri/icons/icon.ico');
  assert.equal(ico.readUInt16LE(0), 0);
  assert.equal(ico.readUInt16LE(2), 1);
  assert.ok(ico.readUInt16LE(4) >= 4);
});
