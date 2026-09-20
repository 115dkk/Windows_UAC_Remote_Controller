// SPDX-License-Identifier: GPL-2.0-or-later
// ROOT only. Deterministic vector compilation, no image-generation service.
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const output = resolve(root, 'target/app-icons');
execFileSync(process.execPath, ['node_modules/@tauri-apps/cli/tauri.js', 'icon',
  'src-tauri/icons/manifest.json', '--output', output], { cwd: root, stdio: 'inherit', windowsHide: true });
const copy = (from, to) => { mkdirSync(dirname(to), { recursive: true }); copyFileSync(from, to); };
for (const file of ['32x32.png', '64x64.png', '128x128.png', '128x128@2x.png', 'icon.png', 'icon.ico',
  'StoreLogo.png', ...[30, 44, 71, 89, 107, 142, 150, 284, 310].map(size => `Square${size}x${size}Logo.png`)]) {
  copy(resolve(output, file), resolve(root, 'src-tauri/icons', file));
}
const androidResources = ['src-tauri/icons/android', 'src-tauri/gen/android/app/src/main/res'];
for (const resources of androidResources) {
  for (const density of ['mdpi', 'hdpi', 'xhdpi', 'xxhdpi', 'xxxhdpi']) {
    for (const name of ['ic_launcher', 'ic_launcher_round', 'ic_launcher_foreground']) {
      const file = `mipmap-${density}/${name}.png`;
      copy(resolve(output, 'android', file), resolve(root, resources, file));
    }
  }
  for (const file of ['values/ic_launcher_background.xml']) {
    copy(resolve(output, 'android', file), resolve(root, resources, file));
  }
  for (const name of ['ic_launcher', 'ic_launcher_round']) {
    copy(resolve(root, 'src-tauri/icons/adaptive-icon.xml'), resolve(root, resources, `mipmap-anydpi-v26/${name}.xml`));
  }
  copy(resolve(root, 'src-tauri/icons/foreground-inset.xml'), resolve(root, resources, 'drawable/ic_launcher_foreground_inset.xml'));
}
copy(resolve(root, 'src-tauri/icons/source.svg'), resolve(root, 'ui/public/app-logo.svg'));
process.stdout.write('Windows icons, Android launcher/adaptive resources and client logo synchronized.\n');
