// SPDX-License-Identifier: GPL-2.0-or-later
// Metadata inventory, not a legal-compatibility decision or source-bundle generator.
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
// Shared locked metadata observation. Importing this module performs no Cargo
// invocation or filesystem mutation; the standalone command below is unchanged.
export function readLockedCargoMetadata({ cwd = root, spawn = spawnSync, stderr = process.stderr, offline = false } = {}) {
  const result = spawn('cargo', ['metadata', '--format-version', '1', '--locked', ...(offline ? ['--offline'] : [])], {
    cwd,
    encoding: 'utf8',
    timeout: 180_000,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.signal || result.status !== 0) {
    stderr.write(result.stderr ?? '');
    throw new Error(`Cargo metadata failed: ${result.error?.message ?? result.signal ?? result.status}`);
  }
  return JSON.parse(result.stdout);
}

export function licenseInventoryFromMetadata(metadata) {
  const workspace = new Set(metadata.workspace_members);
  const inventory = metadata.packages.map((package_) => ({
    name: package_.name,
    version: package_.version,
    workspace: workspace.has(package_.id),
    license: package_.license,
    hasLicenseFile: package_.license_file !== null,
    source: package_.source,
  })).sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));

  for (const package_ of inventory) {
    if (package_.workspace && package_.license !== 'GPL-2.0-or-later') {
      throw new Error(`Unexpected project license: ${package_.name}`);
    }
    if (!package_.license && !package_.hasLicenseFile) {
      throw new Error(`Missing dependency license metadata: ${package_.name}`);
    }
  }
  return inventory;
}

export function runLicenseInventory() {
  const inventory = licenseInventoryFromMetadata(readLockedCargoMetadata());
  const output = join(root, 'target', 'quality');
  mkdirSync(output, { recursive: true });
  writeFileSync(join(output, 'license-inventory.json'), `${JSON.stringify(inventory, null, 2)}\n`);
  process.stdout.write(`License metadata recorded for ${inventory.length} packages; project crates use GPL-2.0-or-later.\n`);
  process.stdout.write('This does not yet prove distribution compatibility or fulfill corresponding-source obligations.\n');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) runLicenseInventory();
