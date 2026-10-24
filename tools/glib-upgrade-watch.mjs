// SPDX-License-Identifier: GPL-2.0-or-later
// deny.toml tolerates exactly one advisory, RUSTSEC-2024-0429 (glib < 0.20,
// GHSA-wrw7-89jp-8q8g), because no release of the crates that pull glib in has
// moved past it. This watch fails as soon as that stops being true:
//
// - when the newest releases of those dependencies resolve without glib < 0.20,
//   an upgrade exists and the exception is no longer justified;
// - when Cargo.lock itself no longer holds glib < 0.20, the exception and this
//   watch are both obsolete (Cargo Deny's unused-ignored-advisory fails too).
//
// It never edits the repository. The probe is a throwaway package in the
// system temporary directory whose dependencies are the workspace's own
// declarations of the glib-pulling crates, with the same features, raised to
// "the newest release at or above the locked one". Patches and vendored copies
// do not apply to it, so it sees upstream exactly as an upgrade would.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));

export const TOLERATED = Object.freeze({
  advisory: 'RUSTSEC-2024-0429',
  alias: 'GHSA-wrw7-89jp-8q8g',
  crate: 'glib',
  patched: Object.freeze([0, 20, 0]),
});

/** Reads the [[package]] tables of a Cargo.lock. */
export function parseLock(text) {
  const packages = [];
  let current = null;
  let inDependencies = false;
  for (const raw of text.split(/\r?\n/u)) {
    const line = raw.trim();
    if (inDependencies) {
      if (line === ']') { inDependencies = false; continue; }
      const entry = /^"([^"]+)",?$/u.exec(line);
      if (!entry) throw new Error(`unreadable Cargo.lock dependency line: ${line}`);
      current.dependencies.push(entry[1]);
      continue;
    }
    if (line === '[[package]]') {
      current = { name: null, version: null, source: null, dependencies: [] };
      packages.push(current);
      continue;
    }
    // Any other table ([metadata] in old lockfiles) ends the package list.
    if (line.startsWith('[')) current = null;
    if (!current) continue;
    const field = /^(name|version|source) = "([^"]*)"$/u.exec(line);
    if (field) { current[field[1]] = field[2]; continue; }
    if (line === 'dependencies = [') inDependencies = true;
    else if (/^dependencies = \[(.*)\]$/u.test(line)) {
      for (const entry of line.slice('dependencies = ['.length, -1).matchAll(/"([^"]+)"/gu)) current.dependencies.push(entry[1]);
    }
  }
  if (packages.some((pkg) => !pkg.name || !pkg.version)) throw new Error('Cargo.lock has a [[package]] without name or version');
  return packages;
}

function versionTriple(version) {
  const triple = version.split(/[-+]/u)[0].split('.').map(Number);
  if (triple.length !== 3 || triple.some((part) => !Number.isSafeInteger(part))) throw new Error(`unreadable version ${version}`);
  return triple;
}

function below(version, bound) {
  const triple = versionTriple(version);
  for (let index = 0; index < 3; index += 1) {
    if (triple[index] !== bound[index]) return triple[index] < bound[index];
  }
  return false;
}

const key = (pkg) => `${pkg.name} ${pkg.version}`;

/** The locked packages the tolerated advisory names. */
export function vulnerable(packages, tolerated = TOLERATED) {
  return packages.filter((pkg) => pkg.name === tolerated.crate && below(pkg.version, tolerated.patched));
}

/** Resolves a lock dependency entry ("name", "name version" or "name version (source)"). */
function resolveEntry(packages, entry) {
  const parts = /^(\S+)(?: (\S+))?(?: \((.+)\))?$/u.exec(entry);
  if (!parts) throw new Error(`unreadable Cargo.lock dependency "${entry}"`);
  const [, name, version, source] = parts;
  const matches = packages.filter((pkg) => pkg.name === name
    && (version === undefined || pkg.version === version)
    && (source === undefined || pkg.source === source));
  if (matches.length !== 1) throw new Error(`Cargo.lock dependency "${entry}" does not name exactly one package`);
  return matches[0];
}

/** Keys of every locked package that reaches a vulnerable one, the vulnerable ones included. */
export function pullers(packages, tolerated = TOLERATED) {
  const parents = new Map();
  for (const pkg of packages) {
    for (const entry of pkg.dependencies) {
      const child = key(resolveEntry(packages, entry));
      if (!parents.has(child)) parents.set(child, []);
      parents.get(child).push(key(pkg));
    }
  }
  const reached = new Set(vulnerable(packages, tolerated).map(key));
  const queue = [...reached];
  while (queue.length > 0) {
    for (const parent of parents.get(queue.shift()) ?? []) {
      if (!reached.has(parent)) { reached.add(parent); queue.push(parent); }
    }
  }
  return reached;
}

/**
 * The workspace members' own registry dependency declarations that lead to a
 * vulnerable package, each with the version the lock resolved for it.
 * `members` is `packages` from `cargo metadata --no-deps`.
 */
export function pullingDeclarations(members, packages, tolerated = TOLERATED) {
  const reached = pullers(packages, tolerated);
  const declarations = new Map();
  for (const member of members) {
    const locked = packages.find((pkg) => pkg.name === member.name && pkg.version === member.version && pkg.source === null);
    if (!locked) throw new Error(`workspace member ${member.name} ${member.version} is not in Cargo.lock`);
    for (const dependency of member.dependencies) {
      if (dependency.path) continue;
      const entry = locked.dependencies.find((candidate) => candidate.split(' ')[0] === dependency.name);
      if (!entry) continue;
      const target = resolveEntry(packages, entry);
      if (!reached.has(key(target))) continue;
      const previous = declarations.get(dependency.name);
      const features = new Set([...(previous?.features ?? []), ...dependency.features]);
      declarations.set(dependency.name, {
        name: dependency.name,
        locked: target.version,
        defaultFeatures: (previous?.defaultFeatures ?? false) || dependency.uses_default_features,
        features: [...features].sort(),
      });
    }
  }
  return [...declarations.values()].sort((left, right) => left.name.localeCompare(right.name));
}

/** Cargo.toml of the throwaway probe package. */
export function probeManifest(declarations) {
  const lines = [
    '[package]',
    'name = "glib-upgrade-probe"',
    'version = "0.0.0"',
    'edition = "2021"',
    'publish = false',
    '',
    '[workspace]',
    '',
    '[dependencies]',
  ];
  for (const declaration of declarations) {
    const features = declaration.features.map((feature) => JSON.stringify(feature)).join(', ');
    lines.push(`${declaration.name} = { version = ${JSON.stringify(`>=${declaration.locked}`)}, default-features = ${declaration.defaultFeatures}, features = [${features}] }`);
  }
  return `${lines.join('\n')}\n`;
}

/** The verdict; `ok` false fails the step. */
export function decide({ lockVulnerable, declarations, probePackages, tolerated = TOLERATED }) {
  const id = `${tolerated.advisory} (${tolerated.alias})`;
  const remedy = `delete the ${tolerated.advisory} entry from deny.toml's [advisories] ignore list, this watch and its step in .github/workflows/quality.yml`;
  if (lockVulnerable.length === 0) {
    return { ok: false, message: `Cargo.lock no longer holds ${tolerated.crate} < ${tolerated.patched.join('.')}, so ${id} is no longer tolerated anywhere: ${remedy}.` };
  }
  if (declarations.length === 0) {
    return { ok: false, message: `Cargo.lock holds ${lockVulnerable.map(key).join(', ')} but no workspace dependency declaration leads to it; this watch cannot tell whether an upgrade exists.` };
  }
  const newest = declarations.map((declaration) => {
    const resolved = probePackages.filter((pkg) => pkg.name === declaration.name && pkg.source !== null).map((pkg) => pkg.version);
    return `${declaration.name} ${resolved.join('/') || '(not resolved)'}`;
  }).join(', ');
  const stillVulnerable = vulnerable(probePackages, tolerated);
  if (stillVulnerable.length > 0) {
    return { ok: true, message: `No upgrade clears ${id} yet: the newest releases (${newest}) still resolve ${stillVulnerable.map(key).join(', ')}. The exception stands.` };
  }
  return { ok: false, message: `An upgrade now clears ${id}: the newest releases (${newest}) resolve without ${tolerated.crate} < ${tolerated.patched.join('.')}. Upgrade them (re-vendor the patched copies under vendor/), then ${remedy}.` };
}

export function runWatch({ cwd = root, spawn = spawnSync, read = readFileSync, temporary = tmpdir() } = {}) {
  const lockPackages = parseLock(read(join(cwd, 'Cargo.lock'), 'utf8'));
  const lockVulnerable = vulnerable(lockPackages);
  if (lockVulnerable.length === 0) return decide({ lockVulnerable, declarations: [], probePackages: [] });

  const metadata = spawn('cargo', ['metadata', '--format-version', '1', '--no-deps', '--locked'], { cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 600_000 });
  if (metadata.status !== 0) return { ok: false, message: `cargo metadata failed (${metadata.error?.message ?? `status ${metadata.status}`}): ${metadata.stderr ?? ''}` };
  const declarations = pullingDeclarations(JSON.parse(metadata.stdout).packages, lockPackages);
  if (declarations.length === 0) return decide({ lockVulnerable, declarations, probePackages: [] });

  const probe = mkdtempSync(join(temporary, 'glib-upgrade-probe-'));
  try {
    mkdirSync(join(probe, 'src'));
    writeFileSync(join(probe, 'src', 'lib.rs'), '');
    writeFileSync(join(probe, 'Cargo.toml'), probeManifest(declarations));
    // cwd stays the repository so rustup uses its pinned toolchain; the probe's
    // own [workspace] table keeps Cargo from attaching it to this workspace.
    const resolved = spawn('cargo', ['generate-lockfile', '--manifest-path', join(probe, 'Cargo.toml')], { cwd, encoding: 'utf8', timeout: 600_000 });
    if (resolved.status !== 0) {
      return { ok: false, message: `The probe could not resolve the newest ${declarations.map((declaration) => declaration.name).join(', ')} (${resolved.error?.message ?? `status ${resolved.status}`}). Update this watch so it can tell whether ${TOLERATED.advisory} is still unavoidable:\n${resolved.stderr ?? ''}` };
    }
    return decide({ lockVulnerable, declarations, probePackages: parseLock(read(join(probe, 'Cargo.lock'), 'utf8')) });
  } finally {
    rmSync(probe, { recursive: true, force: true });
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const verdict = runWatch();
  (verdict.ok ? process.stdout : process.stderr).write(`${verdict.message}\n`);
  process.exitCode = verdict.ok ? 0 : 1;
}
