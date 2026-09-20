// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';

export const VERSION_FILES = ['package.json', 'package-lock.json', 'Cargo.toml', 'Cargo.lock', 'src-tauri/tauri.conf.json'];
export function stableVersion(tag) {
  const match = /^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u.exec(tag);
  if (!match) return null;
  const value = match.slice(1).map(Number);
  return value.every(number => Number.isSafeInteger(number) && number < 65535) ? value : null;
}
export function compareVersions(a, b) {
  for (let index = 0; index < 3; index++) if (a[index] !== b[index]) return a[index] - b[index];
  return 0;
}
export function nextVersion(latestTag, messages) {
  const before = latestTag === null ? null : stableVersion(latestTag);
  assert.ok(latestTag === null || before, 'Invalid stable baseline');
  if (!before || before[0] < 1) return '1.0.0';
  const subject = message => message.trimStart().split(/\r?\n/u)[0];
  const breaking = messages.some(message => /^[a-z]+(?:\([^\r\n)]+\))?!:/iu.test(subject(message)) || /^BREAKING[ -]CHANGE:\s*\S/imu.test(message));
  const feature = messages.some(message => /^feat(?:\([^\r\n)]+\))?:/iu.test(subject(message)));
  const [major, minor, patch] = before;
  const next = breaking ? [major + 1, 0, 0] : feature ? [major, minor + 1, 0] : [major, minor, patch + 1];
  assert.ok(stableVersion(next.join('.')), 'Version exceeds Windows package limits');
  return next.join('.');
}

// One read-only owner for both stamping and tagged-release consistency checks.
// The returned representation stays private; callers never repeat file rules.
function readMetadata(root) {
  const path = name => resolve(root, name);
  const packageJson = JSON.parse(readFileSync(path('package.json'), 'utf8'));
  const previous = packageJson.version;
  assert.equal(typeof previous, 'string', 'Package version is required');
  assert.ok(previous.length > 0, 'Package version is required');
  const lock = JSON.parse(readFileSync(path('package-lock.json'), 'utf8'));
  const tauri = JSON.parse(readFileSync(path('src-tauri/tauri.conf.json'), 'utf8'));
  const cargo = readFileSync(path('Cargo.toml'), 'utf8');
  assert.equal(lock.version, previous);
  assert.equal(lock.packages[''].version, previous);
  assert.equal(tauri.version, previous);
  const workspaceVersion = /\[workspace\.package\][\s\S]*?^version = "([^"]+)"/mu.exec(cargo);
  assert.equal(workspaceVersion?.[1], previous);
  const members = /^members = \[([\s\S]*?)^\]/mu.exec(cargo)?.[1];
  assert.ok(members);
  const memberPaths = [...members.matchAll(/"([^"\r\n]+)"/gu)].map(match => match[1]);
  const names = new Set(memberPaths.map(member => {
    assert.ok(!member.startsWith('/') && !member.includes('..') && !member.includes('\\'));
    const manifest = readFileSync(path(`${member}/Cargo.toml`), 'utf8');
    assert.match(manifest, /^version\.workspace = true$/mu);
    const name = /^name = "([a-z0-9-]+)"$/mu.exec(manifest)?.[1];
    assert.ok(name);
    return name;
  }));
  assert.ok(names.size > 0 && names.size === memberPaths.length, 'Workspace package names must be unique and nonempty');
  const found = new Set();
  const lockBlocks = readFileSync(path('Cargo.lock'), 'utf8').split(/(?=^\[\[package\]\]\r?$)/mu).map(block => {
    const name = /^name = "([^"]+)"/mu.exec(block)?.[1];
    if (!names.has(name)) return { text: block, owned: false };
    assert.ok(!found.has(name), 'Duplicate workspace lock package');
    found.add(name);
    assert.equal(/^version = "([^"]+)"/mu.exec(block)?.[1], previous);
    return { text: block, owned: true };
  });
  assert.equal(found.size, names.size, 'Every owned workspace package must be present');
  return { previous, packageJson, lock, tauri, cargo, lockBlocks };
}

export function verifyTaggedMetadata(root, tag) {
  // Preserve the existing Release tag grammar, including explicit prereleases.
  // Reject line terminators too: JS $ alone permits a final newline.
  assert.match(tag, /^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?$(?![\s\S])/u, 'Version tag required');
  const version = tag.slice(1);
  assert.equal(readMetadata(root).previous, version, 'Tag must match release metadata');
  return version;
}

export function stampMetadata(root, version) {
  assert.ok(stableVersion(version), 'Stable version required');
  const { packageJson, lock, tauri, cargo, lockBlocks } = readMetadata(root);
  const path = name => resolve(root, name);
  const cargoLock = lockBlocks.map(({ text, owned }) => owned
    ? text.replace(/^version = "[^"]+"/mu, `version = "${version}"`) : text).join('');
  packageJson.version = lock.version = lock.packages[''].version = tauri.version = version;
  const cargoAfter = cargo.replace(/(\[workspace\.package\][\s\S]*?^version = ")[^"]+(".*$)/mu, (_match, prefix, suffix) => prefix + version + suffix);
  // All parsing/consistency checks finish before the first version-file write.
  for (const [name, value] of [['package.json', packageJson], ['package-lock.json', lock], ['src-tauri/tauri.conf.json', tauri]]) {
    writeFileSync(path(name), JSON.stringify(value, null, 2) + '\n');
  }
  writeFileSync(path('Cargo.toml'), cargoAfter);
  writeFileSync(path('Cargo.lock'), cargoLock);
}

function publishedRelease(tag) {
  const repository = process.env.GITHUB_REPOSITORY;
  assert.match(repository ?? '', /^[\w.-]+\/[\w.-]+$/u);
  let release;
  try {
    release = JSON.parse(execFileSync('gh', ['api', `repos/${repository}/releases/tags/${tag}`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }));
  } catch (failure) {
    if (/\(HTTP 404\)/u.test(String(failure.stderr ?? ''))) return false;
    throw failure; // Network/auth/parse failures never mean a completed release.
  }
  assert.equal(release.tag_name, tag);
  assert.equal(release.draft, false, 'Existing draft requires explicit recovery');
  assert.equal(release.prerelease, false, 'Stable tag has a prerelease record');
  for (const name of ['uac-remote-controller-windows-x64-setup.exe', 'uac-remote-controller-android-arm64.apk', 'SHA256SUMS.txt']) {
    assert.ok(release.assets.some(asset => asset.name === name && asset.size > 0), 'Existing release is incomplete');
  }
  return true;
}

function prepareMain() {
  assert.equal(process.env.GITHUB_ACTIONS, 'true');
  assert.equal(process.env.GITHUB_REF, 'refs/heads/main');
  assert.ok(process.env.GITHUB_OUTPUT);
  const git = (...args) => execFileSync('git', args, { encoding: 'utf8' }).trim();
  assert.equal(git('status', '--porcelain', '--untracked-files=no'), '');
  const head = git('rev-parse', 'HEAD');
  const tags = git('tag', '--merged', 'HEAD', '--list', 'v*').split('\n').filter(tag => stableVersion(tag));
  tags.sort((a,b) => compareVersions(stableVersion(a), stableVersion(b)));
  const latest = tags.at(-1) ?? null;
  const output = result => { appendFileSync(process.env.GITHUB_OUTPUT, Object.entries(result).map(([key,value]) => `${key}=${value}\n`).join('')); };
  if (latest && git('rev-list', '-n', '1', latest) === head) {
    output({ skip: publishedRelease(latest), sha: head, version: latest.slice(1) });
    return; // Missing publication retries this exact tag, never another bump.
  }
  const current = JSON.parse(readFileSync('package.json', 'utf8')).version;
  const prepared = stableVersion(current) && git('log', '-1', '--format=%s') === `chore(release): ${current}`;
  const messages = git('log', '--format=%B%x00', latest ? `${latest}..HEAD` : 'HEAD').split('\0');
  const version = prepared ? current : nextVersion(latest, messages);
  if (prepared) {
    const changed = git('diff-tree', '--no-commit-id', '--name-only', '-r', 'HEAD').split('\n');
    assert.ok(changed.every(name => VERSION_FILES.includes(name)), 'Prepared commit changed product code');
    assert.ok(!latest || compareVersions(stableVersion(version), stableVersion(latest)) > 0);
  } else {
    stampMetadata(process.cwd(), version);
    git('add', '--', ...VERSION_FILES);
    if (git('diff', '--cached', '--name-only', '--', ...VERSION_FILES)) {
      git('commit', '-m', `chore(release): ${version}`);
      // Ordinary fast-forward only. A concurrent main change stops publication.
      git('push', 'origin', 'HEAD:refs/heads/main');
    }
    // A fix after failed pre-tag CI may already carry the intended version.
    // Its current HEAD still needs every gate, not a failing empty Git commit.
  }
  output({ skip: false, version, sha: git('rev-parse', 'HEAD') });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    prepareMain(); // The only mutating mode; retains the main/CI/clean-tree guards.
  } else {
    assert.ok(args.length === 2 && args[0] === '--verify-tag', 'Usage: release-version.mjs [--verify-tag <tag>]');
    process.stdout.write(verifyTaggedMetadata(process.cwd(), args[1]) + '\n');
  }
}
