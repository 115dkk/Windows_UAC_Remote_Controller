// SPDX-License-Identifier: GPL-2.0-or-later
// CI-only pinned upstream binary; never an unreviewed curl | shell installer.
import { createHash } from 'node:crypto';
import { appendFileSync, chmodSync, lstatSync, mkdtempSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const version = '1.12.0';
const url = `https://github.com/tamarin-prover/tamarin-prover/releases/download/${version}/tamarin-prover-${version}-linux64-ubuntu.tar.gz`;
const expected = '201be06f469e47cff554df6ca93db8366fc2c69d70c61fcbd1370a1074b469c6';
if (process.platform !== 'linux' || process.arch !== 'x64' || !process.env.RUNNER_TEMP || !process.env.GITHUB_OUTPUT) {
  throw new Error('Use the Linux x64 hosted CI installer, or install Tamarin separately from its official documentation.');
}
const directory = mkdtempSync(join(resolve(process.env.RUNNER_TEMP), 'uac-tamarin-'));
const response = await fetch(url, { signal: AbortSignal.timeout(120_000) });
if (!response.ok || !response.body) throw new Error(`Tamarin download failed (${response.status}).`);
const chunks = [];
let length = 0;
for await (const chunk of response.body) {
  length += chunk.length;
  if (length > 20 * 1024 * 1024) throw new Error('Unexpected Tamarin archive size.');
  chunks.push(chunk);
}
const archiveBytes = Buffer.concat(chunks);
if (createHash('sha256').update(archiveBytes).digest('hex') !== expected) throw new Error('Tamarin release SHA-256 mismatch.');
const archive = join(directory, 'upstream.tar.gz');
writeFileSync(archive, archiveBytes, { flag: 'wx' });
const listing = spawnSync('tar', ['-tzf', archive], { encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 * 1024 });
if (listing.status !== 0 || listing.error || listing.signal) throw new Error('Cannot inspect the pinned Tamarin archive.');
const candidates = listing.stdout.split(/\r?\n/).filter((name) => name === 'tamarin-prover' || name === './tamarin-prover');
if (candidates.length !== 1) throw new Error('Pinned archive does not contain exactly one expected binary.');
const unpacked = spawnSync('tar', ['-xzf', archive, '--directory', directory, '--no-same-owner', '--no-same-permissions', '--', candidates[0]], { encoding: 'utf8', timeout: 30_000 });
if (unpacked.status !== 0 || unpacked.error || unpacked.signal) throw new Error('Tamarin extraction failed.');
const binary = join(directory, 'tamarin-prover');
const stat = lstatSync(binary);
if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 1024 || stat.size > 150 * 1024 * 1024) throw new Error('Unexpected extracted binary.');
chmodSync(binary, 0o755);
const observed = spawnSync(binary, ['--version'], { encoding: 'utf8', timeout: 30_000 });
if (observed.status !== 0 || observed.error || !/tamarin[- ]prover\s+1\.12\.0\b/i.test(observed.stdout + observed.stderr)) throw new Error('Installed Tamarin version did not match.');
process.stdout.write(`${observed.stdout}${observed.stderr}\nUpstream archive SHA-256: ${expected}\n`);
appendFileSync(process.env.GITHUB_OUTPUT, `binary=${binary}\n`);
