// SPDX-License-Identifier: GPL-2.0-or-later
// CI-only pinned upstream binary; never an unreviewed curl | shell installer.
import { createHash } from 'node:crypto';
import { appendFileSync, chmodSync, lstatSync, mkdtempSync, writeFileSync } from 'node:fs';
import { delimiter, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const version = '1.12.0';
const url = `https://github.com/tamarin-prover/tamarin-prover/releases/download/${version}/tamarin-prover-${version}-linux64-ubuntu.tar.gz`;
const expected = '201be06f469e47cff554df6ca93db8366fc2c69d70c61fcbd1370a1074b469c6';
if (process.platform !== 'linux' || process.arch !== 'x64' || !process.env.RUNNER_TEMP || !process.env.GITHUB_OUTPUT || !process.env.GITHUB_PATH || !process.env.GITHUB_ENV) {
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
// Ubuntu24.04's Maude3.2 is not in Tamarin1.12's supported list. Pin the
// upstream supported interpreter AND its sibling prelude/modules, not apt's
// version or a PATH shim that merely prints another version number.
const maudeHash = '72ed1ca87e3b3d0dfc6ee1436baf154bf04c45ff97d521bec040c5e8dfc8f92c';
const maudeResponse = await fetch('https://github.com/maude-lang/Maude/releases/download/Maude3.5.1/Maude-3.5.1-linux-x86_64.zip', { signal: AbortSignal.timeout(120_000) });
if (!maudeResponse.ok || !maudeResponse.body) throw new Error('Maude download failed.');
const maudeChunks = [];
let maudeLength = 0;
for await (const chunk of maudeResponse.body) {
  maudeLength += chunk.length;
  if (maudeLength > 10 * 1024 * 1024) throw new Error('Unexpected Maude archive size.');
  maudeChunks.push(chunk);
}
const maudeBytes = Buffer.concat(maudeChunks);
if (createHash('sha256').update(maudeBytes).digest('hex') !== maudeHash) throw new Error('Maude release SHA-256 mismatch.');
const maudeArchive = join(directory, 'maude.zip');
writeFileSync(maudeArchive, maudeBytes, { flag: 'wx' });
const maudeListing = spawnSync('unzip', ['-Z1', maudeArchive], { encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 * 1024 });
const members = maudeListing.stdout?.trim().split(/\r?\n/) ?? [];
if (maudeListing.status !== 0 || maudeListing.error || members.length !== 14 || !members.includes('maude') || !members.includes('prelude.maude') || members.some((name) => !/^(?:maude|[A-Za-z-]+\.(?:maude|sty))$/.test(name))) throw new Error('Unexpected pinned Maude archive members.');
const extracted = spawnSync('unzip', ['-q', maudeArchive, '-d', directory], { encoding: 'utf8', timeout: 30_000 });
if (extracted.status !== 0 || extracted.error || extracted.signal) throw new Error('Maude extraction failed.');
for (const name of members) {
  const member = lstatSync(join(directory, name));
  if (!member.isFile() || member.isSymbolicLink() || member.size > 20 * 1024 * 1024) throw new Error('Invalid extracted Maude member.');
}
const maude = join(directory, 'maude');
chmodSync(maude, 0o755);
const environment = { ...process.env, PATH: `${directory}${delimiter}${process.env.PATH ?? ''}`, MAUDE_LIB: directory };
const maudeVersion = spawnSync(maude, ['--version'], { env: environment, encoding: 'utf8', timeout: 30_000 });
if (maudeVersion.status !== 0 || maudeVersion.error || maudeVersion.stdout.trim() !== '3.5.1') throw new Error('Installed Maude version did not match.');
const observed = spawnSync(binary, ['--version'], { env: environment, encoding: 'utf8', timeout: 30_000 });
if (observed.status !== 0 || observed.error || /WARNING:|unsupported/i.test(observed.stdout + observed.stderr) || !/tamarin[- ]prover\s+1\.12\.0\b/i.test(observed.stdout + observed.stderr)) throw new Error('Installed Tamarin/toolchain version did not match.');
process.stdout.write(`${observed.stdout}${observed.stderr}\nUpstream archive SHA-256: ${expected}\n`);
process.stdout.write(`Maude3.5.1 archive SHA-256: ${maudeHash}\n`);
appendFileSync(process.env.GITHUB_OUTPUT, `binary=${binary}\n`);
appendFileSync(process.env.GITHUB_PATH, `${directory}\n`);
appendFileSync(process.env.GITHUB_ENV, `MAUDE_LIB=${directory}\n`);
