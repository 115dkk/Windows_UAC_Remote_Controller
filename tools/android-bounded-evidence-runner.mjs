// SPDX-License-Identifier: GPL-2.0-or-later
import { createHash } from 'node:crypto';
import { createReadStream, lstatSync } from 'node:fs';
import { join, relative } from 'node:path';
import { runProver } from './prover-process.mjs';

const requireThat = (value, message) => { if (!value) throw new Error(message); };

export function commandEvidenceComplete(value, transcript) {
  return value?.status === 0 && !value.error && !value.signal && value.cancelled === false && value.cleanupIncomplete === false &&
    transcript?.logUnavailable !== true && Number.isSafeInteger(transcript?.bytes) && transcript.bytes >= 0 && /^[0-9a-f]{64}$/.test(transcript?.sha256 ?? '');
}

async function fingerprintTranscript(path, maximum) {
  const before = lstatSync(path);
  requireThat(before.isFile() && !before.isSymbolicLink() && before.size <= maximum, 'Expected bounded regular command transcript.');
  const digest = createHash('sha256');
  let bytes = 0;
  for await (const chunk of createReadStream(path)) {
    bytes += chunk.length;
    requireThat(bytes <= maximum, 'Command transcript exceeded its bound.');
    digest.update(chunk);
  }
  const after = lstatSync(path);
  requireThat(bytes === before.size && bytes === after.size && before.mtimeMs === after.mtimeMs && before.ctimeMs === after.ctimeMs &&
    before.dev === after.dev && before.ino === after.ino, 'Command transcript changed during observation.');
  return { bytes, sha256: digest.digest('hex') };
}

export function createBoundedEvidenceRunner({
  root,
  directory,
  result,
  signal,
  commandLimit,
  maximumCommandLimit,
  deadline = null,
  stoppedMessage,
  incompleteMessage,
}) {
  let commandIndex = 0;
  return {
    get commandIndex() { return commandIndex; },
    async run(binary, argv, {
      timeoutMs = 15_000,
      mutatesDevice = false,
      maxOutputBytes = 512 * 1024,
      logName = null,
    } = {}) {
      const limit = commandLimit();
      const remaining = deadline === null ? null : deadline - performance.now();
      requireThat(!signal.aborted && !result.deviceOperationMayContinue && Number.isSafeInteger(limit) &&
        limit >= 0 && limit <= maximumCommandLimit && commandIndex < limit && (remaining === null || remaining > 0), stoppedMessage);
      const name = logName ?? `${String(commandIndex + 1).padStart(3, '0')}.log`;
      commandIndex += 1;
      const path = join(directory, name);
      const value = await runProver(binary, argv, {
        cwd: root,
        logPath: path,
        timeoutMs: remaining === null ? timeoutMs : Math.min(timeoutMs, Math.floor(remaining)),
        maxOutputBytes,
        signal,
      });
      const transcript = await fingerprintTranscript(path, maxOutputBytes).catch(() => ({ logUnavailable: true }));
      result.commands.push({
        log: name,
        command: relative(root, binary),
        args: argv,
        status: value.status,
        signal: value.signal,
        failed: Boolean(value.error),
        cancelled: value.cancelled,
        cleanupIncomplete: value.cleanupIncomplete,
        ...transcript,
      });
      result.cancelled ||= value.cancelled;
      result.cleanupIncomplete ||= value.cleanupIncomplete;
      if (mutatesDevice && (value.error || value.cancelled || value.cleanupIncomplete || value.status !== 0)) {
        result.deviceOperationMayContinue = true;
      }
      requireThat(commandEvidenceComplete(value, transcript), incompleteMessage);
      return { value, transcript, name };
    },
  };
}
