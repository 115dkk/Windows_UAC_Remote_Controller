// SPDX-License-Identifier: GPL-2.0-or-later
// Bounded child lifetime/output. POSIX owns the process group it creates;
// Windows fixtures own the direct child only (the formal runner is Linux-only).
import { spawn } from 'node:child_process';
import { appendFileSync, closeSync, openSync } from 'node:fs';

const MAX_CAPTURE_BYTES = 32 * 1024 * 1024;
const MAX_TIMER_MILLIS = 2 ** 31 - 1;

export function runProver(command, args, { cwd, logPath, timeoutMs = 120_000, maxOutputBytes = MAX_CAPTURE_BYTES, killGraceMs = 2000, signal } = {}) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMER_MILLIS ||
      !Number.isSafeInteger(maxOutputBytes) || maxOutputBytes <= 0 || maxOutputBytes > MAX_CAPTURE_BYTES ||
      !Number.isSafeInteger(killGraceMs) || killGraceMs <= 0 || killGraceMs > Math.floor(MAX_TIMER_MILLIS / 2) ||
      (signal !== undefined && !(signal instanceof AbortSignal))) throw new Error('Invalid prover process bounds.');
  const log = openSync(logPath, 'w');
  return new Promise((resolve) => {
    const grouped = process.platform !== 'win32';
    let child, stdout = Buffer.alloc(0), stderr = Buffer.alloc(0);
    let stdoutBytes = 0, stderrBytes = 0, bytes = 0, error;
    let timeout, escalation, cleanupDeadline, finished = false, stopping = false, cleanupIncomplete = false;
    const abort = () => stop(signal.reason instanceof Error ? signal.reason : new Error('Prover was cancelled.'));
    function signalOwned(name) {
      if (!child?.pid) return;
      try {
        if (grouped) process.kill(-child.pid, name);
        else child.kill(name);
      } catch (failure) {
        if (failure.code !== 'ESRCH') { error ??= failure; cleanupIncomplete = true; }
      }
    }
    function finish(status, exitSignal, incomplete = false) {
      if (finished) return;
      finished = true;
      cleanupIncomplete ||= incomplete;
      clearTimeout(timeout);
      clearTimeout(escalation);
      clearTimeout(cleanupDeadline);
      signal?.removeEventListener('abort', abort);
      if (incomplete) {
        // An escaped descendant/failed native termination must not hold this
        // promise through inherited pipes indefinitely. This is NOT a cleanup
        // success; the orchestrator must stop launching further proof groups.
        error ??= new Error('Prover process cleanup did not complete.');
        signalOwned('SIGKILL');
        child?.stdout?.destroy();
        child?.stderr?.destroy();
        child?.unref();
      }
      try { closeSync(log); }
      catch (failure) { error ??= failure; cleanupIncomplete = true; }
      resolve({ status, signal: exitSignal, error, cleanupIncomplete, cancelled: signal?.aborted === true,
        stdout: stdout.toString('utf8', 0, stdoutBytes), stderr: stderr.toString('utf8', 0, stderrBytes) });
    }
    function boundCleanup() {
      cleanupDeadline ??= setTimeout(() => finish(child?.exitCode ?? null, child?.signalCode ?? null, true), killGraceMs * 2);
    }
    function stop(reason) {
      if (finished) return;
      error ??= reason instanceof Error ? reason : new Error(reason);
      if (stopping) return;
      stopping = true;
      signalOwned('SIGTERM');
      escalation = setTimeout(() => signalOwned('SIGKILL'), killGraceMs);
      boundCleanup();
    }
    function receive(channel, chunk) {
      if (finished) return;
      const count = Math.min(chunk.length, maxOutputBytes - bytes);
      if (count) {
        // Fixed buffers avoid retaining arbitrarily many tiny Buffer objects or
        // backing allocations while still enforcing one combined output bound.
        if (channel === 'stdout') { chunk.copy(stdout, stdoutBytes, 0, count); stdoutBytes += count; }
        else { chunk.copy(stderr, stderrBytes, 0, count); stderrBytes += count; }
        try { appendFileSync(log, chunk.subarray(0, count)); }
        catch { stop('Cannot retain prover transcript.'); }
        bytes += count;
      }
      if (count !== chunk.length) stop('Prover output limit exceeded.');
    }
    try {
      if (signal?.aborted) { error = signal.reason instanceof Error ? signal.reason : new Error('Prover was cancelled.'); finish(null, null); return; }
      stdout = Buffer.alloc(maxOutputBytes);
      stderr = Buffer.alloc(maxOutputBytes);
      child = spawn(command, args, { cwd, detached: grouped, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    } catch (failure) {
      error = failure;
      finish(null, null);
      return;
    }
    timeout = setTimeout(() => stop('Prover timed out.'), timeoutMs);
    child.stdout.on('data', (chunk) => receive('stdout', chunk));
    child.stderr.on('data', (chunk) => receive('stderr', chunk));
    child.stdout.on('error', (failure) => stop(failure));
    child.stderr.on('error', (failure) => stop(failure));
    child.on('error', (failure) => stop(failure));
    child.on('exit', () => {
      if (finished) return;
      // Do not wait for close: a remaining Maude process may keep inherited
      // pipes open after the prover exits. No process outside this group is
      // enumerated or targeted, and POSIX group escape is not sandboxed here.
      if (grouped) signalOwned('SIGKILL');
      boundCleanup();
    });
    child.on('close', (status, exitSignal) => finish(status, exitSignal));
    signal?.addEventListener('abort', abort, { once: true });
    if (signal?.aborted) abort();
  });
}
