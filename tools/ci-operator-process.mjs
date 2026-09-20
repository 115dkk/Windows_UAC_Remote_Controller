// SPDX-License-Identifier: GPL-2.0-or-later
// CI-only ownership of the already-spawned fixed PsExec/operator launch.
// This observes liveness/completion; the bridge's native checks remain authority.
const signals = new Set(['SIGTERM', 'SIGKILL', 'SIGINT', 'SIGABRT', 'SIGHUP']);
const spawnErrors = new Set(['ENOENT', 'EACCES', 'EPERM', 'ENOEXEC', 'EINVAL']);
const failureReasons = new Set(['stream_failed', 'spawn_failed', 'startup_exit', 'exit_failed', 'startup_timeout', 'whole_timeout',
  'invalid_startup', 'bridge_arm_failed', 'invalid_completion', 'completion_timeout', 'aborted']);
const boundedExit = value => Number.isInteger(value) && value >= -2147483648 && value <= 4294967295 ? value : null;

// Reconstruct only the native operator's bounded structural report. Never
// publish UI names, locations, command arguments, comparison codes or pixels.
export function projectConsentTopology(text) {
  if (typeof text !== 'string' || text.length > 32768) return { textNodes: null, rows: [] };
  let textNodes = null;
  const rows = [];
  const id = '(redacted|[0-9]{1,5}|[A-Za-z_][A-Za-z_.-]{0,39})';
  const hash = '(none|unbound|[A-F0-9]{16})';
  const boolean = '(True|False)';
  const pattern = new RegExp(`^CI consent topology: type=Text id=${id} node=${hash} parent=${hash} locationLabel=${boolean}(?: locationLabelTrimmed=${boolean} combinedLocation=${boolean} hasFormat=${boolean})? expectedPath=${boolean} closedPair=${boolean} conflictingPath=${boolean}(?: nextType=(None|Text|Button|Hyperlink|Other) nextExpectedPath=${boolean})?$`);
  for (const line of text.split(/[\r\n]+/)) {
    const summary = /^CI consent topology summary: textNodes=(0|[1-9][0-9]{0,2})$/.exec(line);
    if (summary && Number(summary[1]) <= 256) { textNodes = Number(summary[1]); continue; }
    const match = pattern.exec(line);
    if (!match) continue;
    const row = { type: 'Text', id: match[1], node: match[2], parent: match[3],
      locationLabel: match[4] === 'True', expectedPath: match[8] === 'True',
      closedPair: match[9] === 'True', conflictingPath: match[10] === 'True' };
    if (match[5] !== undefined) {
      row.locationLabelTrimmed = match[5] === 'True'; row.combinedLocation = match[6] === 'True'; row.hasFormat = match[7] === 'True';
    }
    if (match[11]) { row.nextType = match[11]; row.nextExpectedPath = match[12] === 'True'; }
    if (rows.length === 32) break;
    rows.push(row);
  }
  return { textNodes, rows };
}

export class OperatorProcess {
  #stderrBytes = Buffer.alloc(8192);
  #stderrLength = 0;
  #stderrFinalized = false;
  #stdoutBytes = Buffer.alloc(8192);
  #stdoutLength = 0;
  constructor(child, { startupTimeoutMs = 60000, wholeTimeoutMs = 300000, completionTimeoutMs = 10000, cleanupTimeoutMs = 2000 } = {}) {
    this.child = child;
    this.completionTimeoutMs = completionTimeoutMs;
    this.cleanupTimeoutMs = cleanupTimeoutMs;
    this.closed = false; this.exitObserved = false; this.exitCode = null;
    this.signal = 'none'; this.spawnError = 'none'; this.failure = null;
    this.stderrClassification = 'unclassified'; this.stderrTruncated = false;
    this.stdoutTruncated = false; this.consentTopology = { textNodes: null, rows: [] };
    this.startupComplete = false; this.startupClaimed = false; this.completionClaimed = false;
    this.waiters = new Set();
    // Neither stream is authority. At most 8 KiB of each is held privately for
    // closed diagnostic projection; PsExec can forward child stderr on stdout.
    child.stdout?.on('data', chunk => this.observeStdout(chunk));
    child.stdout?.on('error', () => this.fail('stream_failed'));
    child.stderr?.on('data', chunk => this.observeStderr(chunk));
    child.stderr?.on('error', () => this.fail('stream_failed'));
    child.stdin?.on('error', () => this.fail('stream_failed'));
    child.on('error', error => {
      this.spawnError = spawnErrors.has(error?.code) ? error.code : 'other';
      this.fail('spawn_failed');
    });
    child.on('exit', (code, signal) => {
      this.observeExit(code, signal);
      if (!this.startupComplete) this.fail('startup_exit');
      else if (code !== 0 || signal !== null) this.fail('exit_failed');
    });
    // `exit` does not prove drained private streams. Only `close` can complete.
    child.on('close', (code, signal) => {
      this.observeExit(code, signal); this.closed = true;
      this.discardStderr();
      this.clearTimers();
      if (!this.startupComplete) this.fail('startup_exit');
      else if (code !== 0 || signal !== null) this.fail('exit_failed');
      this.notify();
    });
    this.startupTimer = setTimeout(() => this.expire('startup_timeout'), startupTimeoutMs);
    this.wholeTimer = setTimeout(() => this.expire('whole_timeout'), wholeTimeoutMs);
  }

  observeExit(code, signal) {
    this.exitObserved = true; this.exitCode = boundedExit(code);
    this.signal = signal === null ? 'none' : signals.has(signal) ? signal : 'other';
  }

  observeStderr(chunk) {
    if (this.#stderrFinalized || !Buffer.isBuffer(chunk)) return;
    const count = Math.min(chunk.length, this.#stderrBytes.length - this.#stderrLength);
    chunk.copy(this.#stderrBytes, this.#stderrLength, 0, count);
    this.#stderrLength += count;
    if (count !== chunk.length) this.stderrTruncated = true;
  }

  observeStdout(chunk) {
    if (this.#stderrFinalized || !Buffer.isBuffer(chunk)) return;
    const count = Math.min(chunk.length, this.#stdoutBytes.length - this.#stdoutLength);
    chunk.copy(this.#stdoutBytes, this.#stdoutLength, 0, count);
    this.#stdoutLength += count;
    if (count !== chunk.length) this.stdoutTruncated = true;
  }

  topology() {
    if (this.#stderrFinalized) return { textNodes: this.consentTopology.textNodes, rows: this.consentTopology.rows.map(row => ({ ...row })) };
    return projectConsentTopology(this.#stdoutBytes.subarray(0, this.#stdoutLength).toString('utf8') + '\n' +
      this.#stderrBytes.subarray(0, this.#stderrLength).toString('utf8'));
  }

  classifyStderr() {
    if (this.#stderrFinalized) return this.stderrClassification;
    const text = this.#stderrBytes.subarray(0, this.#stderrLength).toString('utf8').toLowerCase();
    const matches = [];
    if (text.includes('access is denied')) matches.push('access_denied');
    if (text.includes('the handle is invalid')) matches.push('invalid_handle');
    if (text.includes('the system cannot find the file specified')) matches.push('file_not_found');
    // This is an observed phrase, never proof of failure cause or authority.
    return matches.length === 1 ? matches[0] : 'unclassified';
  }

  discardStderr() {
    if (this.#stderrFinalized) return;
    this.stderrClassification = this.classifyStderr();
    this.consentTopology = this.topology();
    this.#stdoutBytes.fill(0); this.#stdoutLength = 0;
    this.#stderrBytes.fill(0); this.#stderrLength = 0; this.#stderrFinalized = true;
  }

  clearTimers() { clearTimeout(this.startupTimer); clearTimeout(this.wholeTimer); }
  notify() { for (const waiter of this.waiters) waiter(); }
  stopOwnedChild() {
    try { this.child.stdin?.destroy(); } catch { /* Preserve original failure. */ }
    try { this.child.kill(); } catch { /* Original remote operator has its watchdog. */ }
  }
  expire(reason) { this.fail(reason); this.stopOwnedChild(); }
  fail(reason) {
    if (!this.failure) {
      this.failure = new Error('CI operator launcher failed');
      this.failure.reason = failureReasons.has(reason) ? reason : 'other';
    }
    this.clearTimers(); this.notify();
  }

  async guardStartup(armBridge) {
    if (this.startupClaimed || this.failure || this.exitObserved) {
      if (!this.failure) this.fail('invalid_startup');
      throw this.failure;
    }
    this.startupClaimed = true;
    let watcher;
    const failed = new Promise((_, reject) => {
      watcher = () => { if (this.failure) reject(this.failure); };
      this.waiters.add(watcher);
    });
    try {
      // Start the existing authenticated arm request only after the watcher is
      // installed. A launcher exit, even zero, cannot substitute for that reply.
      const armed = Promise.resolve().then(() => {
        if (this.failure) throw this.failure;
        return armBridge();
      });
      const result = await Promise.race([armed, failed]);
      if (this.failure || this.exitObserved) {
        if (!this.failure) this.fail('startup_exit');
        throw this.failure;
      }
      this.startupComplete = true; clearTimeout(this.startupTimer);
      return result;
    } catch {
      if (!this.failure) this.fail('bridge_arm_failed');
      throw this.failure;
    } finally { this.waiters.delete(watcher); }
  }

  async complete() {
    if (this.failure) throw this.failure;
    if (!this.startupComplete || this.completionClaimed) {
      this.fail('invalid_completion'); throw this.failure;
    }
    this.completionClaimed = true;
    if (!this.closed) {
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => this.expire('completion_timeout'), this.completionTimeoutMs);
        const watcher = () => {
          if (!this.failure && !this.closed) return;
          clearTimeout(timer); this.waiters.delete(watcher);
          if (this.failure) reject(this.failure); else resolve();
        };
        this.waiters.add(watcher);
      });
    }
    if (this.failure) throw this.failure;
    if (this.exitCode !== 0 || this.signal !== 'none') {
      this.fail('exit_failed'); throw this.failure;
    }
  }

  snapshot() {
    return { closed: this.closed, exitCode: this.exitCode, signal: this.signal,
      spawnError: this.spawnError, failure: this.failure?.reason ?? 'none',
      stderrClassification: this.classifyStderr(), stderrTruncated: this.stderrTruncated,
      stdoutTruncated: this.stdoutTruncated, consentTopology: this.topology() };
  }

  async abort() {
    this.clearTimers();
    if (this.closed) return;
    this.fail('aborted');
    // Only this original ChildProcess is terminated. No PID lookup, remote kill,
    // new PsExec command, policy mutation or completion claim is introduced.
    this.stopOwnedChild();
    if (!this.closed) {
      await new Promise(resolve => {
        const finish = () => {
          clearTimeout(timer); this.child.removeListener('close', finish); resolve();
        };
        const timer = setTimeout(finish, this.cleanupTimeoutMs);
        this.child.once('close', finish);
      });
    }
    this.discardStderr();
  }
}
