// SPDX-License-Identifier: GPL-2.0-or-later
// CI-only ownership of an already-spawned private phone/bridge process.
// Never echo process streams: they can contain QR pixels and comparison digits.
import { fixtureDiagnostic } from './ci-fixture-diagnostics.mjs';
export class PrivateChild {
  constructor(child, { responseTimeoutMs = 120000, completionTimeoutMs = 10000 } = {}) {
    this.child = child;
    this.responseTimeoutMs = responseTimeoutMs;
    this.completionTimeoutMs = completionTimeoutMs;
    this.queue = []; this.buffer = ''; this.failure = null; this.waiter = null;
    this.pendingWrites = new Set(); this.closeWaiter = null; this.closed = false;
    this.finishing = false; this.code = null; this.signal = null;
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', chunk => this.receive(chunk));
    child.stdout.on('end', () => { if (this.buffer.length) this.fail('partial_response'); });
    child.stdout.on('error', () => this.fail('stdout_failed'));
    child.stdin.on('error', () => this.fail('stdin_failed'));
    // Drain privately; arbitrary stderr is never evidence, even if ASCII-only.
    child.stderr.on('data', () => {});
    child.stderr.on('error', () => this.fail('stderr_failed'));
    child.on('error', () => this.fail('spawn_failed'));
    // `exit` is not stdout completion. `close` follows all child stdio closure.
    child.on('close', (code, signal) => {
      this.closed = true; this.code = code; this.signal = signal;
      if (code !== 0 || signal !== null || this.buffer.length) this.fail('child_exit_failed');
      else if (this.waiter) this.fail('response_missing');
      this.closeWaiter?.();
    });
  }

  receive(chunk) {
    if (this.failure) return;
    this.buffer += chunk;
    if (Buffer.byteLength(this.buffer) > 12 * 1024 * 1024) { this.fail('response_too_large'); return; }
    let end;
    while ((end = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, end); this.buffer = this.buffer.slice(end + 1);
      let value;
      try { value = JSON.parse(line); } catch { this.fail('invalid_response'); return; }
      if (!value || typeof value !== 'object' || Array.isArray(value) || line.includes('\r')) {
        this.fail('invalid_response'); return;
      }
      if (value.state === 'failed' || value.status === 'failed') {
        this.diagnostic = fixtureDiagnostic(value);
        this.fail(this.diagnostic ? 'fixture_failed' : 'invalid_diagnostic'); return;
      }
      if (this.finishing) { this.fail('extra_response'); return; }
      if (this.waiter) {
        const waiter = this.waiter; this.waiter = null; waiter.resolve(value);
      } else if (this.queue.length < 16) this.queue.push(value);
      else { this.fail('response_queue_full'); return; }
    }
  }

  fail(reason) {
    if (!this.failure) {
      this.failure = new Error('Private CI fixture failed');
      this.failure.reason = reason;
    }
    // First failure wins; no previously queued positive reply can escape it.
    this.queue.length = 0; this.buffer = '';
    const waiter = this.waiter; this.waiter = null;
    waiter?.reject(this.failure);
    for (const reject of this.pendingWrites) reject(this.failure);
    this.pendingWrites.clear();
    this.closeWaiter?.();
  }

  next() {
    if (this.failure) return Promise.reject(this.failure);
    if (this.waiter || this.finishing) {
      this.fail('invalid_wait'); return Promise.reject(this.failure);
    }
    if (this.queue.length) return Promise.resolve(this.queue.shift()).then(value => {
      if (this.failure) throw this.failure;
      return value;
    });
    if (this.closed) { this.fail('response_missing'); return Promise.reject(this.failure); }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.fail('response_timeout'), this.responseTimeoutMs);
      this.waiter = {
        resolve: value => { clearTimeout(timer); resolve(value); },
        reject: error => { clearTimeout(timer); reject(error); },
      };
    }).then(value => {
      // A coalesced chunk can contain a reply followed by a terminal failure.
      if (this.failure) throw this.failure;
      return value;
    });
  }

  send(value) {
    if (this.failure) return Promise.reject(this.failure);
    if (this.closed || this.finishing || this.child.stdin.destroyed) {
      this.fail('input_closed'); return Promise.reject(this.failure);
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.fail('stdin_timeout'), this.responseTimeoutMs);
      const rejectWrite = error => { clearTimeout(timer); reject(error); };
      this.pendingWrites.add(rejectWrite);
      try {
        this.child.stdin.write(`${JSON.stringify(value)}\n`, error => {
          clearTimeout(timer);
          this.pendingWrites.delete(rejectWrite);
          if (error) this.fail('stdin_failed');
          if (this.failure) reject(this.failure); else resolve();
        });
      } catch { this.fail('stdin_failed'); }
    });
  }

  async request(value, state) {
    await this.send(value);
    const reply = await this.next();
    if ((reply.state ?? reply.status) !== state) {
      this.fail('unexpected_stage'); throw this.failure;
    }
    return reply;
  }

  async complete() {
    if (this.failure) throw this.failure;
    if (this.finishing || this.waiter || this.queue.length || this.pendingWrites.size) {
      this.fail('unfinished_protocol'); throw this.failure;
    }
    this.finishing = true;
    if (!this.closed) {
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => this.fail('completion_timeout'), this.completionTimeoutMs);
        this.closeWaiter = () => {
          if (!this.failure && !this.closed) return;
          clearTimeout(timer); this.closeWaiter = null;
          if (this.failure) reject(this.failure); else resolve();
        };
        try { this.child.stdin.end(); } catch { this.fail('stdin_failed'); }
      });
    }
    if (this.failure) throw this.failure;
    if (this.code !== 0 || this.signal !== null) {
      this.fail('child_exit_failed'); throw this.failure;
    }
  }

  abort() {
    // Cleanup is never successful completion and only touches this owned child.
    if (this.closed) return;
    this.fail('aborted');
    try { this.child.stdin.destroy(); } catch { /* Preserve original failure. */ }
    try { this.child.kill(); } catch { /* Bounded child watchdog remains. */ }
  }
}
