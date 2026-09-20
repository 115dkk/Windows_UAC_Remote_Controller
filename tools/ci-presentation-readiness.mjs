// SPDX-License-Identifier: GPL-2.0-or-later
// No pixels/codes/errors are retained in diagnostics. Retry presentation only,
// never a failed fixture, enrollment, signature or comparison decision.
import { setTimeout as delay } from 'node:timers/promises';

export async function awaitQrEnrollment({ capture, enroll, onAttempt = () => {},
  pause = () => delay(200), now = () => performance.now() }) {
  let deadline;
  for (let attempt = 1; attempt <= 25; attempt++) {
    if (deadline !== undefined && now() >= deadline) break;
    // The first capture includes the one-use initial consent and introduction.
    const pixels = await capture();
    if (deadline === undefined) deadline = now() + 10000;
    onAttempt(attempt);
    const result = await enroll(pixels);
    if (result?.state === 'awaiting_comparison') return;
    if (result?.state !== 'qr_not_ready' || Object.keys(result).length !== 1) {
      throw new Error('QR enrollment response rejected');
    }
    if (now() >= deadline) break;
    if (attempt < 25) await pause();
  }
  throw new Error('QR presentation readiness exhausted');
}
