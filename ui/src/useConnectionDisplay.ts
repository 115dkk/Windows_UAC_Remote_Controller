// SPDX-License-Identifier: GPL-2.0-or-later
import { useEffect, useState } from 'react';

// Display only: a phone that was connected and dropped is shown as reconnecting
// until one bounded deadline from the first missing sample, as the phone shows
// its PC. Request admission, signing, expiry and commands always use the raw
// snapshot. null (unknown/stopped owner) and identity changes invalidate at
// once, and a view that starts disconnected says so at once.
export const PHONE_RECONNECT_GRACE_MS = 60_000;

export type ConnectionDisplay = 'connected' | 'reconnecting' | 'disconnected';

export function useConnectionDisplay(observed: boolean | null, identity: string, allowGrace = true): ConnectionDisplay | null {
  const [last, setLast] = useState({ identity, connected: observed });
  const sameOwner = last.identity === identity;
  const holding = sameOwner && allowGrace && observed === false && last.connected === true;
  if (!holding && (!sameOwner || last.connected !== observed)) {
    setLast({ identity, connected: observed });
  }
  useEffect(() => {
    if (!holding) return;
    const timeout = window.setTimeout(() => { setLast({ identity, connected: false }); }, PHONE_RECONNECT_GRACE_MS);
    return () => window.clearTimeout(timeout);
  }, [holding, identity]);
  if (holding) return 'reconnecting';
  return observed === null ? null : observed ? 'connected' : 'disconnected';
}
