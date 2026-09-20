// SPDX-License-Identifier: GPL-2.0-or-later
import { useEffect, useState } from 'react';

// Display only: coalesce one missed foreground refresh and its next sample.
// Request admission, signing, expiry and commands always use the raw snapshot.
// null (unknown/stopped owner) and identity changes invalidate immediately.
export const CONNECTION_DISPLAY_GRACE_MS = 10_000;

export function useConnectionDisplay(observed: boolean | null, identity: string, allowGrace = true): boolean | null {
  const [last, setLast] = useState({ identity, connected: observed });
  const sameOwner = last.identity === identity;
  const holding = sameOwner && allowGrace && observed === false && last.connected === true;
  if (!holding && (!sameOwner || last.connected !== observed)) {
    setLast({ identity, connected: observed });
  }
  useEffect(() => {
    if (!holding) return;
    const timeout = window.setTimeout(() => { setLast({ identity, connected: false }); }, CONNECTION_DISPLAY_GRACE_MS);
    return () => window.clearTimeout(timeout);
  }, [holding, identity]);
  return holding ? true : observed;
}
