// SPDX-License-Identifier: GPL-2.0-or-later
import type { AppSnapshot } from './contracts';

/** Only a ready native catalogue establishes absence; an unread list does not. */
export function hasNoPairedPc(snapshot: AppSnapshot): boolean {
  return snapshot.platform === 'android' && snapshot.dataAvailability.requests === 'available'
    && snapshot.requestCatalog?.status === 'ready' && snapshot.requestCatalog.peerCount === 0
    && snapshot.requests.length === 0;
}
