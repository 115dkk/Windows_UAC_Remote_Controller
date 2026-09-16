// SPDX-License-Identifier: GPL-2.0-or-later
import type { AppSnapshot } from './contracts';

/** Only a ready native catalogue establishes absence; an unread list does not. */
export function hasNoPairedPc(snapshot: AppSnapshot): boolean {
  return snapshot.platform === 'android' && snapshot.dataAvailability.requests === 'available'
    && snapshot.requestCatalog?.status === 'ready' && snapshot.requestCatalog.peerCount === 0
    && snapshot.requests.length === 0;
}

/**
 * The other side of the same question, and not the negation of it: absence
 * needs a ready catalogue, while presence needs only one thing this phone can
 * actually see. A counted peer is one, and so is a request, which only a paired
 * PC can have sent. Asking someone to connect a PC while their PC is connected
 * is wrong whatever the catalogue happens to be doing at that moment.
 */
export function hasPairedPc(snapshot: AppSnapshot): boolean {
  return snapshot.platform === 'android'
    && ((snapshot.requestCatalog?.peerCount ?? 0) > 0 || snapshot.requests.length > 0);
}
