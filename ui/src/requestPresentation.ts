// SPDX-License-Identifier: GPL-2.0-or-later
import type { AppSnapshot } from './contracts';

// Conservative display withdrawal only. This cannot approve, deny, expire a
// native request, or extend its original lifetime. Native commands check again.
export function withoutRequestBodies(snapshot: AppSnapshot): AppSnapshot {
  return { ...snapshot, requests: [], requestReview: null,
    requestCatalog: snapshot.requestCatalog ? { ...snapshot.requestCatalog, status: 'unavailable' } : null,
    dataAvailability: { ...snapshot.dataAvailability, requests: 'unavailable' } };
}

export function ageRequestPresentation(snapshot: AppSnapshot, elapsedMillis: number): AppSnapshot {
  if (!snapshot.requests.length) return snapshot;
  if (!Number.isFinite(elapsedMillis) || elapsedMillis < 0
    || snapshot.requests.some((request) => !Number.isFinite(request.refreshAfterMillis)
      || request.refreshAfterMillis <= elapsedMillis)) return withoutRequestBodies(snapshot);
  return { ...snapshot, requests: snapshot.requests.map((request) => ({ ...request,
    refreshAfterMillis: Math.max(0, request.refreshAfterMillis - Math.ceil(elapsedMillis)),
    remainingSeconds: Math.max(0, request.remainingSeconds - Math.ceil(elapsedMillis / 1000)),
  })) };
}
