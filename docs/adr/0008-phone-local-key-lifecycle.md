# 0008 — Persist local key identity separately from enrollment authority

Status: implemented source; ROOT CI/native evidence is recorded separately.
This does not choose the pending pairing UX, create native keys, authenticate a
user, enroll a PC or expose a signing/Tauri command.

## One owner and one checkpoint

ControllerCheckpoint V2 stores inbox, bounded history and LocalKeyLedger under
the existing384KiBcap and SnapshotStore lock/transaction. The new key section is
at most10,828bytes: a12-byte header and32records of at most338bytes. A record is
Preparing(handle32, challenge32) or CreatedUnverified with the exact three
canonical91-byte P-256 public keys. Handles/challenges are nonzero and unique;
keys cannot be reused across roles/retained sets. These checks do not prove
entropy, hardware policy, native observation or enrollment authority.

The trusted Rust owner must persist Preparing before a future native generation
attempt, then record its exact public observation separately. No generation
caller is activated by this change. Preparing is never a retry grant, even when
no aliases are visible after restart. A failed observation write leaves the
pending/store-intent reconciliation problem; it does not authorize deleting
aliases, resetting metadata or creating replacement keys. There is no key
metadata deletion, expiration, eviction or recovery API in this slice.

Typed invalid input is rejected before a store intent. Accepted candidates use
the same commit-before-exposure owner as policy/history. Storage failure latches
the whole owner. Policy edits, inbox transitions and history clearing preserve
all local key metadata. User-visible activity history is not the key ledger.

## Migration and startup order

The exact earlier V1 composite may decode with absent key metadata; older raw
inbox migration keeps its existing policy-only restriction. Unsupported versions
and malformed sections do not fall back to another decoder. Native Application
startup acquires the actual store lock, strictly decodes and checks policy-only
state, then performs native key preflight BEFORE any migration/restore write.
Empty metadata in V1 or V2 with any surviving controller alias is reconciliation-
required. Preparing is reconciliation-required regardless of alias presence.
Unknown files and the existing fresh-start marker/has_device_keys rules remain.
No ad-hoc Kotlin preference writer, extra key-state file or second controller is
introduced. A fresh store also rechecks namespace absence before readiness.

CreatedUnverified records are passed only to read-only reopening of existing
aliases. The same native adapter is owned by ApplicationPolicyActor, not by an
Activity. It checks the entire fixed controller namespace before and after the
batch, derives only the three fixed aliases per handle, and checks each key's
actual policy and exact role/SPKI. It never searches for a replacement key or
generates/imports/signs one. Canonical SPKI equality is not attestation, enrollment
or proof that a later private-key operation will succeed.

## Native reference ownership

DeviceKeyStore instances have distinct owners. Creation and reopening share one
bounded32set/96reference registry. An exact repeated reopen re-inspects native
state and returns the same canonical references. Wrong owner, conflicting tuple,
role swaps and cross-set key reuse fail. Reinspection failure invalidates only
that owner's exact affected registration. Memory-only release is idempotent,
cannot remove a newer registration and never deletes AndroidKeyStore aliases or
changes the checkpoint. Closing an owner permanently prevents reuse; it remains
possible when lock/credential storage is unavailable.

Before native reopening starts, Rust records a cleanup obligation. Constructor
errors preserve the primary error and attempt owner-scoped cleanup. The Kotlin
Application retains the exact adapter even when no Rust handle is returned, so
failed memory cleanup has an explicit retry path. Late initialization results
still obey the existing bounded lifecycle deadline. Shutdown attempts notification
and key-reference cleanup independently and retains each failed obligation.

ABI4 adds only outbound native key descriptors and reopen/release callbacks.
The real generated contract/checksum gate remains mandatory. No UI, broadcast,
Binder, deep-link or generic byte-signing endpoint is added. New internal error
categories map to existing storage-unavailable presentation, not a fabricated
missing-screen-lock result. Native key operations still distinguish configured,
missing and unavailable lock observations.

## Clock and evidence

The final native clock sample after initialization is retained as an independent
nanosecond floor. Subsequent observations below that floor stop the owner, even
when the inbox's last pre-IO sample was older. This addresses the1s initial →2s
final →1.5s subsequent-operation regression found during static review.

ROOT tests cover local metadata bounds and conflict/idempotency, V1/V2 migration,
same-envelope retention, preflight-before-write/lock ownership, store failure,
callback cleanup and the clock regression. Native reference tests use synthetic
public material and pure lifetime bookkeeping; they do not execute Keystore.
Real Android process death/reopen, hardware key policy, exact OEM errors, native
loading and authentication remain unverified until device checks. The user will
perform actual UAC and phone-authentication acceptance later. Whole-program
enrollment, intake/effects, signing/notifications and release remain unfinished.
