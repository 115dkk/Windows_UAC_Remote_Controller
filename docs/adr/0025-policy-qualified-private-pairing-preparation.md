# ADR 0025: Policy-qualified private pairing preparation

Status: accepted for implementation; native qualification and QR issuance pending.

## Context

The service-owned rendezvous in ADR0024 binds live Starter/Helper peers. Bound
is informational and cannot alone authorize enrollment or disclose a QR secret.
The launch interval also needs the applicable Windows UAC policy to be observed
before the original Offer, not first inspected after a helper is already elevated.

## Decision

The original Starter peer privately owns a fixed local64-bit policy-key handle
and an asynchronous change event. Ownership begins before native resource
preparation and watch registration. The one-use whole-key watch is armed before
initial reads and Offer; change signals, value drift, native errors and uncertain
release permanently invalidate the attempt. No policy is written or defaulted.

Require EnableLUA=1, PromptOnSecureDesktop=1 and EnableUIADesktopToggle=0, plus
the actual Starter's applicable prompting mode: admin1..5 or standard-user1/3.
Only the actual built-in RID500 limited administrator additionally requires
FilterAdministratorToken=1. ROOT observed that value absent on this PC; unrelated
policy values therefore are not queried or guessed. Token classification and
the existing live process/session/context checks remain native, not caller flags.

The existing Session owns one volatile preparation after both Bound completions,
idle live peers, current registry/engine checkpoint equality and original
deadline/stop checks. One claim burns before failure-prone work. An owned
Zeroizing80-byte buffer exists before random filling and retains nonce, challenge
and recipient material; validation borrows its bytes rather than retaining Copy
secret DTOs. Failure, collision, cancellation and retirement drop-wipe that owner.

The existing retained PC key is checked through SessionKey::public immediately
before and after the one preparation claim, surrounded by original peer/policy/
window/stop fences. Already-prepared idle polls do not invoke native key exports.
The cached public pin remains context, not continuous key-health evidence.

Registry-key close must precede event release. Uncertain key close retains the
whole original peer/pipe/context and cannot rearm. Stop/failure cleanup remains
available, the original five-minute window and30-second close reserve remain,
and both CloseAcks are still required before closing either healthy peer.

## Limits

This creates no QR, grant, signature, durable enrollment, public capability or
first-install entitlement. Later disclosure/signing requires fresh validation,
protected display and real carrier/route inputs. A live helper is not a Windows
cryptographic consent receipt. Empty registration state is not installation
authority. RegNotifyChangeKeyValue does not detect RegRestoreKey; sampled policy
checks are not an exhaustive or atomic audit of administrative policy changes.

Original ownership/crypto behavior is covered by authored fixtures and source
review. ROOT performs executable checks separately; actual native policy/watch/
key behavior and user-deferred UAC/phone acceptance remain distinct evidence.
