// SPDX-License-Identifier: GPL-2.0-or-later
//! Same production TLS/host-store fixtures; original receiving provenance only.
use super::*;
use android_controller::AssociatedRequestIssue;
use phone_request_core::InboxIssue;
use service_protocol::{ClockProbe, VerifiedPcEvent};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn withholding_legacy_body_does_not_discard_committed_expiry_withdrawal() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let temp = tempfile::tempdir().unwrap();
        let clock = HostClock::new();
        let (mut owner, _) = owner(&temp, &clock);
        let key = PcPublicKey::from_spki_der(public(PC_SIGNING_KEY).as_spki_der()).unwrap();
        let probe = ClockProbe::start(pc(), clock.inbox().phone_monotonic_nanos()).unwrap();
        let wire = signed_frame(
            PcEvent::Clock {
                pc: pc(),
                epoch: epoch(),
                probe: probe.nonce(),
                sampled_at: ServiceTick::from_nanos_since_epoch(0),
            },
            PC_SIGNING_KEY,
        );
        let reply = VerifiedPcEvent::from_wire(&wire[4..], pc(), &key).unwrap();
        let mut correlation = probe
            .complete(&reply, clock.inbox().phone_monotonic_nanos())
            .unwrap();
        let (event, binding) = opened(75);
        let wire = signed_frame(event, PC_SIGNING_KEY);
        let verified = VerifiedPcEvent::from_wire(&wire[4..], pc(), &key).unwrap();
        let accepted = owner
            .receive_opened(&verified, &mut correlation, clock.inbox())
            .unwrap();
        assert!(accepted.update().issue().is_none());
        let current = owner
            .check_pending(request_key(binding), clock.inbox())
            .unwrap();
        let expiry = current
            .check()
            .request()
            .unwrap()
            .original_window()
            .phone_expiry_nanos();
        drop(current);
        let withheld = owner
            .check_associated_pending(request_key(binding), clock.inbox())
            .unwrap();
        assert_eq!(
            withheld.issue(),
            Some(AssociatedRequestIssue::UnassociatedRequest)
        );
        assert!(withheld.request().is_none());
        // Synthetic advancement only; no sleeping and no Android clock claim.
        let expired_clock = InboxClock::new(
            ClockReading::new(
                MonotonicTime::from_millis(expiry / MILLI),
                LocalTime::new(Weekday::Monday, 600).unwrap(),
            ),
            expiry,
        )
        .unwrap();
        let expired = owner
            .check_associated_pending(request_key(binding), expired_clock)
            .unwrap();
        assert!(expired.request().is_none());
        assert!(
            expired
                .update()
                .effects()
                .iter()
                .any(|effect| matches!(effect,
            Effect::Withdraw { key, .. } if *key == request_key(binding)))
        );
    })
    .await
    .expect("bounded source-withholding withdrawal preservation");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reregistered_connection_cannot_retag_an_already_accepted_request() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let temp = tempfile::tempdir().unwrap();
        let clock = HostClock::new();
        let (mut owner, first_ref) = owner(&temp, &clock);
        let budget = Arc::new(ConnectionBudget::new(4).unwrap());
        let mut first = pair(
            &owner,
            first_ref,
            clock.clone(),
            CancellationToken::new(),
            budget.clone(),
        )
        .await;
        let reply = initial_clock(&mut first, &owner, &clock, PC_SIGNING_KEY)
            .await
            .unwrap();
        let sampled = first
            .phone
            .apply_event(&mut owner, reply, clock.inbox())
            .unwrap();
        assert_clock_update(&sampled, &owner, first_ref);
        let (original, binding) = opened(71);
        let message = send(&mut first, original.clone()).await;
        let accepted = first
            .phone
            .apply_event(&mut owner, message, clock.inbox())
            .unwrap();
        assert!(accepted.committed().update().issue().is_none());
        let checked = owner
            .check_associated_pending(request_key(binding), clock.inbox())
            .unwrap();
        let view = checked.request().expect("original bound body");
        assert_eq!(
            view.request().receiving_generation().unwrap().get(),
            first_ref.generation()
        );
        assert_eq!(view.association().reference(), first_ref);
        assert!(view.belongs_to_owner(&owner));
        drop(checked);

        let (revoked, removal) = owner
            .revoke_peer_association_from_trusted_host(first_ref)
            .unwrap();
        assert!(revoked.changed());
        assert_eq!(removal, PeerAssociationRemoval::Removed);
        let (inserted, mutation) = owner
            .record_peer_association_from_trusted_host(association())
            .unwrap();
        assert!(inserted.changed());
        let second_ref = reference(mutation);
        assert_ne!(first_ref, second_ref);
        let mut second = pair(
            &owner,
            second_ref,
            clock.clone(),
            CancellationToken::new(),
            budget,
        )
        .await;
        let reply = initial_clock(&mut second, &owner, &clock, PC_SIGNING_KEY)
            .await
            .unwrap();
        let sampled = second
            .phone
            .apply_event(&mut owner, reply, clock.inbox())
            .unwrap();
        assert_clock_update(&sampled, &owner, second_ref);
        let replay = send(&mut second, original).await;
        let before = witness(&temp, &owner);
        stage_canary(&temp);
        assert_eq!(
            second
                .phone
                .apply_event(&mut owner, replay, clock.inbox())
                .unwrap_err(),
            PeerSocketError::ReceivingSource(InboxIssue::ConflictingReceivingSource)
        );
        assert_preintent_unchanged(&temp, &owner, &before);
        second.phone.check_current(&owner).unwrap();
        remove_own_canary(&temp);

        let withheld = owner
            .check_associated_pending(request_key(binding), clock.inbox())
            .unwrap();
        assert!(withheld.request().is_none());
        assert_eq!(
            withheld.issue(),
            Some(AssociatedRequestIssue::AssociationNoLongerCurrent)
        );
        let raw = owner
            .check_pending(request_key(binding), clock.inbox())
            .unwrap();
        assert_eq!(
            raw.check()
                .request()
                .unwrap()
                .receiving_generation()
                .unwrap()
                .get(),
            first_ref.generation()
        );
        drop(raw);

        let (new_event, new_binding) = opened(72);
        let message = send(&mut second, new_event).await;
        let accepted = second
            .phone
            .apply_event(&mut owner, message, clock.inbox())
            .unwrap();
        assert!(accepted.committed().update().issue().is_none());
        let fresh = owner
            .check_associated_pending(request_key(new_binding), clock.inbox())
            .unwrap();
        assert_eq!(
            fresh.request().unwrap().association().reference(),
            second_ref
        );
    })
    .await
    .expect("bounded immutable original-source regression");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_unassociated_body_is_never_upgraded_by_current_connection() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let temp = tempfile::tempdir().unwrap();
        let clock = HostClock::new();
        let (mut owner, reference) = owner(&temp, &clock);
        let key = PcPublicKey::from_spki_der(public(PC_SIGNING_KEY).as_spki_der()).unwrap();
        let probe = ClockProbe::start(pc(), clock.inbox().phone_monotonic_nanos()).unwrap();
        let wire = signed_frame(
            PcEvent::Clock {
                pc: pc(),
                epoch: epoch(),
                probe: probe.nonce(),
                sampled_at: ServiceTick::from_nanos_since_epoch(0),
            },
            PC_SIGNING_KEY,
        );
        let reply = VerifiedPcEvent::from_wire(&wire[4..], pc(), &key).unwrap();
        let mut correlation = probe
            .complete(&reply, clock.inbox().phone_monotonic_nanos())
            .unwrap();
        let (event, binding) = opened(73);
        let wire = signed_frame(event.clone(), PC_SIGNING_KEY);
        let verified = VerifiedPcEvent::from_wire(&wire[4..], pc(), &key).unwrap();
        let legacy = owner
            .receive_opened(&verified, &mut correlation, clock.inbox())
            .unwrap();
        assert!(legacy.update().issue().is_none());
        let checked = owner
            .check_associated_pending(request_key(binding), clock.inbox())
            .unwrap();
        assert!(checked.request().is_none());
        assert_eq!(
            checked.issue(),
            Some(AssociatedRequestIssue::UnassociatedRequest)
        );

        let mut connected = pair(
            &owner,
            reference,
            clock.clone(),
            CancellationToken::new(),
            Arc::new(ConnectionBudget::new(2).unwrap()),
        )
        .await;
        let reply = initial_clock(&mut connected, &owner, &clock, PC_SIGNING_KEY)
            .await
            .unwrap();
        let sampled = connected
            .phone
            .apply_event(&mut owner, reply, clock.inbox())
            .unwrap();
        assert_clock_update(&sampled, &owner, reference);
        let message = send(&mut connected, event).await;
        let before = witness(&temp, &owner);
        stage_canary(&temp);
        assert_eq!(
            connected
                .phone
                .apply_event(&mut owner, message, clock.inbox())
                .unwrap_err(),
            PeerSocketError::ReceivingSource(InboxIssue::ConflictingReceivingSource)
        );
        assert_preintent_unchanged(&temp, &owner, &before);
    })
    .await
    .expect("bounded legacy provenance rejection");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovered_body_keeps_original_generation_and_new_owner_identity() {
    tokio::time::timeout(TEST_DEADLINE, async {
        let temp = tempfile::tempdir().unwrap();
        let clock = HostClock::new();
        let (mut original_owner, reference) = owner(&temp, &clock);
        let budget = Arc::new(ConnectionBudget::new(2).unwrap());
        let mut connected = pair(
            &original_owner,
            reference,
            clock.clone(),
            CancellationToken::new(),
            budget.clone(),
        )
        .await;
        let reply = initial_clock(&mut connected, &original_owner, &clock, PC_SIGNING_KEY)
            .await
            .unwrap();
        let sampled = connected
            .phone
            .apply_event(&mut original_owner, reply, clock.inbox())
            .unwrap();
        assert_clock_update(&sampled, &original_owner, reference);
        let (event, binding) = opened(74);
        let message = send(&mut connected, event.clone()).await;
        let accepted = connected
            .phone
            .apply_event(&mut original_owner, message, clock.inbox())
            .unwrap();
        assert!(accepted.committed().update().issue().is_none());
        let old = original_owner
            .check_associated_pending(request_key(binding), clock.inbox())
            .unwrap();
        assert!(old.request().is_some());
        drop(connected);
        drop(original_owner);
        let (mut reopened, recovered) =
            DurableInbox::open_existing_host_model(directory(&temp), boot(), clock.inbox())
                .unwrap();
        assert!(recovered.update().fault().is_none());
        assert!(!old.request().unwrap().belongs_to_owner(&reopened));
        let bodyless = reopened
            .check_associated_pending(request_key(binding), clock.inbox())
            .unwrap();
        assert!(bodyless.request().is_none());
        let mut connected = pair(
            &reopened,
            reference,
            clock.clone(),
            CancellationToken::new(),
            budget,
        )
        .await;
        let reply = initial_clock(&mut connected, &reopened, &clock, PC_SIGNING_KEY)
            .await
            .unwrap();
        let sampled = connected
            .phone
            .apply_event(&mut reopened, reply, clock.inbox())
            .unwrap();
        assert!(sampled.committed().update().fault().is_none());
        let message = send(&mut connected, event).await;
        let restored = connected
            .phone
            .apply_event(&mut reopened, message, clock.inbox())
            .unwrap();
        assert!(
            restored
                .committed()
                .update()
                .effects()
                .iter()
                .any(|effect| matches!(effect, Effect::Restore(_)))
        );
        let fresh = reopened
            .check_associated_pending(request_key(binding), clock.inbox())
            .unwrap();
        let view = fresh.request().unwrap();
        assert_eq!(
            view.request().receiving_generation().unwrap().get(),
            reference.generation()
        );
        assert_eq!(view.association().reference(), reference);
        assert!(view.belongs_to_owner(&reopened));
    })
    .await
    .expect("bounded original-source body recovery");
}
