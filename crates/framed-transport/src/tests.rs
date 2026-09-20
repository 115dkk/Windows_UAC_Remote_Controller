// SPDX-License-Identifier: GPL-2.0-or-later
//! Real TLS/channel framing tests with cfg(test)-only synthetic software keys.
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use secure_channel::{ChannelError, EndpointRole, MAX_DRAIN_BYTES};
use service_protocol::{FrameError, MAX_PC_EVENT_BYTES, encode_frame};

use crate::{
    ConnectionBudget, ConnectionBudgetError, FRAME_TIMEOUT, MAX_CONNECTIONS,
    MAX_QUEUED_FRAME_BYTES, MAX_RECEIVED_FRAMES_PER_WINDOW, PeerTransport, TransportError,
    TransportStatus, test_support::*,
};

#[test]
fn global_reservation_precedes_tls_allocation_and_is_not_released_on_failure_or_close() {
    assert_eq!(
        ConnectionBudget::new(0).err(),
        Some(ConnectionBudgetError::InvalidLimit)
    );
    assert_eq!(
        ConnectionBudget::new(MAX_CONNECTIONS + 1).err(),
        Some(ConnectionBudgetError::InvalidLimit)
    );
    let now = Instant::now();
    let budget = Arc::new(ConnectionBudget::new(1).unwrap());
    let mut first = PeerTransport::client(
        Arc::clone(&budget),
        identity(EndpointRole::Client, 1),
        key(2),
        now,
    )
    .unwrap();
    assert_eq!(budget.active(), 1);
    // A wrong-role identity would fail Channel allocation; exhaustion must win
    // first because the reservation is acquired before calling Channel::client.
    assert_eq!(
        PeerTransport::client(
            Arc::clone(&budget),
            identity(EndpointRole::Server, 1),
            key(2),
            now
        )
        .err(),
        Some(TransportError::Budget(ConnectionBudgetError::Exhausted))
    );
    assert_eq!(
        first.reject_protocol_message(now),
        Err(TransportError::ProtocolRejected)
    );
    assert_eq!(budget.active(), 1);
    assert_eq!(
        PeerTransport::client(
            Arc::clone(&budget),
            identity(EndpointRole::Client, 1),
            key(2),
            now
        )
        .err(),
        Some(TransportError::Budget(ConnectionBudgetError::Exhausted))
    );
    drop(first);
    assert_eq!(budget.active(), 0);
    let mut next = PeerTransport::client(
        Arc::clone(&budget),
        identity(EndpointRole::Client, 1),
        key(2),
        now,
    )
    .unwrap();
    next.close(now).unwrap();
    assert_eq!(budget.active(), 1);
    drop(next);
    assert_eq!(budget.active(), 0);
    assert_eq!(
        PeerTransport::client(
            Arc::clone(&budget),
            identity(EndpointRole::Client, 1),
            key(1),
            now
        )
        .err(),
        Some(TransportError::Channel(ChannelError::KeyReuse))
    );
    assert_eq!(
        budget.active(),
        0,
        "a failed constructor has no surviving owner"
    );
}

#[test]
fn concurrent_reservations_cannot_exceed_the_shared_limit() {
    let now = Instant::now();
    let budget = Arc::new(ConnectionBudget::new(4).unwrap());
    let attempted = Arc::new(std::sync::Barrier::new(9));
    let release = Arc::new(std::sync::Barrier::new(9));
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let budget = Arc::clone(&budget);
            let attempted = Arc::clone(&attempted);
            let release = Arc::clone(&release);
            scope.spawn(move || {
                let owned = PeerTransport::client(
                    Arc::clone(&budget),
                    identity(EndpointRole::Client, 1),
                    key(2),
                    now,
                );
                let expected_result = owned.is_ok()
                    || matches!(
                        &owned,
                        Err(TransportError::Budget(ConnectionBudgetError::Exhausted))
                    );
                attempted.wait();
                release.wait();
                drop(owned);
                assert!(expected_result);
            });
        }
        attempted.wait();
        let reserved = budget.active();
        release.wait();
        assert_eq!(reserved, 4);
    });
    assert_eq!(budget.active(), 0);
}

#[test]
fn full_maximum_frames_work_both_directions_with_fragmented_tls_io() {
    let now = Instant::now();
    let (mut client, mut server, budget) = pair(now);
    assert_eq!(
        client.queue_frame(encode_frame(b"not early").unwrap(), now),
        Err(TransportError::NotReady)
    );
    assert!(client.poll_frame(now).unwrap().is_none());
    pump(&mut client, &mut server, now, 17).unwrap();
    let phone_payload = vec![0x51; MAX_PC_EVENT_BYTES];
    let pc_payload = vec![0x63; MAX_PC_EVENT_BYTES];
    client
        .queue_frame(encode_frame(&phone_payload).unwrap(), now)
        .unwrap();
    server
        .queue_frame(encode_frame(&pc_payload).unwrap(), now)
        .unwrap();
    let (at_client, at_server) = pump(&mut client, &mut server, now, 997).unwrap();
    assert_eq!(at_client, vec![pc_payload]);
    assert_eq!(at_server, vec![phone_payload]);
    assert_eq!(client.pending_counts(), Default::default());
    assert_eq!(server.pending_counts(), Default::default());
    assert_eq!(budget.active(), 2);
}

#[test]
fn only_one_outbound_frame_is_owned_until_its_tls_bytes_are_drained() {
    let now = Instant::now();
    let (mut client, mut server, _) = pair(now);
    pump(&mut client, &mut server, now, MAX_DRAIN_BYTES).unwrap();
    client
        .queue_frame(encode_frame(b"first").unwrap(), now)
        .unwrap();
    assert_eq!(client.pending_counts().outbound_plaintext_bytes, 0);
    assert!(client.pending_counts().outbound_frame);
    assert_eq!(
        client.queue_frame(encode_frame(b"second").unwrap(), now),
        Err(TransportError::Busy)
    );
    assert_eq!(client.drain_tls(&mut [], now), Ok(0));
    assert!(client.pending_counts().outbound_frame);
    let (_, frames) = pump(&mut client, &mut server, now, 1).unwrap();
    assert_eq!(frames, vec![b"first".to_vec()]);
    client
        .queue_frame(encode_frame(b"second").unwrap(), now)
        .unwrap();
    let (_, frames) = pump(&mut client, &mut server, now, 2).unwrap();
    assert_eq!(frames, vec![b"second".to_vec()]);
}

#[test]
fn multiple_frames_in_one_record_are_returned_one_at_a_time_with_redacted_debug() {
    let now = Instant::now();
    let (mut raw, mut peer, _) = raw_pair(now);
    let wire = [
        encode_frame(b"synthetic-one").unwrap(),
        encode_frame(b"synthetic-two").unwrap(),
        encode_frame(b"synthetic-three").unwrap(),
    ]
    .concat();
    send_raw(&mut raw, &mut peer, &wire, now).unwrap();
    for expected in [
        b"synthetic-one".as_slice(),
        b"synthetic-two".as_slice(),
        b"synthetic-three".as_slice(),
    ] {
        let frame = peer.poll_frame(now).unwrap().unwrap();
        assert_eq!(format!("{frame:?}"), "ReceivedFrame([redacted])");
        assert_eq!(frame.into_bytes(), expected);
    }
    assert!(peer.poll_frame(now).unwrap().is_none());
    assert_eq!(peer.pending_counts(), Default::default());
}

#[test]
fn plaintext_header_and_body_fragments_keep_one_decoder() {
    let now = Instant::now();
    let (mut raw, mut peer, _) = raw_pair(now);
    let frame = encode_frame(b"synthetic-fragments").unwrap();
    for (index, byte) in frame.iter().enumerate() {
        send_raw(&mut raw, &mut peer, std::slice::from_ref(byte), now).unwrap();
        let result = peer.poll_frame(now).unwrap();
        if index + 1 == frame.len() {
            assert_eq!(result.unwrap().into_bytes(), b"synthetic-fragments");
        } else {
            assert!(result.is_none());
        }
    }
}

#[test]
fn malformed_authenticated_length_is_fatal_and_retains_the_budget_slot() {
    for length in [0, MAX_PC_EVENT_BYTES as u32 + 1, u32::MAX] {
        let now = Instant::now();
        let (mut raw, mut peer, budget) = raw_pair(now);
        send_raw(&mut raw, &mut peer, &length.to_be_bytes(), now).unwrap();
        assert_eq!(
            peer.poll_frame(now).err(),
            Some(TransportError::Frame(FrameError::InvalidLength))
        );
        assert_eq!(peer.status(), TransportStatus::Failed);
        assert_eq!(peer.pending_counts(), Default::default());
        assert_eq!(budget.active(), 1);
        assert_eq!(peer.feed_tls(&[], now), Err(TransportError::Failed));
        assert_eq!(peer.poll_frame(now).err(), Some(TransportError::Failed));
    }
}

#[test]
fn outgoing_length_and_retained_capacity_are_bounded_and_invalid_frames_poison() {
    for frame in [
        vec![],
        vec![0, 0, 0, 0],
        vec![0, 0, 0, 2, 1],
        vec![0; MAX_QUEUED_FRAME_BYTES + 1],
    ] {
        let now = Instant::now();
        let (mut client, mut server, _) = pair(now);
        pump(&mut client, &mut server, now, MAX_DRAIN_BYTES).unwrap();
        assert_eq!(
            client.queue_frame(frame, now),
            Err(TransportError::InvalidOutboundFrame)
        );
        assert_eq!(client.status(), TransportStatus::Failed);
    }
    let now = Instant::now();
    let (mut client, mut server, _) = pair(now);
    pump(&mut client, &mut server, now, MAX_DRAIN_BYTES).unwrap();
    let mut oversized_allocation = Vec::with_capacity(MAX_QUEUED_FRAME_BYTES + 1);
    oversized_allocation.extend_from_slice(&[0, 0, 0, 1, 0x41]);
    assert_eq!(
        client.queue_frame(oversized_allocation, now),
        Err(TransportError::InvalidOutboundFrame)
    );
}

#[test]
fn first_header_byte_starts_an_absolute_deadline_even_without_polling() {
    let now = Instant::now();
    let (mut raw, mut peer, _) = raw_pair(now);
    send_raw(&mut raw, &mut peer, &[0], now).unwrap();
    peer.tick(now + Duration::from_secs(9)).unwrap();
    let later = now + Duration::from_millis(9_999);
    raw.write_plaintext(&[0], later).unwrap();
    let pending_ciphertext = raw_output(&mut raw, later);
    assert_eq!(peer.feed_tls(&pending_ciphertext, later), Ok(0));
    assert_eq!(
        peer.tick(now + FRAME_TIMEOUT),
        Err(TransportError::ReceiveDeadline)
    );
    assert_eq!(peer.pending_counts(), Default::default());
}

#[test]
fn later_frames_are_backpressured_until_prior_plaintext_is_drained_and_keep_their_own_start_time() {
    let now = Instant::now();
    let (mut raw, mut peer, _) = raw_pair(now);
    send_raw(&mut raw, &mut peer, &encode_frame(b"first").unwrap(), now).unwrap();
    let later = now + Duration::from_secs(5);
    raw.write_plaintext(&[0, 0, 0, 4, 0x53], later).unwrap();
    let pending = raw_output(&mut raw, later);
    assert_eq!(peer.feed_tls(&pending, later), Ok(0));
    assert_eq!(
        peer.poll_frame(later).unwrap().unwrap().into_bytes(),
        b"first"
    );
    assert_eq!(peer.feed_tls(&pending, later), Ok(pending.len()));
    assert!(peer.poll_frame(later).unwrap().is_none());
    peer.tick(now + FRAME_TIMEOUT).unwrap();
    assert_eq!(
        peer.tick(later + FRAME_TIMEOUT),
        Err(TransportError::ReceiveDeadline)
    );
}

#[test]
fn oversized_ciphertext_chunk_is_fatal_even_when_plaintext_backpressure_is_active() {
    let now = Instant::now();
    let (mut raw, mut peer, _) = raw_pair(now);
    send_raw(&mut raw, &mut peer, &[0], now).unwrap();
    assert_eq!(
        peer.feed_tls(&vec![0; secure_channel::MAX_INGRESS_BYTES + 1], now),
        Err(TransportError::Channel(ChannelError::IngressTooLarge))
    );
    assert_eq!(peer.pending_counts(), Default::default());
}

#[test]
fn slow_drip_decoder_progress_does_not_restart_the_assembly_timer() {
    let now = Instant::now();
    let (mut raw, mut peer, _) = raw_pair(now);
    send_raw(&mut raw, &mut peer, &[0, 0, 0, 4], now).unwrap();
    assert!(peer.poll_frame(now).unwrap().is_none());
    send_raw(&mut raw, &mut peer, b"abc", now + Duration::from_secs(9)).unwrap();
    assert!(
        peer.poll_frame(now + Duration::from_secs(9))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        peer.tick(now + FRAME_TIMEOUT),
        Err(TransportError::ReceiveDeadline)
    );
}

#[test]
fn delayed_second_frame_suffix_keeps_its_original_arrival_deadline() {
    let now = Instant::now();
    let (mut raw, mut peer, _) = raw_pair(now);
    let wire = [encode_frame(b"first").unwrap(), vec![0, 0]].concat();
    send_raw(&mut raw, &mut peer, &wire, now).unwrap();
    assert_eq!(
        peer.poll_frame(now + Duration::from_secs(9))
            .unwrap()
            .unwrap()
            .into_bytes(),
        b"first"
    );
    assert_eq!(
        peer.tick(now + FRAME_TIMEOUT),
        Err(TransportError::ReceiveDeadline)
    );
}

#[test]
fn send_deadline_includes_tls_buffer_and_does_not_extend_on_progress_or_busy_retry() {
    for payload_size in [1, MAX_PC_EVENT_BYTES] {
        let now = Instant::now();
        let (mut client, mut server, _) = pair(now);
        pump(&mut client, &mut server, now, MAX_DRAIN_BYTES).unwrap();
        client
            .queue_frame(encode_frame(&vec![0x44; payload_size]).unwrap(), now)
            .unwrap();
        client.tick(now + Duration::from_secs(9)).unwrap();
        assert_eq!(
            client.queue_frame(
                encode_frame(b"retry").unwrap(),
                now + Duration::from_secs(9)
            ),
            Err(TransportError::Busy)
        );
        let mut byte = [0];
        assert_eq!(
            client.drain_tls(&mut byte, now + Duration::from_millis(9_999)),
            Ok(1)
        );
        assert_eq!(
            client.tick(now + FRAME_TIMEOUT),
            Err(TransportError::SendDeadline)
        );
        assert_eq!(client.pending_counts(), Default::default());
    }
}

#[test]
fn completed_queue_drain_clears_only_the_internal_deadline_not_a_socket_delivery_claim() {
    let now = Instant::now();
    let (mut client, mut server, _) = pair(now);
    pump(&mut client, &mut server, now, MAX_DRAIN_BYTES).unwrap();
    client
        .queue_frame(encode_frame(b"socket ownership is external").unwrap(), now)
        .unwrap();
    let mut bytes = [0; MAX_DRAIN_BYTES];
    assert!(
        client
            .drain_tls(&mut bytes, now + Duration::from_secs(9))
            .unwrap()
            > 0
    );
    assert!(!client.pending_counts().outbound_frame);
    client.tick(now + Duration::from_secs(11)).unwrap();
    // Deliberately not delivered to the other endpoint: no ReceivedFrame exists.
    assert!(server.poll_frame(now).unwrap().is_none());
}

#[test]
fn receive_rate_is_128_frames_per_fixed_one_second_window() {
    let now = Instant::now();
    let (mut raw, mut peer, budget) = raw_pair(now);
    let frames = encode_frame(b"x")
        .unwrap()
        .repeat(MAX_RECEIVED_FRAMES_PER_WINDOW + 1);
    send_raw(&mut raw, &mut peer, &frames, now).unwrap();
    for _ in 0..MAX_RECEIVED_FRAMES_PER_WINDOW {
        assert_eq!(peer.poll_frame(now).unwrap().unwrap().into_bytes(), b"x");
    }
    assert_eq!(
        peer.poll_frame(now).err(),
        Some(TransportError::RateExceeded)
    );
    assert_eq!(peer.status(), TransportStatus::Failed);
    assert_eq!(budget.active(), 1);

    let (mut raw, mut peer, _) = raw_pair(now);
    let before_boundary = now + Duration::from_millis(999);
    send_raw(
        &mut raw,
        &mut peer,
        &encode_frame(b"x")
            .unwrap()
            .repeat(MAX_RECEIVED_FRAMES_PER_WINDOW),
        before_boundary,
    )
    .unwrap();
    for _ in 0..MAX_RECEIVED_FRAMES_PER_WINDOW {
        peer.poll_frame(before_boundary).unwrap().unwrap();
    }
    let boundary = now + Duration::from_secs(1);
    send_raw(&mut raw, &mut peer, &encode_frame(b"y").unwrap(), boundary).unwrap();
    assert_eq!(
        peer.poll_frame(boundary).unwrap().unwrap().into_bytes(),
        b"y"
    );
}

#[test]
fn authenticated_tls_close_rejects_partial_header_or_body() {
    for plaintext in [vec![0], vec![0, 0, 0, 5, b'a', b'b']] {
        let now = Instant::now();
        let (mut raw, mut peer, _) = raw_pair(now);
        raw.write_plaintext(&plaintext, now).unwrap();
        let mut ciphertext = raw_output(&mut raw, now);
        raw.close_gracefully(now).unwrap();
        ciphertext.extend(raw_output(&mut raw, now));
        feed_wire(&mut peer, &ciphertext, now).unwrap();
        assert_eq!(
            peer.poll_frame(now).err(),
            Some(TransportError::Frame(FrameError::Truncated))
        );
        assert_eq!(peer.status(), TransportStatus::Failed);
    }
}

#[test]
fn complete_frames_drain_on_peer_close_and_a_later_partial_tail_still_fails() {
    for partial_tail in [false, true] {
        let now = Instant::now();
        let (mut raw, mut peer, _) = raw_pair(now);
        let mut plaintext = encode_frame(b"complete unverified payload").unwrap();
        if partial_tail {
            plaintext.extend_from_slice(&[0, 0]);
        }
        raw.write_plaintext(&plaintext, now).unwrap();
        let mut ciphertext = raw_output(&mut raw, now);
        raw.close_gracefully(now).unwrap();
        ciphertext.extend(raw_output(&mut raw, now));
        feed_wire(&mut peer, &ciphertext, now).unwrap();
        assert_eq!(
            peer.poll_frame(now).unwrap().unwrap().into_bytes(),
            b"complete unverified payload"
        );
        if partial_tail {
            assert_eq!(
                peer.poll_frame(now).err(),
                Some(TransportError::Frame(FrameError::Truncated))
            );
        } else {
            assert_eq!(peer.status(), TransportStatus::PeerClosed);
            assert!(peer.poll_frame(now).unwrap().is_none());
            assert_eq!(peer.transport_eof(now), Ok(()));
        }
    }
}

#[test]
fn peer_close_does_not_discard_complete_inbound_frames_because_a_local_frame_is_pending() {
    let now = Instant::now();
    let (mut raw, mut peer, _) = raw_pair(now);
    peer.queue_frame(encode_frame(&vec![0x42; MAX_PC_EVENT_BYTES]).unwrap(), now)
        .unwrap();
    raw.write_plaintext(&encode_frame(b"last complete peer frame").unwrap(), now)
        .unwrap();
    let mut ciphertext = raw_output(&mut raw, now);
    raw.close_gracefully(now).unwrap();
    ciphertext.extend(raw_output(&mut raw, now));
    feed_wire(&mut peer, &ciphertext, now).unwrap();
    assert_eq!(
        peer.poll_frame(now).unwrap().unwrap().into_bytes(),
        b"last complete peer frame"
    );
    assert_eq!(peer.status(), TransportStatus::PeerClosed);
    assert!(peer.pending_counts().outbound_frame);
    assert_eq!(
        peer.tick(now + FRAME_TIMEOUT),
        Err(TransportError::SendDeadline)
    );
}

#[test]
fn raw_tls_eof_local_abort_clock_regression_and_protocol_rejection_cannot_be_reset() {
    let now = Instant::now();
    let (_, mut peer, _) = raw_pair(now);
    assert_eq!(
        peer.transport_eof(now),
        Err(TransportError::Channel(ChannelError::Truncated))
    );
    assert_eq!(peer.poll_frame(now).err(), Some(TransportError::Failed));

    let (_, mut peer, budget) = raw_pair(now);
    peer.close(now).unwrap();
    assert_eq!(peer.transport_eof(now), Err(TransportError::Closed));
    assert_eq!(peer.poll_frame(now).err(), Some(TransportError::Closed));
    assert_eq!(budget.active(), 1);

    let (_, mut peer, _) = raw_pair(now);
    peer.tick(now + Duration::from_secs(1)).unwrap();
    assert_eq!(
        peer.feed_tls(&[], now),
        Err(TransportError::Channel(ChannelError::ClockWentBackwards))
    );
    assert_eq!(peer.status(), TransportStatus::Failed);

    let (_, mut peer, budget) = raw_pair(now);
    peer.queue_frame(
        encode_frame(b"synthetic sensitive display text").unwrap(),
        now,
    )
    .unwrap();
    assert!(peer.pending_counts().outbound_frame);
    assert_eq!(
        peer.reject_protocol_message(now),
        Err(TransportError::ProtocolRejected)
    );
    assert_eq!(peer.pending_counts(), Default::default());
    assert_eq!(
        peer.drain_tls(&mut [0; 64], now),
        Err(TransportError::Failed)
    );
    assert!(!format!("{peer:?}").contains("synthetic sensitive"));
    assert_eq!(budget.active(), 1);
}
