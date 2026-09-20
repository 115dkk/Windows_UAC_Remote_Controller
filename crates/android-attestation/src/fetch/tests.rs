// SPDX-License-Identifier: GPL-2.0-or-later
//! Pure HTTP/time/body fixtures and controlled DNS-owner threads. No real DNS,
//! socket, HTTPS, status endpoint or native key is used by these tests.
use super::*;
use std::{
    io::{self, Cursor},
    net::{IpAddr, Ipv4Addr},
    sync::atomic::AtomicUsize,
};
use ureq::http::HeaderValue;

const WAIT: Duration = Duration::from_secs(10);
fn put(headers: &mut HeaderMap, name: &'static str, value: &str) {
    let _ = headers.insert(name, HeaderValue::from_str(value).unwrap());
}
fn headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    put(
        &mut headers,
        "content-type",
        "application/json; charset=utf-8",
    );
    put(&mut headers, "cache-control", "public, max-age=3600");
    put(
        &mut headers,
        "date",
        &httpdate::fmt_http_date(UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
    );
    headers
}
fn observations() -> (Clock, Clock) {
    let start = Instant::now();
    (
        Clock {
            monotonic: start,
            utc: Duration::from_secs(1_700_000_000),
        },
        Clock {
            monotonic: start + Duration::from_secs(2),
            utc: Duration::from_secs(1_700_000_002),
        },
    )
}
fn address(last: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, last)), 443)
}
fn join_controlled(owner: &DnsOwner) {
    // TEST ONLY: every fake lookup has already been explicitly released and
    // performs no OS lookup. Production only joins is_finished() workers.
    owner.worker.lock().unwrap().take().unwrap().join().unwrap();
}

#[test]
fn client_configuration_is_fixed_https_no_proxy_redirect_pool_or_client_identity() {
    let config = configuration(TOTAL_TIMEOUT);
    assert!(config.https_only());
    assert!(config.proxy().is_none());
    assert_eq!(config.max_redirects(), 0);
    assert_eq!(config.max_response_header_size(), MAX_HEADERS);
    assert_eq!(config.max_idle_connections(), 0);
    assert_eq!(config.max_idle_connections_per_host(), 0);
    assert_eq!(config.timeouts().global, Some(TOTAL_TIMEOUT));
    assert_eq!(config.timeouts().resolve, Some(DNS_TIMEOUT));
    assert_eq!(config.timeouts().connect, Some(CONNECT_TIMEOUT));
    assert_eq!(config.timeouts().recv_body, Some(TOTAL_TIMEOUT));
    let tls = config.tls_config();
    assert!(matches!(tls.provider(), TlsProvider::Rustls));
    assert!(matches!(tls.root_certs(), RootCerts::WebPki));
    assert!(tls.client_cert().is_none());
    assert!(!tls.disable_verification());
    assert!(tls.use_sni());
    assert!(tls.unversioned_rustls_crypto_provider().is_some());
    assert!(fixed_uri(&URL.parse().unwrap()));
    for value in [
        "http://android.googleapis.com/attestation/status",
        "https://other.example/attestation/status",
        "https://android.googleapis.com:443/attestation/status",
        "https://android.googleapis.com/other",
        "https://android.googleapis.com/attestation/status?x=1",
        "https://user@android.googleapis.com/attestation/status",
    ] {
        assert!(!fixed_uri(&value.parse().unwrap()));
    }
}

#[test]
fn response_requires_exact_200_json_utf8_and_identity_encoding() {
    assert_eq!(response_headers(&headers(), 200), Ok(None));
    for status in [201, 204, 301, 302, 304, 401, 500] {
        assert!(matches!(
            response_headers(&headers(), status),
            Err(Error::StatusUnavailable)
        ));
    }
    for media in [
        "text/json",
        "text/html",
        "application/json; charset=utf-16",
        "application/json; charset=utf-8; charset=utf-8",
        "application/json; boundary=x",
    ] {
        let mut value = headers();
        put(&mut value, "content-type", media);
        assert!(response_headers(&value, 200).is_err());
    }
    let mut value = headers();
    put(
        &mut value,
        "content-type",
        "Application/JSON; charset=\"UTF-8\"",
    );
    put(&mut value, "content-encoding", "identity");
    assert!(response_headers(&value, 200).is_ok());
    for encoding in ["gzip", "br", "identity,gzip", ""] {
        put(&mut value, "content-encoding", encoding);
        assert!(response_headers(&value, 200).is_err());
    }
}

#[test]
fn duplicate_headers_ambiguous_framing_and_header_or_length_overflow_reject() {
    for name in ["content-type", "content-encoding", "content-length"] {
        let mut value = headers();
        let field = match name {
            "content-type" => "application/json",
            "content-encoding" => "identity",
            _ => "3",
        };
        put(&mut value, name, field);
        let _ = value.append(name, HeaderValue::from_str(field).unwrap());
        assert!(response_headers(&value, 200).is_err());
    }
    let mut value = headers();
    put(&mut value, "transfer-encoding", "chunked");
    put(&mut value, "content-length", "3");
    assert!(response_headers(&value, 200).is_err());
    let mut value = headers();
    put(&mut value, "content-length", &(MAX_BODY + 1).to_string());
    assert!(matches!(response_headers(&value, 200), Err(Error::Bounds)));
    let mut value = headers();
    put(&mut value, "x-bounded-fixture", &"a".repeat(MAX_HEADERS));
    assert!(matches!(response_headers(&value, 200), Err(Error::Bounds)));
}

#[test]
fn freshness_includes_request_delay_and_apparent_date_age_without_age_header() {
    let (start, response) = observations();
    assert_eq!(
        freshness(&headers(), &start, &response),
        Ok(Duration::from_secs(3598))
    );
    let mut older = headers();
    put(
        &mut older,
        "date",
        &httpdate::fmt_http_date(UNIX_EPOCH + Duration::from_secs(1_699_999_900)),
    );
    assert_eq!(
        freshness(&older, &start, &response),
        Ok(Duration::from_secs(3498))
    );
    put(&mut older, "age", "0");
    assert_eq!(
        freshness(&older, &start, &response),
        Ok(Duration::from_secs(3498))
    );
    put(&mut older, "age", "200");
    assert_eq!(
        freshness(&older, &start, &response),
        Ok(Duration::from_secs(3398))
    );
}

#[test]
fn total_lifetime_is_capped_before_age_and_delay_subtraction() {
    let (start, response) = observations();
    let mut value = headers();
    put(&mut value, "cache-control", "public, max-age=172800");
    put(&mut value, "age", "10000");
    assert_eq!(
        freshness(&value, &start, &response),
        Ok(Duration::from_secs(76398))
    );
    put(&mut value, "age", "86400");
    assert!(matches!(
        freshness(&value, &start, &response),
        Err(Error::StaleStatus)
    ));
    put(&mut value, "age", &u64::MAX.to_string());
    assert!(matches!(
        freshness(&value, &start, &response),
        Err(Error::StaleStatus)
    ));
    assert_eq!(max_age(&format!("max-age={}", u64::MAX)), Ok(MAX_FRESHNESS));
}

#[test]
fn invalid_duplicate_and_noncacheable_metadata_never_defaults_to_fresh() {
    let (start, response) = observations();
    for cache in [
        "public",
        "max-age=0",
        "max-age=60, max-age=60",
        "max-age=60, no-cache",
        "max-age=60, no-store",
        "public, private, max-age=60",
        "max-age=60, stale-if-error=60",
        "max-age=+60",
        "max-age=\"60\"",
        "max-age=18446744073709551616",
        "max-age=60,",
    ] {
        let mut value = headers();
        put(&mut value, "cache-control", cache);
        assert!(freshness(&value, &start, &response).is_err());
    }
    for age in ["+1", "-1", "1, 1", "one", "18446744073709551616"] {
        let mut value = headers();
        put(&mut value, "age", age);
        assert!(freshness(&value, &start, &response).is_err());
    }
    for name in ["date", "age", "cache-control"] {
        let mut value = headers();
        if name == "age" {
            put(&mut value, "age", "0");
        }
        let existing = value.get(name).unwrap().clone();
        let _ = value.append(name, existing);
        assert!(freshness(&value, &start, &response).is_err());
    }
    let mut value = headers();
    let _ = value.remove("date");
    assert!(freshness(&value, &start, &response).is_err());
    put(&mut value, "date", "not a date");
    assert!(freshness(&value, &start, &response).is_err());
}

#[test]
fn clock_regression_and_original_deadline_crossing_fail_without_new_anchor() {
    let (start, mut response) = observations();
    response.utc = start.utc - Duration::from_nanos(1);
    assert!(matches!(
        freshness(&headers(), &start, &response),
        Err(Error::StaleStatus)
    ));
    response.utc = start.utc;
    response.monotonic = start
        .monotonic
        .checked_sub(Duration::from_nanos(1))
        .unwrap();
    assert!(
        response.monotonic < start.monotonic,
        "the fixture must really move backwards"
    );
    assert!(matches!(
        freshness(&headers(), &start, &response),
        Err(Error::StaleStatus)
    ));
    let (start, response) = observations();
    let remaining = freshness(&headers(), &start, &response).unwrap();
    let snapshot = TrustedStatusSnapshot {
        entries: crate::revocation::RevocationList::parse(br#"{"entries":{}}"#).unwrap(),
        deadline: start.monotonic + remaining,
        received_clock: Clock {
            monotonic: start.monotonic,
            utc: start.utc,
        },
        identity: Arc::new(()),
    };
    // Synthetic post-body/parse observations; no wait, HTTP or minting of a
    // public trusted status constructor is used by this unit fixture.
    assert!(
        snapshot
            .require_current(&Clock {
                monotonic: snapshot.deadline - Duration::from_nanos(1),
                utc: response.utc
            })
            .is_ok()
    );
    assert!(matches!(
        snapshot.require_current(&Clock {
            monotonic: snapshot.deadline,
            utc: response.utc
        }),
        Err(Error::StaleStatus)
    ));
    let mut short = headers();
    put(&mut short, "cache-control", "max-age=4");
    assert!(matches!(
        freshness(&short, &start, &response),
        Err(Error::StaleStatus)
    ));
}

struct RecordingReader {
    inner: Cursor<Vec<u8>>,
    eof: bool,
}
impl Read for RecordingReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.eof |= count == 0;
        Ok(count)
    }
}
#[test]
fn exact_body_limit_observes_eof_and_limit_plus_one_is_not_a_truncated_prefix() {
    let mut bytes = br#"{"entries":{}}"#.to_vec();
    bytes.resize(MAX_BODY, b' ');
    let mut reader = RecordingReader {
        inner: Cursor::new(bytes.clone()),
        eof: false,
    };
    assert_eq!(
        bounded_body(&mut reader, Some(MAX_BODY as u64), Instant::now() + WAIT).unwrap(),
        bytes
    );
    assert!(reader.eof);
    bytes.push(b' ');
    let mut reader = RecordingReader {
        inner: Cursor::new(bytes),
        eof: false,
    };
    assert!(matches!(
        bounded_body(&mut reader, None, Instant::now() + WAIT),
        Err(Error::Bounds)
    ));
    assert_eq!(reader.inner.position(), (MAX_BODY + 1) as u64);
    assert!(!reader.eof);
}

#[test]
fn truncated_failed_non_utf8_and_json_prefix_with_extra_body_are_not_accepted() {
    assert!(matches!(
        bounded_body(&mut Cursor::new(b"abc"), Some(4), Instant::now() + WAIT),
        Err(Error::StatusUnavailable)
    ));
    assert!(matches!(
        bounded_body(&mut Cursor::new([0xff]), None, Instant::now() + WAIT),
        Err(Error::Der)
    ));
    struct FailedRead;
    impl Read for FailedRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::UnexpectedEof.into())
        }
    }
    assert!(matches!(
        bounded_body(&mut FailedRead, None, Instant::now() + WAIT),
        Err(Error::StatusUnavailable)
    ));
    let body = bounded_body(
        &mut Cursor::new(br#"{"entries":{}}{}"#),
        None,
        Instant::now() + WAIT,
    )
    .unwrap();
    assert!(crate::revocation::RevocationList::parse(&body).is_err());
    assert!(matches!(
        bounded_body(&mut Cursor::new(b"abc"), None, Instant::now()),
        Err(Error::StatusUnavailable)
    ));
}

#[test]
fn timed_out_lookup_keeps_worker_permit_and_refuses_overlap_until_actual_completion() {
    let owner = Arc::new(DnsOwner::default());
    let (entered, arrived) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    let count = Arc::new(AtomicUsize::new(0));
    let calls = Arc::clone(&count);
    let receiver = owner
        .start(move || {
            calls.fetch_add(1, Ordering::SeqCst);
            entered.send(()).unwrap();
            released.recv().unwrap();
            Ok(vec![address(1)])
        })
        .unwrap();
    arrived.recv_timeout(WAIT).unwrap();
    assert!(matches!(
        wait_lookup(receiver, Instant::now()),
        Err(Error::StatusUnavailable)
    ));
    assert!(owner.gate.busy.load(Ordering::Acquire));
    for _ in 0..32 {
        assert!(matches!(
            owner.start(|| panic!("overlapping worker must not start")),
            Err(Error::StatusUnavailable)
        ));
    }
    assert_eq!(count.load(Ordering::SeqCst), 1);
    release.send(()).unwrap();
    join_controlled(&owner);
    assert!(!owner.gate.busy.load(Ordering::Acquire));
    let next = owner.start(|| Ok(vec![address(2)])).unwrap();
    assert_eq!(
        wait_lookup(next, Instant::now() + WAIT).unwrap(),
        vec![address(2)]
    );
    join_controlled(&owner); // No late result from address1 can enter this channel.
}

#[test]
fn lookup_panic_releases_only_after_worker_cleanup_and_failed_lookup_is_not_empty_success() {
    let owner = DnsOwner::default();
    let receiver = owner.start(|| panic!("synthetic lookup panic")).unwrap();
    assert!(matches!(
        wait_lookup(receiver, Instant::now() + WAIT),
        Err(Error::StatusUnavailable)
    ));
    join_controlled(&owner);
    assert!(!owner.gate.busy.load(Ordering::Acquire));
    let receiver = owner.start(|| Err(())).unwrap();
    assert!(wait_lookup(receiver, Instant::now() + WAIT).is_err());
    join_controlled(&owner);
}

#[test]
fn address_count_port_and_fetch_try_permit_are_bounded() {
    assert!(bounded_addresses(Vec::new()).is_err());
    assert!(bounded_addresses(vec![SocketAddr::new(address(1).ip(), 80)]).is_err());
    assert_eq!(
        bounded_addresses(vec![address(1); MAX_ADDRESSES])
            .unwrap()
            .len(),
        MAX_ADDRESSES
    );
    assert!(bounded_addresses(vec![address(1); MAX_ADDRESSES + 1]).is_err());
    let gate = Arc::new(Gate::default());
    let first = gate.acquire().unwrap();
    assert!(gate.acquire().is_err());
    drop(first);
    assert!(gate.acquire().is_ok());
}
