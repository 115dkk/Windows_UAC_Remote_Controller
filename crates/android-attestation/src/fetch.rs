// SPDX-License-Identifier: GPL-2.0-or-later
//! One fixed-origin outbound HTTPS operation. No caller URL, transport, roots,
//! body or authenticated boolean can construct a trusted status snapshot.
//! A timed-out OS DNS lookup cannot be cancelled by std: its sole worker and
//! permit remain quarantined until actual completion, not reported quiescent.
#![forbid(unsafe_code)]

use crate::{
    TrustedStatusSnapshot, VerificationError as Error,
    policy::{Clock, StatusFetchStarted},
};
use std::{
    fmt,
    io::Read,
    net::{SocketAddr, ToSocketAddrs},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, UNIX_EPOCH},
};
use ureq::{
    Agent,
    config::Config,
    http::{HeaderMap, Uri},
    tls::{RootCerts, TlsConfig, TlsProvider},
    unversioned::{
        resolver::{ResolvedSocketAddrs, Resolver},
        transport::{DefaultConnector, NextTimeout},
    },
};

const URL: &str = "https://android.googleapis.com/attestation/status";
const HOST: &str = "android.googleapis.com";
const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_HEADERS: usize = 32 * 1024;
const MAX_BODY: usize = 2 * 1024 * 1024;
const MAX_ADDRESSES: usize = 16;
const MAX_FRESHNESS: Duration = Duration::from_secs(86_400);

static FETCH_GATE: OnceLock<Arc<Gate>> = OnceLock::new();
static DNS_OWNER: OnceLock<Arc<DnsOwner>> = OnceLock::new();

#[derive(Default)]
struct Gate {
    busy: AtomicBool,
}
struct Permit {
    gate: Arc<Gate>,
}
impl Gate {
    fn acquire(self: &Arc<Self>) -> Result<Permit, Error> {
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::StatusUnavailable)?;
        Ok(Permit {
            gate: Arc::clone(self),
        })
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        self.gate.busy.store(false, Ordering::Release);
    }
}

type LookupResult = Result<Vec<SocketAddr>, ()>;
#[derive(Default)]
struct DnsOwner {
    gate: Arc<Gate>,
    worker: Mutex<Option<JoinHandle<()>>>,
}
impl DnsOwner {
    fn start(
        &self,
        lookup: impl FnOnce() -> LookupResult + Send + 'static,
    ) -> Result<Receiver<LookupResult>, Error> {
        let mut slot = self
            .worker
            .try_lock()
            .map_err(|_| Error::StatusUnavailable)?;
        if let Some(worker) = slot.as_ref() {
            if !worker.is_finished() {
                return Err(Error::StatusUnavailable);
            }
            // Join only a terminated worker, never the timed-out OS operation.
            slot.take()
                .ok_or(Error::StatusUnavailable)?
                .join()
                .map_err(|_| Error::StatusUnavailable)?;
        }
        let permit = self.gate.acquire()?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("attestation-dns".into())
            .spawn(move || {
                // The worker, NOT the waiting HTTP caller, owns this permit.
                let _permit = permit;
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(lookup))
                    .unwrap_or(Err(()));
                // One result fits without waiting. A timed-out caller has dropped its
                // unique receiver, so late results are discarded, never reused.
                let _ = sender.send(result);
            })
            .map_err(|_| Error::StatusUnavailable)?;
        *slot = Some(worker);
        Ok(receiver)
    }
}

struct FixedResolver {
    owner: Arc<DnsOwner>,
    deadline: Instant,
}
impl fmt::Debug for FixedResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FixedStatusResolver")
    }
}
fn fixed_uri(uri: &Uri) -> bool {
    uri.scheme_str() == Some("https")
        && uri.authority().is_some_and(|value| value.as_str() == HOST)
        && uri.path() == "/attestation/status"
        && uri.query().is_none()
}
fn bounded_addresses(addresses: impl IntoIterator<Item = SocketAddr>) -> LookupResult {
    let mut values = Vec::with_capacity(MAX_ADDRESSES);
    for address in addresses.into_iter().take(MAX_ADDRESSES + 1) {
        if values.len() == MAX_ADDRESSES || address.port() != 443 {
            return Err(());
        }
        values.push(address);
    }
    if values.is_empty() {
        Err(())
    } else {
        Ok(values)
    }
}
fn wait_lookup(
    receiver: Receiver<LookupResult>,
    deadline: Instant,
) -> Result<Vec<SocketAddr>, Error> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or(Error::StatusUnavailable)?;
    let result = receiver
        .recv_timeout(remaining)
        .map_err(|_| Error::StatusUnavailable)?;
    if Instant::now() >= deadline {
        return Err(Error::StatusUnavailable);
    }
    result.map_err(|_| Error::StatusUnavailable)
}
impl Resolver for FixedResolver {
    fn resolve(
        &self,
        uri: &Uri,
        _config: &Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        if !fixed_uri(uri) {
            return Err(ureq::Error::HostNotFound);
        }
        let deadline = Instant::now()
            .checked_add((*timeout.after).min(DNS_TIMEOUT))
            .ok_or(ureq::Error::HostNotFound)?
            .min(self.deadline);
        if Instant::now() >= deadline {
            return Err(ureq::Error::Timeout(timeout.reason));
        }
        let receiver = self
            .owner
            .start(|| {
                let addresses = (HOST, 443).to_socket_addrs().map_err(|_| ())?;
                bounded_addresses(addresses)
            })
            .map_err(|_| ureq::Error::HostNotFound)?;
        let addresses = wait_lookup(receiver, deadline).map_err(|_| ureq::Error::HostNotFound)?;
        let mut output = self.empty();
        for address in addresses {
            output.push(address);
        }
        Ok(output)
    }
}

fn configuration(global: Duration) -> Config {
    Agent::config_builder()
        .proxy(None)
        .https_only(true)
        .max_redirects(0)
        .http_status_as_error(false)
        .tls_config(
            TlsConfig::builder()
                .provider(TlsProvider::Rustls)
                .root_certs(RootCerts::WebPki)
                .client_cert(None)
                .use_sni(true)
                .disable_verification(false)
                .unversioned_rustls_crypto_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .build(),
        )
        .timeout_global(Some(global))
        .timeout_per_call(Some(global))
        .timeout_resolve(Some(DNS_TIMEOUT))
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_send_request(Some(global))
        .timeout_recv_response(Some(global))
        .timeout_recv_body(Some(global))
        .max_response_header_size(MAX_HEADERS)
        .max_idle_connections(0)
        .max_idle_connections_per_host(0)
        .accept("application/json")
        .accept_encoding("identity")
        .build()
}

fn single<'a>(
    headers: &'a HeaderMap,
    name: &str,
    required: bool,
) -> Result<Option<&'a str>, Error> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(Error::StatusUnavailable);
    }
    let Some(value) = first else {
        return if required {
            Err(Error::StatusUnavailable)
        } else {
            Ok(None)
        };
    };
    let text = value
        .to_str()
        .map_err(|_| Error::StatusUnavailable)?
        .trim_matches([' ', '\t']);
    if text.is_empty() {
        return Err(Error::StatusUnavailable);
    }
    Ok(Some(text))
}
fn decimal(value: &str) -> Result<u64, Error> {
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::StatusUnavailable);
    }
    value.parse().map_err(|_| Error::StatusUnavailable)
}
fn max_age(value: &str) -> Result<Duration, Error> {
    let mut seen = Vec::with_capacity(8);
    let mut age = None;
    for part in value.split(',') {
        if seen.len() == 16 {
            return Err(Error::StatusUnavailable);
        }
        let part = part.trim_matches([' ', '\t']);
        let (name, argument) = part
            .split_once('=')
            .map_or((part, None), |(name, argument)| {
                (name.trim(), Some(argument.trim()))
            });
        let name = name.to_ascii_lowercase();
        if name.is_empty() || seen.contains(&name) {
            return Err(Error::StatusUnavailable);
        }
        match name.as_str() {
            "max-age" => {
                age = Some(
                    Duration::from_secs(decimal(argument.ok_or(Error::StatusUnavailable)?)?)
                        .min(MAX_FRESHNESS),
                )
            }
            "public" | "private" | "must-revalidate" | "proxy-revalidate" | "no-transform"
            | "immutable"
                if argument.is_none() => {}
            _ => return Err(Error::StatusUnavailable), // includes no-cache/no-store/stale extensions
        }
        seen.push(name);
    }
    if seen.iter().any(|value| value == "public") && seen.iter().any(|value| value == "private") {
        return Err(Error::StatusUnavailable);
    }
    age.filter(|value| !value.is_zero())
        .ok_or(Error::StaleStatus)
}
fn response_headers(headers: &HeaderMap, status: u16) -> Result<Option<u64>, Error> {
    if status != 200 {
        return Err(Error::StatusUnavailable);
    }
    let mut total = 0usize;
    for (name, value) in headers {
        total = total
            .checked_add(name.as_str().len() + value.as_bytes().len() + 4)
            .ok_or(Error::Bounds)?;
        if total > MAX_HEADERS {
            return Err(Error::Bounds);
        }
    }
    let media = single(headers, "content-type", true)?.ok_or(Error::StatusUnavailable)?;
    let mut fields = media.split(';');
    if !fields
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
    {
        return Err(Error::StatusUnavailable);
    }
    if let Some(parameter) = fields.next() {
        let (name, value) = parameter
            .trim()
            .split_once('=')
            .ok_or(Error::StatusUnavailable)?;
        if !name.trim().eq_ignore_ascii_case("charset")
            || !(value.trim().eq_ignore_ascii_case("utf-8")
                || value.trim().eq_ignore_ascii_case("\"utf-8\""))
        {
            return Err(Error::StatusUnavailable);
        }
    }
    if fields.next().is_some() {
        return Err(Error::StatusUnavailable);
    }
    if single(headers, "content-encoding", false)?
        .is_some_and(|value| !value.eq_ignore_ascii_case("identity"))
    {
        return Err(Error::StatusUnavailable);
    }
    let length = single(headers, "content-length", false)?
        .map(decimal)
        .transpose()?;
    if length.is_some_and(|value| value > MAX_BODY as u64) {
        return Err(Error::Bounds);
    }
    if let Some(encoding) = single(headers, "transfer-encoding", false)?
        && (!encoding.eq_ignore_ascii_case("chunked") || length.is_some())
    {
        return Err(Error::StatusUnavailable);
    }
    Ok(length)
}
fn progressing(before: &Clock, after: &Clock) -> Result<Duration, Error> {
    if after.utc < before.utc || after.monotonic < before.monotonic {
        return Err(Error::StaleStatus);
    }
    after
        .monotonic
        .checked_duration_since(before.monotonic)
        .ok_or(Error::StaleStatus)
}
fn freshness(headers: &HeaderMap, started: &Clock, response: &Clock) -> Result<Duration, Error> {
    let lifetime =
        max_age(single(headers, "cache-control", true)?.ok_or(Error::StatusUnavailable)?)?;
    let date = single(headers, "date", true)?.ok_or(Error::StatusUnavailable)?;
    if date.len() > 64 {
        return Err(Error::StatusUnavailable);
    }
    let parsed = httpdate::parse_http_date(date).map_err(|_| Error::StatusUnavailable)?;
    if httpdate::fmt_http_date(parsed) != date {
        return Err(Error::StatusUnavailable);
    }
    let date = parsed
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::StatusUnavailable)?;
    let age = Duration::from_secs(
        single(headers, "age", false)?
            .map(decimal)
            .transpose()?
            .unwrap_or(0),
    );
    let delay = progressing(started, response)?;
    let apparent = response.utc.checked_sub(date).unwrap_or(Duration::ZERO); // RFC apparent-age max(0,...)
    let corrected = apparent.max(age.checked_add(delay).ok_or(Error::StaleStatus)?);
    let remaining = lifetime
        .checked_sub(corrected)
        .filter(|value| !value.is_zero())
        .ok_or(Error::StaleStatus)?;
    // Conservative: header-time remaining freshness is attached to ORIGINAL
    // request start, not response/parse completion. This cannot extend RFC age.
    let deadline = started
        .monotonic
        .checked_add(remaining)
        .ok_or(Error::StaleStatus)?;
    if response.monotonic >= deadline {
        return Err(Error::StaleStatus);
    }
    Ok(remaining)
}
fn within(deadline: Instant) -> Result<(), Error> {
    if Instant::now() >= deadline {
        Err(Error::StatusUnavailable)
    } else {
        Ok(())
    }
}
fn bounded_body(
    reader: &mut impl Read,
    declared: Option<u64>,
    deadline: Instant,
) -> Result<Vec<u8>, Error> {
    let mut output = Vec::with_capacity(declared.unwrap_or(8192).min(MAX_BODY as u64) as usize);
    let mut buffer = [0u8; 8192];
    loop {
        within(deadline)?;
        let amount = (MAX_BODY + 1 - output.len()).min(buffer.len());
        let read = reader
            .read(&mut buffer[..amount])
            .map_err(|_| Error::StatusUnavailable)?;
        within(deadline)?;
        if read == 0 {
            break;
        }
        output.extend_from_slice(&buffer[..read]);
        if output.len() > MAX_BODY {
            return Err(Error::Bounds);
        }
    }
    if declared.is_some_and(|value| value != output.len() as u64) {
        return Err(Error::StatusUnavailable);
    }
    std::str::from_utf8(&output).map_err(|_| Error::Der)?;
    Ok(output)
}

/// Fetch only the fixed Google certificate-status origin with authenticated
/// HTTPS. An unavailable/stale/error response never creates an empty snapshot.
/// No cache, retry, enrollment mutation or user-configurable network input.
pub fn fetch_google_status() -> Result<TrustedStatusSnapshot, Error> {
    let _fetch = FETCH_GATE
        .get_or_init(|| Arc::new(Gate::default()))
        .acquire()?;
    let started = StatusFetchStarted::capture()?;
    let deadline = started
        .clock
        .monotonic
        .checked_add(TOTAL_TIMEOUT)
        .ok_or(Error::StatusUnavailable)?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or(Error::StatusUnavailable)?;
    let resolver = FixedResolver {
        owner: Arc::clone(DNS_OWNER.get_or_init(|| Arc::new(DnsOwner::default()))),
        deadline,
    };
    let agent = Agent::with_parts(
        configuration(remaining),
        DefaultConnector::default(),
        resolver,
    );
    within(deadline)?;
    let mut response = agent
        .get(URL)
        .call()
        .map_err(|_| Error::StatusUnavailable)?;
    let received = Clock::capture()?;
    within(deadline)?;
    let declared = response_headers(response.headers(), response.status().as_u16())?;
    let remaining = freshness(response.headers(), &started.clock, &received)?;
    let body = bounded_body(&mut response.body_mut().as_reader(), declared, deadline)?;
    drop(response);
    drop(agent); // No retained idle pool/socket in the snapshot.
    let after_body = Clock::capture()?;
    progressing(&received, &after_body)?;
    let snapshot =
        TrustedStatusSnapshot::from_authenticated_google_response(started, &body, remaining)?;
    let after_parse = Clock::capture()?;
    progressing(&after_body, &after_parse)?;
    snapshot.require_current(&after_parse)?;
    within(deadline)?;
    Ok(snapshot)
}

#[cfg(test)]
mod tests;
