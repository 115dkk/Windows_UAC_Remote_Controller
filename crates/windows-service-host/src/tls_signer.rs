// SPDX-License-Identifier: GPL-2.0-or-later
//! In-process handoff to the service worker's existing thread-affine TPM key.
//!
//! This is not service IPC, a carrier protocol, enrollment, or an approval API.
//! The only production factory requires the actual borrowed native key and
//! checks its native service/key context. It neither opens nor creates keys.
//! The worker stays on that thread; only a private-constructible TLS witness
//! crosses the bounded queue. No caller bytes/digest/provider can be supplied.
//!
//! The two-second budget bounds the caller's requested response wait, subject
//! to OS scheduling. It does NOT preempt a native CNG call already entered.
//! Cancellation discards its late result; its capacity permit remains held
//! until actual provider completion. The key owner must not close/drop its key
//! or report worker termination before that completion. No thread is spawned
//! here. The service must explicitly service `process_one` on its existing
//! worker and stop transport owners before releasing that worker/key.
//! After the synchronous handoff, the channel owner must obtain a fresh clock
//! and recheck its handshake deadline and live peer registry before application
//! use. This response deadline is not a peer-revocation or request-expiry lease.
//! Construct one pair for the service key/worker and share its proxy across
//! bounded connections; constructing one pair per connection would multiply the
//! per-pair capacity budget and is not the intended service ownership contract.

use std::{
    fmt,
    marker::PhantomData,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError},
    },
    thread::{self, ThreadId},
    time::{Duration, Instant},
};

use secure_channel::{
    CertificateVerifyInput, CertificateVerifySignature, EndpointRole, OwnedCertificateVerifyInput,
    PlatformTlsSigner, SignerError, TlsPublicKey,
};
use thiserror::Error;

/// Combined queued + native-in-flight + caller-response ownership, not per queue.
pub const MAX_TLS_SIGNING_REQUESTS: usize = 8;
pub const TLS_SIGNING_RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);
const CANCEL_CHECK_INTERVAL: Duration = Duration::from_millis(25);
const MAX_RESPONSE_WAITS: usize = 81;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum TlsSigningBridgeError {
    #[error("the service TLS signing bridge is closed")]
    Closed,
    #[error("the service TLS signing capacity is occupied")]
    Busy,
    #[error("the TLS signing response deadline elapsed")]
    TimedOut,
    #[error("TLS signing was requested on the native key worker")]
    SameThread,
    #[error("the TLS signing worker was called on a different thread")]
    WrongThread,
    #[error("only a server TLS CertificateVerify frame is accepted")]
    WrongRole,
    #[error("the native service transport key is unavailable")]
    NativeUnavailable,
    #[error("the native service transport public key changed")]
    PublicKeyMismatch,
    #[error("the service transport signature is invalid")]
    InvalidSignature,
}

/// `Signed` means only a permitted signature response was queued, not a TLS
/// handshake, peer enrollment, delivery, phone authentication or UAC outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsSigningProgress {
    Idle,
    Signed,
    Discarded,
}

struct Shared {
    closed: AtomicBool,
    pending: AtomicUsize,
}

struct Request {
    shared: Arc<Shared>,
    cancelled: AtomicBool,
    deadline: Instant,
}

impl Request {
    fn remaining(&self, now: Instant) -> Result<Duration, TlsSigningBridgeError> {
        if self.shared.closed.load(Ordering::Acquire) || self.cancelled.load(Ordering::Acquire) {
            return Err(TlsSigningBridgeError::Closed);
        }
        self.deadline
            .checked_duration_since(now)
            .filter(|remaining| !remaining.is_zero())
            .ok_or(TlsSigningBridgeError::TimedOut)
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        // Last actual owner, including a blocked provider, releases capacity.
        self.shared.pending.fetch_sub(1, Ordering::AcqRel);
    }
}

type Response = Result<CertificateVerifySignature, TlsSigningBridgeError>;

struct Job {
    input: OwnedCertificateVerifyInput,
    response: SyncSender<Response>,
    // Fields drop in declaration order. The last request owner may release the
    // combined permit only after its input and response endpoint are gone.
    request: Arc<Request>,
}

struct NativeAttempt {
    shared: Arc<Shared>,
    returned: bool,
}

impl Drop for NativeAttempt {
    fn drop(&mut self) {
        // A host catching an unexpected unwind cannot reuse an uncertain owner.
        if !self.returned {
            self.shared.closed.store(true, Ordering::Release);
        }
    }
}

struct PendingCall {
    response: Receiver<Response>,
    // Keep the permit through destruction of an uncollected response. Releasing
    // this Arc first could advertise capacity while that receiver still owns
    // a queued signature (including when the dropping thread is preempted).
    request: Arc<Request>,
}

impl PendingCall {
    fn wait(self, clock: impl Fn() -> Instant) -> Response {
        for _ in 0..MAX_RESPONSE_WAITS {
            let remaining = self.request.remaining(clock())?;
            match self
                .response
                .recv_timeout(remaining.min(CANCEL_CHECK_INTERVAL))
            {
                Ok(result) => {
                    self.request.remaining(clock())?;
                    return result;
                }
                Err(RecvTimeoutError::Timeout) => (),
                Err(RecvTimeoutError::Disconnected) => return Err(TlsSigningBridgeError::Closed),
            }
        }
        Err(TlsSigningBridgeError::TimedOut)
    }
}

impl Drop for PendingCall {
    fn drop(&mut self) {
        // Also cancels work if the caller unwinds after queue admission.
        self.request.cancelled.store(true, Ordering::Release);
    }
}

/// Send+Sync signer for trusted service-owned TLS connections. The key itself
/// never moves here. Do not expose this object through renderer/carrier IPC.
pub struct ServiceTlsSigner {
    public_key: TlsPublicKey,
    shared: Arc<Shared>,
    sender: SyncSender<Job>,
    worker_thread: ThreadId,
}

impl ServiceTlsSigner {
    /// Crate-local software fixture seam; absent from every production build.
    #[cfg(test)]
    pub(crate) fn for_test_key(
        key: &dyn tests::SyntheticKey,
    ) -> Result<(Arc<Self>, ServiceTlsSigningWorker<'_>), TlsSigningBridgeError> {
        Self::with_owner(KeyOwner::Synthetic(key))
    }
    /// Called on the existing trusted service worker with its exact live key.
    /// Native public export rechecks service identity, impersonation and key
    /// policy. No software, alternate-key or open/create fallback is present.
    #[cfg(windows)]
    pub fn for_service_key(
        key: &windows_identity::PcIdentityKey,
    ) -> Result<(Arc<Self>, ServiceTlsSigningWorker<'_>), TlsSigningBridgeError> {
        Self::with_owner(KeyOwner::Native(key))
    }

    fn with_owner(
        key: KeyOwner<'_>,
    ) -> Result<(Arc<Self>, ServiceTlsSigningWorker<'_>), TlsSigningBridgeError> {
        let public_key = key.public_key()?;
        let shared = Arc::new(Shared {
            closed: AtomicBool::new(false),
            pending: AtomicUsize::new(0),
        });
        let (sender, receiver) = mpsc::sync_channel(MAX_TLS_SIGNING_REQUESTS);
        let worker_thread = thread::current().id();
        let signer = Arc::new(Self {
            public_key: public_key.clone(),
            shared: Arc::clone(&shared),
            sender,
            worker_thread,
        });
        let worker = ServiceTlsSigningWorker {
            key,
            public_key,
            shared,
            receiver: Some(receiver),
            worker_thread,
            _thread_affine: PhantomData,
        };
        Ok((signer, worker))
    }

    /// Downward, idempotent and nonblocking. Existing provider work is not
    /// forcibly terminated. Waiters observe closure within their bounded wait.
    pub fn close(&self) {
        self.shared.closed.store(true, Ordering::Release);
    }

    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::Acquire)
    }

    pub fn pending_count(&self) -> usize {
        self.shared.pending.load(Ordering::Acquire)
    }

    fn enqueue(
        &self,
        input: OwnedCertificateVerifyInput,
        now: Instant,
    ) -> Result<PendingCall, TlsSigningBridgeError> {
        if input.role() != EndpointRole::Server {
            return Err(TlsSigningBridgeError::WrongRole);
        }
        if thread::current().id() == self.worker_thread {
            return Err(TlsSigningBridgeError::SameThread);
        }
        if self.is_closed() {
            return Err(TlsSigningBridgeError::Closed);
        }
        let deadline = now
            .checked_add(TLS_SIGNING_RESPONSE_TIMEOUT)
            .ok_or(TlsSigningBridgeError::TimedOut)?;
        self.shared
            .pending
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_TLS_SIGNING_REQUESTS).then_some(count + 1)
            })
            .map_err(|_| TlsSigningBridgeError::Busy)?;
        let request = Arc::new(Request {
            shared: Arc::clone(&self.shared),
            cancelled: AtomicBool::new(false),
            deadline,
        });
        let (sender, response) = mpsc::sync_channel(1);
        let call = PendingCall {
            response,
            request: Arc::clone(&request),
        };
        let job = Job {
            input,
            response: sender,
            request,
        };
        match self.sender.try_send(job) {
            Ok(()) => Ok(call),
            Err(TrySendError::Full(_)) => Err(TlsSigningBridgeError::Busy),
            Err(TrySendError::Disconnected(_)) => Err(TlsSigningBridgeError::Closed),
        }
    }
}

impl PlatformTlsSigner for ServiceTlsSigner {
    fn public_key(&self) -> Result<TlsPublicKey, SignerError> {
        if self.is_closed() {
            Err(SignerError::Unavailable)
        } else {
            Ok(self.public_key.clone())
        }
    }

    fn sign_certificate_verify(
        &self,
        input: CertificateVerifyInput<'_>,
    ) -> Result<CertificateVerifySignature, SignerError> {
        self.enqueue(input.into_owned(), Instant::now())
            .and_then(|pending| pending.wait(Instant::now))
            .map_err(|error| match error {
                TlsSigningBridgeError::WrongRole => SignerError::InvalidMessage,
                TlsSigningBridgeError::InvalidSignature
                | TlsSigningBridgeError::PublicKeyMismatch => SignerError::InvalidSignature,
                TlsSigningBridgeError::SameThread | TlsSigningBridgeError::WrongThread => {
                    SignerError::Rejected
                }
                _ => SignerError::Unavailable,
            })
    }
}

impl Drop for ServiceTlsSigner {
    fn drop(&mut self) {
        self.close();
    }
}

impl fmt::Debug for ServiceTlsSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceTlsSigner")
            .field("closed", &self.is_closed())
            .field("pending", &self.pending_count())
            .finish_non_exhaustive()
    }
}

enum KeyOwner<'key> {
    #[cfg(windows)]
    Native(&'key windows_identity::PcIdentityKey),
    #[cfg(test)]
    Synthetic(&'key dyn tests::SyntheticKey),
}

impl KeyOwner<'_> {
    fn public_key(&self) -> Result<TlsPublicKey, TlsSigningBridgeError> {
        match self {
            #[cfg(windows)]
            Self::Native(key) => {
                use p256::pkcs8::EncodePublicKey;
                let public = key
                    .public_sec1()
                    .map_err(|_| TlsSigningBridgeError::NativeUnavailable)?;
                let point = p256::PublicKey::from_sec1_bytes(public.as_sec1_bytes())
                    .map_err(|_| TlsSigningBridgeError::NativeUnavailable)?;
                let der = point
                    .to_public_key_der()
                    .map_err(|_| TlsSigningBridgeError::NativeUnavailable)?;
                TlsPublicKey::from_spki_der(der.as_bytes())
                    .map_err(|_| TlsSigningBridgeError::NativeUnavailable)
            }
            #[cfg(test)]
            Self::Synthetic(key) => key.public_key(),
        }
    }

    fn sign(&self, input: &OwnedCertificateVerifyInput) -> Response {
        match self {
            #[cfg(windows)]
            Self::Native(key) => {
                use sha2::{Digest, Sha256};
                let digest: [u8; 32] = Sha256::digest(input.as_bytes()).into();
                let signature = key
                    .sign_digest_for_service(&digest)
                    .map_err(|_| TlsSigningBridgeError::NativeUnavailable)?;
                CertificateVerifySignature::from_der(signature.as_der_bytes())
                    .map_err(|_| TlsSigningBridgeError::InvalidSignature)
            }
            #[cfg(test)]
            Self::Synthetic(key) => key.sign(input),
        }
    }
}

/// Sole consumer, borrowed-key owner, and deliberately !Send/!Sync. Call on the
/// factory thread only. Closing this adapter never deletes or closes the key.
pub struct ServiceTlsSigningWorker<'key> {
    key: KeyOwner<'key>,
    public_key: TlsPublicKey,
    shared: Arc<Shared>,
    receiver: Option<Receiver<Job>>,
    worker_thread: ThreadId,
    _thread_affine: PhantomData<Rc<()>>,
}

impl ServiceTlsSigningWorker<'_> {
    /// Nonblocking queue admission; services at most one job. Native public-key
    /// inspection/signing itself can block and is not a hard two-second task.
    pub fn process_one(&mut self) -> Result<TlsSigningProgress, TlsSigningBridgeError> {
        self.process_with_clock(Instant::now)
    }

    fn process_with_clock(
        &mut self,
        clock: impl Fn() -> Instant,
    ) -> Result<TlsSigningProgress, TlsSigningBridgeError> {
        if thread::current().id() != self.worker_thread {
            self.close();
            return Err(TlsSigningBridgeError::WrongThread);
        }
        if self.shared.closed.load(Ordering::Acquire) {
            self.close();
            return Err(TlsSigningBridgeError::Closed);
        }
        let job = match self
            .receiver
            .as_ref()
            .ok_or(TlsSigningBridgeError::Closed)?
            .try_recv()
        {
            Ok(job) => job,
            Err(TryRecvError::Empty) => return Ok(TlsSigningProgress::Idle),
            Err(TryRecvError::Disconnected) => {
                self.close();
                return Err(TlsSigningBridgeError::Closed);
            }
        };
        let mut attempt = NativeAttempt {
            shared: Arc::clone(&self.shared),
            returned: false,
        };
        let result = (|| {
            job.request.remaining(clock())?;
            if job.input.role() != EndpointRole::Server {
                return Err(TlsSigningBridgeError::WrongRole);
            }
            if self.key.public_key()? != self.public_key {
                return Err(TlsSigningBridgeError::PublicKeyMismatch);
            }
            job.request.remaining(clock())?;
            let signature = self.key.sign(&job.input)?;
            job.request.remaining(clock())?;
            if self.key.public_key()? != self.public_key {
                return Err(TlsSigningBridgeError::PublicKeyMismatch);
            }
            job.request.remaining(clock())?;
            job.input
                .verify_signature(&self.public_key, &signature)
                .map_err(|_| TlsSigningBridgeError::InvalidSignature)?;
            job.request.remaining(clock())?;
            Ok(signature)
        })();
        attempt.returned = true;
        match result {
            Ok(signature) => match job.response.try_send(Ok(signature)) {
                Ok(()) => Ok(TlsSigningProgress::Signed),
                Err(_) => Ok(TlsSigningProgress::Discarded),
            },
            Err(error @ (TlsSigningBridgeError::Closed | TlsSigningBridgeError::TimedOut)) => {
                let _ = job.response.try_send(Err(error));
                Ok(TlsSigningProgress::Discarded)
            }
            Err(error) => {
                let _ = job.response.try_send(Err(error));
                self.close();
                Err(error)
            }
        }
    }

    pub fn close(&mut self) {
        self.shared.closed.store(true, Ordering::Release);
        // Drop the bounded queue instead of just draining it: an enqueue racing
        // its earlier closed check cannot leave work behind in a closed owner.
        // Response senders drop too; this never closes/deletes the borrowed key.
        drop(self.receiver.take());
    }
}

impl Drop for ServiceTlsSigningWorker<'_> {
    fn drop(&mut self) {
        self.close();
    }
}

impl fmt::Debug for ServiceTlsSigningWorker<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceTlsSigningWorker")
            .field("closed", &self.shared.closed.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(crate) mod tests;
