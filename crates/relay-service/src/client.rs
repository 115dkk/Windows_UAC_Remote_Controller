// SPDX-License-Identifier: GPL-2.0-or-later
//! Untrusted rendezvous carrier setup. The result MUST be wrapped in peer-pinned
//! TLS; neither the public marker nor this successful function authenticates a PC.
use crate::{CancellationToken, READY_MARKER, Registration};
use std::{fmt, net::SocketAddr, time::Duration};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const CLIENT_RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(30);

/// Opaque byte carrier only, deliberately not named authenticated/ready/paired.
pub struct RendezvousCarrier(TcpStream);
impl RendezvousCarrier {
    /// Move directly into the endpoint's bounded, authenticated TLS actor.
    /// Do not send plaintext application requests or credentials on this stream.
    pub fn into_stream(self) -> TcpStream {
        self.0
    }
}
impl fmt::Debug for RendezvousCarrier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RendezvousCarrier([unauthenticated])")
    }
}

pub async fn connect_rendezvous(
    address: SocketAddr,
    registration: Registration,
    stop: CancellationToken,
) -> Result<RendezvousCarrier, RendezvousError> {
    let mut stream = tokio::select! {
        biased;
        _ = stop.cancelled() => return Err(RendezvousError::Cancelled),
        result = timeout(CONNECT_TIMEOUT, TcpStream::connect(address)) => {
            result.map_err(|_| RendezvousError::ConnectTimeout)?.map_err(|_| RendezvousError::Connection)?
        }
    };
    // The application uses small control/TLS records. Set the actual socket
    // policy in product code, not only in a benchmark or test fixture.
    stream
        .set_nodelay(true)
        .map_err(|_| RendezvousError::Connection)?;
    let exchange = async {
        stream
            .write_all(&registration.to_wire())
            .await
            .map_err(|_| RendezvousError::Connection)?;
        let mut marker = [0; READY_MARKER.len()];
        stream
            .read_exact(&mut marker)
            .await
            .map_err(|_| RendezvousError::Connection)?;
        if &marker != READY_MARKER {
            return Err(RendezvousError::InvalidMarker);
        }
        Ok(())
    };
    tokio::select! {
        biased;
        _ = stop.cancelled() => return Err(RendezvousError::Cancelled),
        result = timeout(CLIENT_RENDEZVOUS_TIMEOUT, exchange) => {
            result.map_err(|_| RendezvousError::RendezvousTimeout)??;
        }
    }
    Ok(RendezvousCarrier(stream))
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RendezvousError {
    #[error("rendezvous setup was cancelled")]
    Cancelled,
    #[error("rendezvous connection deadline expired")]
    ConnectTimeout,
    #[error("rendezvous waiting deadline expired")]
    RendezvousTimeout,
    #[error("rendezvous connection could not complete")]
    Connection,
    #[error("rendezvous marker was invalid")]
    InvalidMarker,
}
