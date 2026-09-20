// SPDX-License-Identifier: GPL-2.0-or-later
//! Release-owned public anchors, never learned from a candidate or system store.

use crate::{VerificationError as Error, certificate::Certificate};
use der::asn1::ObjectIdentifier;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RootKind {
    FactoryRsa,
    CurrentP384,
}

pub(crate) struct Anchor {
    pub(crate) der: Vec<u8>,
    pub(crate) spki: Vec<u8>,
    pub(crate) kind: RootKind,
}

pub(crate) fn google() -> Result<&'static [Anchor], Error> {
    static ANCHORS: OnceLock<Result<Vec<Anchor>, Error>> = OnceLock::new();
    match ANCHORS.get_or_init(load) {
        Ok(anchors) => Ok(anchors),
        Err(error) => Err(*error),
    }
}

fn load() -> Result<Vec<Anchor>, Error> {
    const END: &str = "-----END CERTIFICATE-----";
    let input = include_str!("google-roots.pem");
    let mut roots = Vec::new();
    for part in input
        .split_inclusive(END)
        .filter(|part| !part.trim().is_empty())
    {
        let (label, encoded) =
            der::pem::decode_vec(part.trim().as_bytes()).map_err(|_| Error::InvalidPolicy)?;
        if label != "CERTIFICATE" {
            return Err(Error::InvalidPolicy);
        }
        let cert = Certificate::parse(&encoded)?;
        cert.verify_issued_by(&cert)?;
        let key = cert.parsed.tbs_certificate().subject_public_key_info();
        let kind = if key.algorithm.oid == ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1") {
            RootKind::FactoryRsa
        } else if key.algorithm.oid == ObjectIdentifier::new_unwrap("1.2.840.10045.2.1")
            && key
                .algorithm
                .parameters
                .as_ref()
                .ok_or(Error::InvalidPolicy)?
                .decode_as::<ObjectIdentifier>()
                .map_err(|_| Error::InvalidPolicy)?
                == ObjectIdentifier::new_unwrap("1.3.132.0.34")
        {
            RootKind::CurrentP384
        } else {
            return Err(Error::InvalidPolicy);
        };
        let spki = cert.spki().to_vec();
        roots.push(Anchor {
            der: encoded,
            spki,
            kind,
        });
    }
    if roots.len() != 2
        || roots[0].kind != RootKind::FactoryRsa
        || roots[1].kind != RootKind::CurrentP384
    {
        return Err(Error::InvalidPolicy);
    }
    Ok(roots)
}
