// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded Google certificate-status JSON, not a trusted/fresh status snapshot.
//! Informational fields never remove a published REVOKED/SUSPENDED membership.
#![forbid(unsafe_code)]

use std::{cell::Cell, collections::BTreeSet, fmt};

use serde::de::{self, DeserializeSeed, MapAccess, Visitor};

use crate::VerificationError;

const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_ENTRIES: usize = 32_768;
const MAX_SERIAL_BYTES: usize = 32;
const MAX_SERIAL_HEX_BYTES: usize = MAX_SERIAL_BYTES * 2;
const MAX_COMMENT_CHARACTERS: usize = 140;

/// Membership is only data. The caller must separately establish authenticated
/// provenance, freshness, chain validity and which certificate serials to test.
pub(crate) struct RevocationList {
    serials: BTreeSet<Vec<u8>>,
}

impl RevocationList {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, VerificationError> {
        if bytes.len() > MAX_BODY_BYTES {
            return Err(VerificationError::Bounds);
        }
        let context = ParseContext::default();
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let serials = RootSeed(&context)
            .deserialize(&mut deserializer)
            .map_err(|_| context.error())?;
        deserializer.end().map_err(|_| context.error())?;
        Ok(Self { serials })
    }

    /// Input is a positive big-endian magnitude, not DER. A bounded leading-zero
    /// representation is normalized defensively; this does not decode ASN.1.
    pub(crate) fn contains_serial(&self, serial: &[u8]) -> Result<bool, VerificationError> {
        let normalized = normalized_serial(serial)?;
        Ok(self.serials.contains(normalized))
    }
}

impl fmt::Debug for RevocationList {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RevocationList")
            .field("entries", &self.serials.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
enum DataFault {
    Bounds,
    Shape,
}

type TextDecoder<T> = fn(&str) -> Result<T, DataFault>;

#[derive(Default)]
struct ParseContext {
    bounds: Cell<bool>,
}

impl ParseContext {
    fn reject<E: de::Error>(&self, fault: DataFault) -> E {
        if matches!(fault, DataFault::Bounds) {
            self.bounds.set(true);
        }
        E::custom("invalid certificate-status data")
    }

    fn error(&self) -> VerificationError {
        if self.bounds.get() {
            VerificationError::Bounds
        } else {
            VerificationError::Der
        }
    }
}

/// serde_json owns JSON syntax/UTF-8/escape handling and its normal recursion
/// bound. The whole body is capped before parsing; escaped-string scratch space
/// may reach that body cap before this visitor can enforce the decoded bound.
/// No serde_json::Value, recursive ignored-value traversal or raw errors escape.
struct TextSeed<'a, T> {
    context: &'a ParseContext,
    maximum_bytes: usize,
    decode: TextDecoder<T>,
}

impl<'de, T> DeserializeSeed<'de> for TextSeed<'_, T> {
    type Value = T;

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<T, D::Error> {
        deserializer.deserialize_str(self)
    }
}

impl<'de, T> Visitor<'de> for TextSeed<'_, T> {
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded certificate-status string")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<T, E> {
        if value.len() > self.maximum_bytes {
            return Err(self.context.reject(DataFault::Bounds));
        }
        (self.decode)(value).map_err(|fault| self.context.reject(fault))
    }
}

#[derive(Clone, Copy)]
enum Field {
    Entries,
    Status,
    Reason,
    Comment,
    Expires,
}

fn field(value: &str) -> Result<Field, DataFault> {
    match value {
        "entries" => Ok(Field::Entries),
        "status" => Ok(Field::Status),
        "reason" => Ok(Field::Reason),
        "comment" => Ok(Field::Comment),
        "expires" => Ok(Field::Expires),
        _ => Err(DataFault::Shape),
    }
}

fn field_seed(context: &ParseContext) -> TextSeed<'_, Field> {
    TextSeed {
        context,
        maximum_bytes: 7,
        decode: field,
    }
}

struct RootSeed<'a>(&'a ParseContext);

impl<'de> DeserializeSeed<'de> for RootSeed<'_> {
    type Value = BTreeSet<Vec<u8>>;

    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for RootSeed<'_> {
    type Value = BTreeSet<Vec<u8>>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the certificate-status entries object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut entries = None;
        while let Some(key) = map.next_key_seed(field_seed(self.0))? {
            if !matches!(key, Field::Entries) || entries.is_some() {
                return Err(self.0.reject(DataFault::Shape));
            }
            entries = Some(map.next_value_seed(EntriesSeed(self.0))?);
        }
        entries.ok_or_else(|| self.0.reject(DataFault::Shape))
    }
}

struct EntriesSeed<'a>(&'a ParseContext);

impl<'de> DeserializeSeed<'de> for EntriesSeed<'_> {
    type Value = BTreeSet<Vec<u8>>;

    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for EntriesSeed<'_> {
    type Value = BTreeSet<Vec<u8>>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded map of canonical hexadecimal serials")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut entries = BTreeSet::new();
        while let Some(serial) = map.next_key_seed(TextSeed {
            context: self.0,
            maximum_bytes: MAX_SERIAL_HEX_BYTES,
            decode: serial_key,
        })? {
            if entries.len() >= MAX_ENTRIES {
                return Err(self.0.reject(DataFault::Bounds));
            }
            // Compare normalized magnitudes, also catching JSON-escaped aliases.
            if entries.contains(&serial) {
                return Err(self.0.reject(DataFault::Shape));
            }
            map.next_value_seed(RowSeed(self.0))?;
            entries.insert(serial);
        }
        Ok(entries)
    }
}

struct RowSeed<'a>(&'a ParseContext);

impl<'de> DeserializeSeed<'de> for RowSeed<'_> {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for RowSeed<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a certificate-status row")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen = 0u8;
        while let Some(key) = map.next_key_seed(field_seed(self.0))? {
            let (flag, maximum_bytes, decode): (u8, usize, TextDecoder<()>) = match key {
                Field::Status => (1, 9, status),
                Field::Reason => (2, 14, reason),
                Field::Comment => (4, MAX_COMMENT_CHARACTERS * 4, comment),
                Field::Expires => (8, 10, date),
                Field::Entries => return Err(self.0.reject(DataFault::Shape)),
            };
            if seen & flag != 0 {
                return Err(self.0.reject(DataFault::Shape));
            }
            seen |= flag;
            map.next_value_seed(TextSeed {
                context: self.0,
                maximum_bytes,
                decode,
            })?;
        }
        if seen & 1 == 0 {
            return Err(self.0.reject(DataFault::Shape));
        }
        Ok(())
    }
}

fn status(value: &str) -> Result<(), DataFault> {
    match value {
        "REVOKED" | "SUSPENDED" => Ok(()),
        _ => Err(DataFault::Shape),
    }
}

fn reason(value: &str) -> Result<(), DataFault> {
    match value {
        "UNSPECIFIED" | "KEY_COMPROMISE" | "CA_COMPROMISE" | "SUPERSEDED" | "SOFTWARE_FLAW" => {
            Ok(())
        }
        _ => Err(DataFault::Shape),
    }
}

fn comment(value: &str) -> Result<(), DataFault> {
    if value.chars().take(MAX_COMMENT_CHARACTERS + 1).count() > MAX_COMMENT_CHARACTERS {
        Err(DataFault::Bounds)
    } else {
        Ok(())
    }
}

/// Schema date syntax/calendar only. No wall clock or local expiry decision.
fn date(value: &str) -> Result<(), DataFault> {
    let [y0, y1, y2, y3, b'-', m0, m1, b'-', d0, d1] = value.as_bytes() else {
        return Err(DataFault::Shape);
    };
    fn digits(first: u8, second: u8) -> Result<u16, DataFault> {
        if !first.is_ascii_digit() || !second.is_ascii_digit() {
            return Err(DataFault::Shape);
        }
        Ok(u16::from(first - b'0') * 10 + u16::from(second - b'0'))
    }
    let year = digits(*y0, *y1)? * 100 + digits(*y2, *y3)?;
    let month = digits(*m0, *m1)?;
    let day = digits(*d0, *d1)?;
    let leap = year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100));
    let maximum = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(DataFault::Shape),
    };
    if day == 0 || day > maximum {
        Err(DataFault::Shape)
    } else {
        Ok(())
    }
}

fn nibble(byte: u8) -> Result<u8, DataFault> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(DataFault::Shape),
    }
}

fn serial_key(value: &str) -> Result<Vec<u8>, DataFault> {
    let mut digits = value.as_bytes();
    if digits.is_empty() || digits.first() == Some(&b'0') {
        return Err(DataFault::Shape);
    }
    let mut serial = Vec::with_capacity(digits.len().div_ceil(2));
    if !digits.len().is_multiple_of(2) {
        let (first, rest) = digits.split_first().ok_or(DataFault::Shape)?;
        serial.push(nibble(*first)?);
        digits = rest;
    }
    for pair in digits.chunks_exact(2) {
        let [high, low] = pair else {
            return Err(DataFault::Shape);
        };
        serial.push((nibble(*high)? << 4) | nibble(*low)?);
    }
    Ok(serial)
}

fn normalized_serial(mut serial: &[u8]) -> Result<&[u8], VerificationError> {
    if serial.is_empty() {
        return Err(VerificationError::Der);
    }
    // Permit at most one extra representation byte before normalization; a
    // giant zero prefix cannot consume unbounded lookup work.
    if serial.len() > MAX_SERIAL_BYTES + 1 {
        return Err(VerificationError::Bounds);
    }
    while serial.len() > 1 && serial.first() == Some(&0) {
        serial = serial.get(1..).ok_or(VerificationError::Der)?;
    }
    if serial == [0] {
        return Err(VerificationError::Der);
    }
    if serial.len() > MAX_SERIAL_BYTES {
        return Err(VerificationError::Bounds);
    }
    Ok(serial)
}

#[cfg(test)]
mod tests;
