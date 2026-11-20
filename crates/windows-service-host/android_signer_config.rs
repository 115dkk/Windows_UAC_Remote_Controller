// SPDX-License-Identifier: GPL-2.0-or-later

pub(crate) fn parse_signers(value: Option<&str>) -> Result<Vec<[u8; 32]>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if value.is_empty() {
        return Err("UAC_ANDROID_SIGNER_SHA256 must not be empty when set".into());
    }
    value
        .split(',')
        .map(|digest| {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(
                    "UAC_ANDROID_SIGNER_SHA256 requires comma-separated lowercase SHA-256 hex"
                        .into(),
                );
            }
            let mut bytes = [0_u8; 32];
            for (output, pair) in bytes.iter_mut().zip(digest.as_bytes().as_chunks::<2>().0) {
                let nibble = |byte: u8| match byte {
                    b'0'..=b'9' => byte - b'0',
                    b'a'..=b'f' => byte - b'a' + 10,
                    _ => unreachable!(),
                };
                *output = nibble(pair[0]) * 16 + nibble(pair[1]);
            }
            Ok(bytes)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_signers;

    #[test]
    fn missing_is_empty_and_lowercase_digests_parse() {
        assert!(parse_signers(None).unwrap().is_empty());
        let parsed =
            parse_signers(Some(&format!("{},{}", "01".repeat(32), "ab".repeat(32)))).unwrap();
        assert_eq!(parsed, vec![[1; 32], [0xab; 32]]);
    }

    #[test]
    fn malformed_values_reject() {
        for value in ["", "00", &"A0".repeat(32), &format!("{},", "00".repeat(32))] {
            assert!(parse_signers(Some(value)).is_err());
        }
    }
}
