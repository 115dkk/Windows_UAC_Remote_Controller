// SPDX-License-Identifier: GPL-2.0-or-later
//! Strict parser for the fixed, version-bound protected repair manifest.
#![forbid(unsafe_code)]

use serde::Deserialize;

use crate::SERVICE_EXECUTABLE;

pub(crate) const MAX_REPAIR_MANIFEST_BYTES: u64 = 4096;
pub(crate) const MAX_REPAIR_FILE_BYTES: u64 = 128 * 1024 * 1024;
const PRODUCT: &str = "uac-remote-controller";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RepairFileName {
    Service,
    Probe,
}

impl RepairFileName {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Service => SERVICE_EXECUTABLE,
            Self::Probe => windows_prompt_probe::supervision::PROBE_EXECUTABLE,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RepairFile {
    name: RepairFileName,
    bytes: u64,
    sha256: [u8; 32],
}

impl RepairFile {
    pub(crate) const fn name(self) -> RepairFileName {
        self.name
    }

    pub(crate) const fn bytes(self) -> u64 {
        self.bytes
    }

    pub(crate) const fn sha256(self) -> [u8; 32] {
        self.sha256
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RepairManifest {
    files: [RepairFile; 2],
}

impl RepairManifest {
    pub(crate) const fn files(self) -> [RepairFile; 2] {
        self.files
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    schema: u8,
    product: String,
    version: String,
    files: Vec<RawFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    name: String,
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InvalidRepairManifest;

pub(crate) fn parse(bytes: &[u8]) -> Result<RepairManifest, InvalidRepairManifest> {
    if bytes.is_empty()
        || bytes.len() as u64 > MAX_REPAIR_MANIFEST_BYTES
        || bytes.starts_with(&[0xef, 0xbb, 0xbf])
    {
        return Err(InvalidRepairManifest);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| InvalidRepairManifest)?;
    let raw: RawManifest = serde_json::from_str(text).map_err(|_| InvalidRepairManifest)?;
    if raw.schema != 1 || raw.product != PRODUCT || raw.version != env!("CARGO_PKG_VERSION") {
        return Err(InvalidRepairManifest);
    }
    let [service, probe]: [RawFile; 2] = raw.files.try_into().map_err(|_| InvalidRepairManifest)?;
    Ok(RepairManifest {
        files: [
            validate_file(service, RepairFileName::Service)?,
            validate_file(probe, RepairFileName::Probe)?,
        ],
    })
}

fn validate_file(
    file: RawFile,
    expected: RepairFileName,
) -> Result<RepairFile, InvalidRepairManifest> {
    if file.name != expected.as_str() || !(1..=MAX_REPAIR_FILE_BYTES).contains(&file.bytes) {
        return Err(InvalidRepairManifest);
    }
    let sha256 = decode_sha256(&file.sha256)?;
    Ok(RepairFile {
        name: expected,
        bytes: file.bytes,
        sha256,
    })
}

fn decode_sha256(text: &str) -> Result<[u8; 32], InvalidRepairManifest> {
    if text.len() != 64 {
        return Err(InvalidRepairManifest);
    }
    let digit = |value: u8| match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(InvalidRepairManifest),
    };
    let mut digest = [0u8; 32];
    for (output, pair) in digest.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
        *output = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn valid_value() -> Value {
        json!({
            "schema": 1,
            "product": "uac-remote-controller",
            "version": env!("CARGO_PKG_VERSION"),
            "files": [
                {
                    "name": SERVICE_EXECUTABLE,
                    "bytes": 123,
                    "sha256": "01".repeat(32),
                },
                {
                    "name": windows_prompt_probe::supervision::PROBE_EXECUTABLE,
                    "bytes": 456,
                    "sha256": "ab".repeat(32),
                }
            ]
        })
    }

    fn encoded(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).expect("test JSON must encode")
    }

    fn rejected(value: Value) {
        assert_eq!(parse(&encoded(&value)), Err(InvalidRepairManifest));
    }

    #[test]
    fn accepts_the_exact_manifest_and_decodes_hashes() {
        let manifest = parse(&encoded(&valid_value())).expect("valid manifest");
        let [service, probe] = manifest.files();
        assert_eq!(service.name(), RepairFileName::Service);
        assert_eq!(service.bytes(), 123);
        assert_eq!(service.sha256(), [0x01; 32]);
        assert_eq!(probe.name(), RepairFileName::Probe);
        assert_eq!(probe.bytes(), 456);
        assert_eq!(probe.sha256(), [0xab; 32]);
    }

    #[test]
    fn rejects_each_wrong_top_level_field_and_unknown_field() {
        let mut schema = valid_value();
        schema["schema"] = json!(2);
        rejected(schema);

        let mut product = valid_value();
        product["product"] = json!("another-product");
        rejected(product);

        let mut version = valid_value();
        version["version"] = json!("0.0.0-wrong");
        rejected(version);

        let mut extra = valid_value();
        extra["extra"] = json!(true);
        rejected(extra);

        for field in ["schema", "product", "version", "files"] {
            let mut value = valid_value();
            value.as_object_mut().unwrap().remove(field);
            rejected(value);
        }
    }

    #[test]
    fn rejects_wrong_file_count_order_and_names() {
        let mut one = valid_value();
        one["files"].as_array_mut().unwrap().pop();
        rejected(one);

        let mut three = valid_value();
        let duplicate = three["files"][1].clone();
        three["files"].as_array_mut().unwrap().push(duplicate);
        rejected(three);

        let mut reversed = valid_value();
        reversed["files"].as_array_mut().unwrap().reverse();
        rejected(reversed);

        let mut service_name = valid_value();
        service_name["files"][0]["name"] = json!("service.exe");
        rejected(service_name);

        let mut probe_name = valid_value();
        probe_name["files"][1]["name"] = json!("probe.exe");
        rejected(probe_name);

        for field in ["name", "bytes", "sha256"] {
            let mut value = valid_value();
            value["files"][0].as_object_mut().unwrap().remove(field);
            rejected(value);
        }
    }

    #[test]
    fn rejects_zero_and_oversize_file_lengths() {
        for (index, length) in [(0, 0), (1, MAX_REPAIR_FILE_BYTES + 1)] {
            let mut value = valid_value();
            value["files"][index]["bytes"] = json!(length);
            rejected(value);
        }
        let mut maximum = valid_value();
        maximum["files"][0]["bytes"] = json!(MAX_REPAIR_FILE_BYTES);
        assert!(parse(&encoded(&maximum)).is_ok());
        let mut one = valid_value();
        one["files"][1]["bytes"] = json!(1);
        assert!(parse(&encoded(&one)).is_ok());

        let mut wrong_type = valid_value();
        wrong_type["files"][0]["bytes"] = json!("123");
        rejected(wrong_type);
    }

    #[test]
    fn rejects_noncanonical_hashes_and_unknown_file_fields() {
        for digest in [
            "a".repeat(63),
            "a".repeat(65),
            "AB".repeat(32),
            format!("{}G", "a".repeat(63)),
            "gg".repeat(32),
        ] {
            let mut value = valid_value();
            value["files"][0]["sha256"] = json!(digest);
            rejected(value);
        }
        let mut extra = valid_value();
        extra["files"][1]["extra"] = json!(true);
        rejected(extra);
    }

    #[test]
    fn rejects_bom_invalid_utf8_invalid_json_and_oversize_input() {
        assert_eq!(parse(&[]), Err(InvalidRepairManifest));
        let mut bom = vec![0xef, 0xbb, 0xbf];
        bom.extend(encoded(&valid_value()));
        assert_eq!(parse(&bom), Err(InvalidRepairManifest));
        assert_eq!(parse(&[0xff]), Err(InvalidRepairManifest));
        assert_eq!(parse(b"not json"), Err(InvalidRepairManifest));
        assert_eq!(
            parse(&vec![b' '; MAX_REPAIR_MANIFEST_BYTES as usize + 1]),
            Err(InvalidRepairManifest)
        );
    }
}
