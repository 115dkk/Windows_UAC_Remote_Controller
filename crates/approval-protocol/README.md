# Approval protocol v1

Status: implemented_unverified. This crate is a pure shared protocol foundation,
not a paired phone, authenticated transport, Android authentication check, or
Windows UAC integration.

## Canonical signing and Android interop

Use the exact bytes returned by `UnsignedDecision::signing_bytes()` as input to
Android `SHA256withECDSA` with the enrolled P-256 purpose key. Do not sign JSON,
reorder fields, interpret path/details as a command, or prehash those bytes before
passing them to that algorithm. The verifier uses fixed P-256/SHA-256.

The signing record is:

| Field | Encoding |
| --- | --- |
| Domain | UTF-8 bytes `Windows-UAC-Remote-Controller/approve/v1` plus NUL for approve; `Windows-UAC-Remote-Controller/deny/v1` plus NUL for deny |
| Version | u16 big-endian, exactly 1 |
| Device identity | 16 nonzero bytes |
| Purpose | u8: 1 approve, 2 deny |
| PC identity | 32 nonzero bytes |
| Service boot epoch | 32 nonzero random bytes |
| Windows session | u32 big-endian session ID followed by u64 big-endian logon LUID |
| Request ID | 32 nonzero random bytes |
| Challenge nonce | 32 independent nonzero random bytes |
| Content digest | 32 bytes SHA-256 |
| Expiry | u64 big-endian, positive nanoseconds since the current service epoch's monotonic start |

Expiry is an opaque value for the phone to sign. It is not a remote wall-clock
deadline. The service maintains and checks the corresponding actual `Instant`.

`SignedDecision::from_der` accepts the exact ASN.1 DER result of Android signing,
bounded to 8–72 bytes. It rejects noncanonical padding, zero/out-of-range scalars,
negative integers, indefinite lengths, garbage and trailing bytes. Both valid S
representatives interoperate; the verifier normalizes S internally. Neither raw
DER bytes nor a signature hash is ever a replay identifier.

`DecisionPublicKey::from_sec1_bytes` accepts only a valid compressed (33-byte,
prefix 02/03) or uncompressed (65-byte, prefix 04) P-256 SEC1 point. It stores
compressed form so alternate encodings cannot evade key-separation checks. This
validates the public key, not Android hardware provenance or authentication policy.

## Wire and content bounds

The decision wire record is the eight-byte `WUACDEC` plus NUL magic, followed by
the signing record **without its domain**, followed by a u16 big-endian DER length
and exactly that many DER bytes. Its total size is 217–281 bytes. The parser
rejects unknown versions, unknown purposes, invalid fixed fields, malformed DER,
incorrect lengths, truncation and trailing bytes before accepting a record. There
is no attacker-controlled algorithm, extension, key or allocation length.

`RequestContent` retains an exact UTF-8 `program_name`, path and details as
immutable separate data fields. The name works for ordinary GUI applications as
well as terminal shells; it does not assert that every request runs a shell.
Each field is bounded to 98,304 bytes: a conservative 32,768 UTF-16-code-unit
budget times a maximum three UTF-8 bytes per UTF-16 code unit. Supplementary
characters take four UTF-8 bytes for two UTF-16 units, so they fit too. The former
4,096/8,192-byte path/details caps would reject normal long Windows strings,
especially non-ASCII strings. This budget does not prove any OS capture path or
define how a future adapter handles ill-formed UTF-16, publisher provenance or
other metadata. Never silently truncate or normalize a request to fit.

Name and path are nonempty; details may be empty; NUL is rejected. Total text
payload is at most 294,912 bytes (288 KiB), plus allocation headers. Its digest
covers a separate versioned domain, version, and each field's tag, u32 big-endian
byte length, and bytes. Renaming the first field does not change its tag or the
v1 canonical bytes. The decision wire record remains 217–281 bytes because it
contains a content digest, not the display body. No JSON/body parser or
attacker-sized allocation path is introduced. A future transport must validate
its own per-field, total frame and concurrent-memory limits before allocating.

The digest neither normalizes Unicode/case nor authenticates a Windows origin.
Windows credentials and QR bootstrap secrets do not belong in these fields.
Command-line details may themselves be sensitive: the user's on-demand display
requirement must use transient, confidential delivery to the enrolled phone,
not silently omit the original text or copy it to logs, analytics or history.
Debug is redacted, but this is not heap zeroization or crash-dump protection.
The host must release presentation copies and configure diagnostic collection
appropriately. Separate transient display from operational logging.

Fixtures exercise canonical records, parsing, wrong keys, every binding field,
DER interop (including nonminimal lengths and out-of-range scalars), GUI/shell
names, full-budget Unicode content and signature malleability. They were written
but not executed by the implementation/security-review child agents.
