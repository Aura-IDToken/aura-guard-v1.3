//! Minimal RFC 3161 Time-Stamp Protocol client.
//!
//! Scope (v1.4):
//!
//! * Build a SHA-256 `TimeStampReq` (DER) for a given digest.
//! * POST it to a TSA over HTTP(S) with `Content-Type:
//!   application/timestamp-query`.
//! * Persist the opaque `TimeStampResp` (DER) bytes so they can be
//!   verified offline by `aura-seal verify-tst`.
//! * Probe the response for the original message imprint to confirm the
//!   TSA echoed the digest we asked it to stamp.
//!
//! Out of scope (v1.4 → deferred to v1.5):
//!
//! * Full ASN.1 parsing of `TSTInfo`.
//! * PKIX certificate-chain validation against an operator-pinned root.
//! * Signature verification of the TSA `SignedData`.
//!
//! These intentional limits keep the v1.4 surface area small and the
//! deterministic Merkle layer fully testable without a network mock; full
//! TSR validation lands as a focused follow-up.

use std::io::Read;
use std::time::Duration;

use sha2::{Digest, Sha256};

/// Errors surfaced by the TSA client. All variants are non-fatal: callers
/// (`SegmentSealer`) are expected to log + count and continue.
#[derive(Debug, thiserror::Error)]
pub enum TsaError {
    /// Network or TLS error while POSTing to the TSA.
    #[error("TSA transport error: {0}")]
    Transport(String),
    /// HTTP status was not 200.
    #[error("TSA HTTP {0}: {1}")]
    Http(u16, String),
    /// The TSR did not contain the request's message imprint as a 32-byte
    /// contiguous substring. Either the TSA returned a `granted-with-mods`
    /// stamp for a different digest, or a transport intermediary tampered
    /// with the response.
    #[error("TSR does not contain the requested message imprint")]
    ImprintMismatch,
}

/// SHA-256 OID `2.16.840.1.101.3.4.2.1` (RFC 5754 § 2.1) in DER form
/// (`OBJECT IDENTIFIER` body bytes).
const SHA256_OID_DER: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
];

/// Build a DER-encoded `TimeStampReq` for the given **already-hashed**
/// 32-byte SHA-256 digest.
///
/// ```text
/// TimeStampReq ::= SEQUENCE {
///   version          INTEGER (v1),
///   messageImprint   SEQUENCE { hashAlgorithm AlgorithmIdentifier,
///                               hashedMessage OCTET STRING },
///   certReq          BOOLEAN DEFAULT FALSE  -- we set TRUE for offline verify
/// }
/// ```
#[must_use]
pub fn build_request(digest: &[u8; 32]) -> Vec<u8> {
    // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters NULL }
    let mut algo = Vec::with_capacity(13);
    algo.extend_from_slice(SHA256_OID_DER); // OID
    algo.extend_from_slice(&[0x05, 0x00]); // NULL parameters
    let algo_seq = der_sequence(&algo);

    // hashedMessage OCTET STRING
    let mut octet = vec![0x04, 0x20];
    octet.extend_from_slice(digest);

    // messageImprint SEQUENCE
    let mut imprint = Vec::with_capacity(algo_seq.len() + octet.len());
    imprint.extend_from_slice(&algo_seq);
    imprint.extend_from_slice(&octet);
    let imprint_seq = der_sequence(&imprint);

    // version INTEGER 1
    let version = [0x02, 0x01, 0x01];

    // certReq BOOLEAN TRUE — request that the TSA include its signing cert
    // chain so the response is offline-verifiable.
    let cert_req = [0x01, 0x01, 0xff];

    let mut body = Vec::with_capacity(version.len() + imprint_seq.len() + cert_req.len());
    body.extend_from_slice(&version);
    body.extend_from_slice(&imprint_seq);
    body.extend_from_slice(&cert_req);

    der_sequence(&body)
}

/// Submit `der_request` to `tsa_url` via HTTP POST and return the raw
/// DER-encoded `TimeStampResp` bytes.
///
/// The caller is expected to persist the bytes opaquely; this function
/// validates only the HTTP transport, **not** the cryptographic content of
/// the response.
pub fn submit(tsa_url: &str, der_request: &[u8], timeout: Duration) -> Result<Vec<u8>, TsaError> {
    let agent = ureq::AgentBuilder::new()
        .timeout(timeout)
        .user_agent(concat!("aura-guard/", env!("CARGO_PKG_VERSION")))
        .build();

    let resp = agent
        .post(tsa_url)
        .set("Content-Type", "application/timestamp-query")
        .set("Accept", "application/timestamp-reply")
        .send_bytes(der_request)
        .map_err(|e| match e {
            ureq::Error::Status(code, response) => TsaError::Http(
                code,
                response
                    .into_string()
                    .unwrap_or_else(|_| "<unreadable body>".to_string()),
            ),
            other => TsaError::Transport(other.to_string()),
        })?;

    let mut buf = Vec::new();
    resp.into_reader()
        .read_to_end(&mut buf)
        .map_err(|e| TsaError::Transport(e.to_string()))?;
    Ok(buf)
}

/// Convenience wrapper: build a request for `preimage` (which is hashed
/// with SHA-256 first), submit it, and return the response bytes alongside
/// the 32-byte digest that was stamped.
pub fn timestamp(
    tsa_url: &str,
    preimage: &[u8],
    timeout: Duration,
) -> Result<(Vec<u8>, [u8; 32]), TsaError> {
    let digest: [u8; 32] = Sha256::digest(preimage).into();
    let req = build_request(&digest);
    let resp = submit(tsa_url, &req, timeout)?;
    if !contains_imprint(&resp, &digest) {
        return Err(TsaError::ImprintMismatch);
    }
    Ok((resp, digest))
}

/// Search for the 32-byte message imprint inside the opaque TSR.
///
/// RFC 3161 mandates that the TSA echo the original `MessageImprint` inside
/// `TSTInfo`, encoded as `OCTET STRING (32 bytes)`. The DER encoding of
/// that field is the literal sequence `04 20 || imprint`, which always
/// appears verbatim in the response. This is the minimum check needed to
/// detect bait-and-switch; full ASN.1 parsing lands in v1.5.
#[must_use]
pub fn contains_imprint(tsr: &[u8], imprint: &[u8; 32]) -> bool {
    let mut needle = Vec::with_capacity(2 + imprint.len());
    needle.extend_from_slice(&[0x04, 0x20]);
    needle.extend_from_slice(imprint);
    tsr.windows(needle.len()).any(|w| w == needle.as_slice())
}

/// Wrap a body in a DER `SEQUENCE` tag with the correct length encoding.
fn der_sequence(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 4);
    out.push(0x30);
    encode_length(body.len(), &mut out);
    out.extend_from_slice(body);
    out
}

/// DER short/long-form length encoding.
fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let mut tmp = [0u8; 8];
    let mut n = len;
    let mut i = 0;
    while n > 0 {
        tmp[i] = (n & 0xff) as u8;
        n >>= 8;
        i += 1;
    }
    out.push(0x80 | (i as u8));
    for j in (0..i).rev() {
        out.push(tmp[j]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_request_matches_known_shape() {
        let digest = [0xabu8; 32];
        let req = build_request(&digest);

        // SEQUENCE tag + length
        assert_eq!(req[0], 0x30);
        // Should contain the SHA-256 OID bytes verbatim.
        assert!(req
            .windows(SHA256_OID_DER.len())
            .any(|w| w == SHA256_OID_DER));
        // Should contain the 32-byte digest as `04 20 || digest`.
        let mut needle = vec![0x04, 0x20];
        needle.extend_from_slice(&digest);
        assert!(req.windows(needle.len()).any(|w| w == needle.as_slice()));
        // Length encoded correctly: TimeStampReq body is small (<128) so
        // length is a single byte.
        assert_eq!(req.len() as u8, req[1] + 2);
    }

    #[test]
    fn contains_imprint_finds_substring() {
        let imprint = [0x42u8; 32];
        let mut tsr = vec![0u8; 50];
        tsr.extend_from_slice(&[0x04, 0x20]);
        tsr.extend_from_slice(&imprint);
        tsr.extend_from_slice(&[0u8; 20]);
        assert!(contains_imprint(&tsr, &imprint));
    }

    #[test]
    fn contains_imprint_rejects_wrong_digest() {
        let imprint = [0x42u8; 32];
        let other = [0x99u8; 32];
        let mut tsr = vec![0x04, 0x20];
        tsr.extend_from_slice(&imprint);
        assert!(!contains_imprint(&tsr, &other));
    }

    #[test]
    fn encode_length_short_form() {
        let mut out = Vec::new();
        encode_length(0x7f, &mut out);
        assert_eq!(out, vec![0x7f]);
    }

    #[test]
    fn encode_length_long_form() {
        let mut out = Vec::new();
        encode_length(0x100, &mut out);
        assert_eq!(out, vec![0x82, 0x01, 0x00]);
    }
}
