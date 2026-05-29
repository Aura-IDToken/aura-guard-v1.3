#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Strict RFC 3161 verifier integration tests.
//!
//! These tests run against committed FreeTSA fixtures and tampered
//! variants. The TSR + root fixtures are real (round-tripped against
//! `https://freetsa.org/tsr` and `https://freetsa.org/files/cacert.pem`);
//! the tampered variants are generated in-test by mutating well-defined
//! offsets so that we exercise specific failure paths without smuggling
//! large binary diffs into the repo.

use std::fs;
use std::path::Path;

use aura_guard::segment::SegmentManifest;
use aura_guard::tst_verify::{verify_tsr, TrustAnchors, TstError};
use sha2::{Digest, Sha256};

/// Helper: load a fixture TSR and its manifest, return (tsr_bytes, expected_imprint).
fn load_segment(segment_id: u64) -> (Vec<u8>, [u8; 32], SegmentManifest) {
    let manifest_path = format!("tests/fixtures/tsa/segment-{segment_id:03}.manifest.json");
    let tsr_path = format!("tests/fixtures/tsa/segment-{segment_id:03}.tsr");
    let manifest: SegmentManifest =
        serde_json::from_slice(&fs::read(&manifest_path).expect("manifest exists")).unwrap();
    let tsr = fs::read(&tsr_path).expect("tsr exists");
    let preimage = SegmentManifest::segment_chain_preimage(
        &manifest.prev_segment_chain_hash,
        &manifest.merkle_root,
        manifest.first_seq,
        manifest.last_seq,
        &manifest.sealed_at,
    );
    let imprint: [u8; 32] = Sha256::digest(preimage.as_bytes()).into();
    (tsr, imprint, manifest)
}

fn anchors() -> TrustAnchors {
    TrustAnchors::from_pem_file(Path::new("tests/fixtures/tsa/freetsa-cacert.pem"))
        .expect("load freetsa-cacert.pem")
}

#[test]
fn valid_tsr_passes_strict_verification_segment_001() {
    let (tsr, imprint, _) = load_segment(1);
    let v = verify_tsr(&tsr, &imprint, &anchors()).expect("verify segment-001");
    assert_eq!(v.policy_oid, "1.2.3.4.1");
    assert!(v.signer_subject.contains("Free TSA"));
    assert!(v.root_subject.contains("Free TSA"));
    assert_eq!(v.message_imprint_sha256, hex::encode(imprint));
}

#[test]
fn valid_tsr_passes_strict_verification_segment_002() {
    let (tsr, imprint, _) = load_segment(2);
    let v = verify_tsr(&tsr, &imprint, &anchors()).expect("verify segment-002");
    assert!(v.signer_subject.contains("Free TSA"));
}

#[test]
fn wrong_expected_imprint_fails() {
    let (tsr, _, _) = load_segment(1);
    let bogus = [0u8; 32];
    let err = verify_tsr(&tsr, &bogus, &anchors()).expect_err("must reject wrong imprint");
    assert!(
        matches!(err, TstError::ImprintMismatch { .. }),
        "got {err:?}"
    );
}

#[test]
fn no_trust_anchor_fails() {
    let (tsr, imprint, _) = load_segment(1);
    let empty_anchors = TrustAnchors::from_pem_bytes(
        b"-----BEGIN CERTIFICATE-----\n\
          -----END CERTIFICATE-----\n",
    );
    // PEM parser rejects an empty block: this matches operational expectation
    // that operators cannot accidentally configure a no-op trust set.
    assert!(empty_anchors.is_err());

    // Confirm: a real but unrelated root must also fail with Chain error.
    // The freetsa-tsa.crt is the *signer* cert, not a self-signed root,
    // so anchoring against it cannot terminate the chain.
    let signer_only = TrustAnchors::from_pem_file(Path::new("tests/fixtures/tsa/freetsa-tsa.crt"))
        .expect("load signer cert as PEM");
    let err = verify_tsr(&tsr, &imprint, &signer_only)
        .expect_err("must reject chain that does not reach the pinned root");
    assert!(matches!(err, TstError::Chain(_)), "got {err:?}");
}

#[test]
fn tampered_signedattrs_fails_with_signature_or_digest_error() {
    let (mut tsr, imprint, _) = load_segment(1);
    // Flip a byte inside the SignedData area. Offset 4500 lands in the
    // signed-data region in our fixture (4633-byte TSR); flipping it
    // perturbs the messageDigest signedAttr or the signature itself.
    let idx = 4500usize.min(tsr.len() - 1);
    tsr[idx] ^= 0xFF;
    let err = verify_tsr(&tsr, &imprint, &anchors()).expect_err("must reject tampered TSR");
    // Either the SignerInfo signature fails or the messageDigest attr
    // no longer matches eContent — both are valid CHAIN-of-trust
    // failures we want to surface to the operator.
    let is_expected = matches!(
        err,
        TstError::SignerSignature(_) | TstError::BadMessageDigestAttr(_) | TstError::Asn1(_)
    );
    assert!(
        is_expected,
        "expected signature/digest/asn1 error, got {err:?}"
    );
}

#[test]
fn truncated_tsr_fails_cleanly() {
    let (mut tsr, imprint, _) = load_segment(1);
    tsr.truncate(100);
    let err = verify_tsr(&tsr, &imprint, &anchors()).expect_err("must reject truncated input");
    assert!(matches!(err, TstError::Asn1(_)), "got {err:?}");
}

#[test]
fn empty_tsr_fails_cleanly() {
    let err = verify_tsr(&[], &[0u8; 32], &anchors()).expect_err("must reject empty input");
    assert!(matches!(err, TstError::Asn1(_)), "got {err:?}");
}

#[test]
fn trust_anchors_load_from_real_pem() {
    let anchors = TrustAnchors::from_pem_file(Path::new("tests/fixtures/tsa/freetsa-cacert.pem"))
        .expect("load");
    let _ = anchors;
}

#[test]
fn trust_anchors_reject_garbage_pem() {
    let err = TrustAnchors::from_pem_bytes(b"this is not PEM").expect_err("must reject");
    let _ = err;
}
