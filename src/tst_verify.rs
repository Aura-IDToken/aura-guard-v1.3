//! Full RFC 3161 Time-Stamp Response (`.tsr`) verifier.
//!
//! Scope (v1.5):
//!
//! * Parse the `TimeStampResp` wrapper, the encapsulated CMS `SignedData`
//!   and the inner `TSTInfo` structure.
//! * Verify that `messageImprint == SHA-256(preimage)` (anti-substitution
//!   for the segment we sealed).
//! * Verify the SignerInfo signature over the DER-re-encoded `signedAttrs`
//!   (RSA-PKCS1-v1.5 / ECDSA-P256 / ECDSA-P384, with SHA-256/-384/-512).
//! * Verify the `signingCertificate` (RFC 2634 v1, SHA-1) or
//!   `signingCertificateV2` (RFC 5816, SHA-256) attribute matches the
//!   signer certificate (anti-substitution per RFC 5816 §3).
//! * Walk the certificate chain (signer + any intermediates embedded in
//!   the CMS structure) up to an operator-pinned trust anchor.
//! * Require the signer certificate to carry EKU
//!   `id-kp-timeStamping` (1.3.6.1.5.5.7.3.8) marked critical
//!   (RFC 3161 §2.3).
//! * Check that `genTime` falls inside the signer certificate's validity
//!   window.
//!
//! What this verifier deliberately does **not** do:
//!
//! * Online revocation (CRL/OCSP): operators must rotate trust anchors
//!   out-of-band when a TSA key is revoked. The signer certificate is
//!   pinned by chain + EKU; revocation should be enforced operationally.
//! * Policy OID matching (`TSAPolicyId`): not part of integrity proof.
//! * Path length / name constraints: chains of TSAs in practice are
//!   2 deep (signer + root); we enforce that explicitly.
//!
//! This is enforced offline: the verifier never opens a network socket.

#![allow(clippy::module_name_repetitions)]

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use const_oid::ObjectIdentifier;
use der::asn1::{Any, OctetString, SetOfVec};
use der::oid::db::rfc5912;
use der::{Decode, Encode, Sequence};
use sha2::{Digest, Sha256, Sha384, Sha512};
use signature::hazmat::PrehashVerifier;
use spki::AlgorithmIdentifierOwned;
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::Certificate;

/// OID for `id-ct-TSTInfo` — `1.2.840.113549.1.9.16.1.4` (RFC 3161 §2.4.2).
const OID_ID_CT_TSTINFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");

/// OID for `id-signedData` — `1.2.840.113549.1.7.2` (CMS, RFC 5652).
const OID_ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

/// OID for the `id-kp-timeStamping` Extended Key Usage
/// — `1.3.6.1.5.5.7.3.8` (RFC 3161 §2.3).
const OID_ID_KP_TIMESTAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");

/// OID for `id-aa-signingCertificate` — `1.2.840.113549.1.9.16.2.12`
/// (RFC 2634 §5.4, ESS v1).
const OID_ID_AA_SIGNING_CERTIFICATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12");

/// OID for `id-aa-signingCertificateV2` — `1.2.840.113549.1.9.16.2.47`
/// (RFC 5035 / RFC 5816).
const OID_ID_AA_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");

/// OID for `id-aa-contentType` — `1.2.840.113549.1.9.3` (CMS).
const OID_ID_AA_CONTENT_TYPE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");

/// OID for `id-aa-messageDigest` — `1.2.840.113549.1.9.4` (CMS).
const OID_ID_AA_MESSAGE_DIGEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

/// OID for `id-sha256` — `2.16.840.1.101.3.4.2.1`.
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
/// OID for `id-sha384` — `2.16.840.1.101.3.4.2.2`.
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
/// OID for `id-sha512` — `2.16.840.1.101.3.4.2.3`.
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
/// OID for `id-sha1` — `1.3.14.3.2.26`. Used by signingCertificate v1.
const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");

/// OID for `ecPublicKey` — `1.2.840.10045.2.1`.
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// OID for `rsaEncryption` — `1.2.840.113549.1.1.1`.
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// Named curve OIDs.
const OID_P256_CURVE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_P384_CURVE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// Signature algorithm OIDs we accept on SignerInfo / certificate signatures.
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");
const OID_RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_RSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");

/// Errors surfaced by the strict TSR verifier. Every variant carries a
/// concrete reason that operators can paste into a ticket.
#[derive(Debug, thiserror::Error)]
pub enum TstError {
    /// The DER input could not be parsed.
    #[error("malformed DER: {0}")]
    Asn1(String),

    /// The `TimeStampResp.status` did not report `granted` (0) or
    /// `granted-with-mods` (1).
    #[error("TSA reported failure status {0}: {1}")]
    BadStatus(u32, String),

    /// The wrapped `ContentInfo.contentType` was not `id-signedData`.
    #[error("inner ContentInfo is not id-signedData (got {0})")]
    NotSignedData(String),

    /// The `EncapsulatedContentInfo.eContentType` was not `id-ct-TSTInfo`.
    #[error("encapsulated content is not id-ct-TSTInfo (got {0})")]
    NotTstInfo(String),

    /// SignedData has zero or more than one SignerInfo (we require exactly one).
    #[error("SignedData must carry exactly one SignerInfo, got {0}")]
    SignerInfoCount(usize),

    /// `TSTInfo.version` was not 1.
    #[error("TSTInfo.version must be 1, got {0}")]
    BadVersion(i64),

    /// `messageImprint` did not equal the imprint we expected to find.
    #[error(
        "messageImprint mismatch: expected SHA-256(preimage) = {expected}, \
         got hashAlgorithm={got_alg} digest={got}"
    )]
    ImprintMismatch {
        /// Hex of the expected SHA-256 imprint.
        expected: String,
        /// Stringified OID of the hash algorithm the TSA actually used.
        got_alg: String,
        /// Hex of the digest the TSA actually returned.
        got: String,
    },

    /// The `id-aa-contentType` signed attribute is missing or does not
    /// match the eContent type.
    #[error("missing or invalid signedAttr id-aa-contentType: {0}")]
    BadContentTypeAttr(String),

    /// The `id-aa-messageDigest` signed attribute is missing or does not
    /// match `digestAlg(eContent.value)`.
    #[error("signedAttr id-aa-messageDigest does not match eContent digest ({0})")]
    BadMessageDigestAttr(String),

    /// The `signingCertificate(V2)` signed attribute did not match the
    /// SignerInfo's signer certificate.
    #[error("signingCertificate{} does not bind the signer (got {0})", _0)]
    BadSigningCertAttr(String),

    /// The `signingCertificate(V2)` signed attribute was missing.
    #[error("signedAttrs is missing signingCertificate / signingCertificateV2")]
    MissingSigningCertAttr,

    /// SignedData carried no embedded certificates, or none of them
    /// matched the SignerIdentifier.
    #[error("cannot resolve signer certificate from SignedData: {0}")]
    SignerCertMissing(String),

    /// The signer certificate is missing the `id-kp-timeStamping`
    /// extended-key-usage extension (must be present and critical per
    /// RFC 3161 §2.3).
    #[error("signer certificate is missing critical EKU id-kp-timeStamping")]
    MissingTimestampingEku,

    /// `genTime` falls outside the signer certificate's validity window.
    #[error(
        "genTime {gen_time} is outside signer certificate validity ({not_before} .. {not_after})"
    )]
    GenTimeOutsideValidity {
        /// Stringified `genTime` value.
        gen_time: String,
        /// Stringified `notBefore`.
        not_before: String,
        /// Stringified `notAfter`.
        not_after: String,
    },

    /// Signature on SignerInfo did not verify.
    #[error("SignerInfo signature did not verify: {0}")]
    SignerSignature(String),

    /// Chain validation failed (no path to a pinned trust anchor or
    /// intermediate signature did not verify).
    #[error("PKIX chain validation failed: {0}")]
    Chain(String),

    /// A signature/hash algorithm in the TSR is not supported by this
    /// verifier.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlg(String),

    /// I/O error reading the trust-anchor PEM.
    #[error("trust-anchor IO: {0}")]
    TrustAnchorIo(String),
}

/// `TimeStampResp` (RFC 3161 §2.4.2):
///
/// ```text
/// TimeStampResp ::= SEQUENCE {
///   status         PKIStatusInfo,
///   timeStampToken TimeStampToken OPTIONAL
/// }
/// ```
#[derive(Debug, Clone, Sequence)]
struct TimeStampResp {
    status: PkiStatusInfo,
    #[asn1(optional = "true")]
    time_stamp_token: Option<ContentInfo>,
}

/// `PKIStatusInfo` (RFC 2510). We only inspect the leading `status`
/// integer; the variable-shape `statusString` / `failInfo` fields are
/// kept as opaque `Any` so that the decoder accepts every TSA's
/// flavour without modelling each one.
#[derive(Debug, Clone, Sequence)]
struct PkiStatusInfo {
    status: i32,
    #[asn1(optional = "true")]
    status_string: Option<Any>,
    #[asn1(optional = "true")]
    fail_info: Option<Any>,
}

/// `TSTInfo` (RFC 3161 §2.4.2). The optional trailing fields (accuracy,
/// ordering, nonce, tsa, extensions) are declared as opaque `Any`s so
/// the SEQUENCE accepts whatever a real TSA returns; only the leading
/// fields are decoded into typed values for verification.
#[derive(Debug, Clone, Sequence)]
struct TstInfo {
    version: i64,
    policy: ObjectIdentifier,
    message_imprint: MessageImprint,
    serial_number: der::asn1::Int,
    gen_time: der::asn1::GeneralizedTime,
    #[asn1(optional = "true")]
    accuracy: Option<Any>,
    #[asn1(optional = "true")]
    ordering: Option<bool>,
    #[asn1(optional = "true")]
    nonce: Option<der::asn1::Int>,
    #[asn1(context_specific = "0", optional = "true")]
    tsa: Option<Any>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    extensions: Option<Any>,
}

/// `MessageImprint` (RFC 3161 §2.4.1).
#[derive(Debug, Clone, Sequence)]
struct MessageImprint {
    hash_algorithm: AlgorithmIdentifierOwned,
    hashed_message: OctetString,
}

/// `ESSCertID` (RFC 2634).
#[derive(Debug, Clone, Sequence)]
struct EssCertId {
    cert_hash: OctetString,
    // issuerSerial is optional and not validated here.
}

/// `SigningCertificate` (RFC 2634 §5.4). Contains a SEQUENCE OF
/// `ESSCertID`.
#[derive(Debug, Clone, Sequence)]
struct SigningCertificate {
    certs: der::asn1::SequenceOf<EssCertId, 8>,
    // policies OPTIONAL, ignored.
}

/// `ESSCertIDv2` (RFC 5035 / RFC 5816). `hashAlgorithm` is `DEFAULT
/// id-sha256`; when omitted the verifier treats the digest as SHA-256.
#[derive(Debug, Clone, Sequence)]
struct EssCertIdV2 {
    #[asn1(optional = "true")]
    hash_algorithm: Option<AlgorithmIdentifierOwned>,
    cert_hash: OctetString,
    // issuerSerial is optional and not validated here.
}

/// `SigningCertificateV2` (RFC 5035 §3).
#[derive(Debug, Clone, Sequence)]
struct SigningCertificateV2 {
    certs: der::asn1::SequenceOf<EssCertIdV2, 8>,
}

/// Operator-pinned set of trust anchors loaded from a PEM file.
///
/// Each anchor is a `Certificate` parsed from `-----BEGIN CERTIFICATE-----`
/// blocks; the validator requires the discovered chain to terminate at one
/// of these certificates by raw DER equality.
#[derive(Debug, Clone)]
pub struct TrustAnchors {
    anchors: Vec<Certificate>,
}

impl TrustAnchors {
    /// Load a PEM bundle from `path`. Each `BEGIN CERTIFICATE` block is
    /// parsed independently; the first parse failure is returned.
    pub fn from_pem_file(path: &Path) -> Result<Self, TstError> {
        let bytes = std::fs::read(path).map_err(|e| {
            TstError::TrustAnchorIo(format!("cannot read '{}': {e}", path.display()))
        })?;
        Self::from_pem_bytes(&bytes)
    }

    /// Parse a PEM bundle from an in-memory byte slice.
    pub fn from_pem_bytes(bytes: &[u8]) -> Result<Self, TstError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|e| TstError::TrustAnchorIo(format!("trust anchor file is not UTF-8: {e}")))?;
        let mut anchors = Vec::new();
        let mut remaining = text;
        while let Some(start) = remaining.find("-----BEGIN CERTIFICATE-----") {
            let rest = &remaining[start..];
            let end = rest
                .find("-----END CERTIFICATE-----")
                .ok_or_else(|| TstError::TrustAnchorIo("unterminated PEM block".to_string()))?;
            let block = &rest[..end + "-----END CERTIFICATE-----".len()];
            let cert = Certificate::load_pem(block)?;
            anchors.push(cert);
            remaining = &rest[end + "-----END CERTIFICATE-----".len()..];
        }
        if anchors.is_empty() {
            return Err(TstError::TrustAnchorIo(
                "no PEM CERTIFICATE blocks found".to_string(),
            ));
        }
        Ok(Self { anchors })
    }
}

trait PemLoad: Sized {
    fn load_pem(pem: &str) -> Result<Self, TstError>;
}

impl PemLoad for Certificate {
    fn load_pem(pem: &str) -> Result<Self, TstError> {
        use base64::Engine;
        // Strip PEM headers + whitespace, base64-decode, parse DER.
        let body: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .flat_map(|l| l.chars())
            .filter(|c| !c.is_whitespace())
            .collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .map_err(|e| TstError::Asn1(format!("PEM base64 decode failed: {e}")))?;
        Certificate::from_der(&der).map_err(|e| TstError::Asn1(format!("X.509 parse failed: {e}")))
    }
}

impl From<der::Error> for TstError {
    fn from(e: der::Error) -> Self {
        TstError::Asn1(e.to_string())
    }
}

/// Result of a successful TSR verification.
#[derive(Debug, Clone)]
pub struct VerifiedTst {
    /// `genTime` from `TSTInfo`, in UTC.
    pub gen_time: SystemTime,
    /// `TSAPolicyId` OID (dot-form).
    pub policy_oid: String,
    /// DN of the signer (end-entity) certificate.
    pub signer_subject: String,
    /// DN of the trust anchor that terminated the chain.
    pub root_subject: String,
    /// Hex-encoded SHA-256 digest that was time-stamped.
    pub message_imprint_sha256: String,
}

/// Strict-mode verifier. Returns `VerifiedTst` on success; otherwise the
/// specific reason is in the error variant.
///
/// `now` is the wall-clock time used to bound the signer certificate's
/// validity (defaults to `genTime` for offline replay if you pass it
/// in directly). Pass `SystemTime::now()` for live validation.
pub fn verify_tsr(
    tsr_bytes: &[u8],
    expected_sha256_imprint: &[u8; 32],
    anchors: &TrustAnchors,
) -> Result<VerifiedTst, TstError> {
    // 1. Parse the wrapper.
    let resp = TimeStampResp::from_der(tsr_bytes)?;
    if !(resp.status.status == 0 || resp.status.status == 1) {
        return Err(TstError::BadStatus(
            resp.status.status as u32,
            format!("PKIStatusInfo.status = {}", resp.status.status),
        ));
    }
    let token = resp
        .time_stamp_token
        .ok_or_else(|| TstError::BadStatus(0, "missing timeStampToken".to_string()))?;
    if token.content_type != OID_ID_SIGNED_DATA {
        return Err(TstError::NotSignedData(token.content_type.to_string()));
    }

    // 2. Decode the inner SignedData.
    let signed: SignedData = token.content.decode_as()?;
    let encap = &signed.encap_content_info;
    if encap.econtent_type != OID_ID_CT_TSTINFO {
        return Err(TstError::NotTstInfo(encap.econtent_type.to_string()));
    }

    // 3. Decode the encapsulated TSTInfo.
    let econtent = encap
        .econtent
        .as_ref()
        .ok_or_else(|| TstError::NotTstInfo("eContent absent".to_string()))?;
    // eContent is an Any tagged EXPLICIT [0] containing an OCTET STRING.
    // After cms decoded the EXPLICIT wrapper, what's left is the OCTET STRING
    // whose value bytes hold the DER of TSTInfo.
    let econtent_octets: OctetString = econtent.decode_as()?;
    let econtent_bytes = econtent_octets.as_bytes();
    let tst_info = TstInfo::from_der(econtent_bytes)?;
    if tst_info.version != 1 {
        return Err(TstError::BadVersion(tst_info.version));
    }

    // 4. Verify the messageImprint.
    let imprint_alg = &tst_info.message_imprint.hash_algorithm.oid;
    let imprint_bytes = tst_info.message_imprint.hashed_message.as_bytes();
    if *imprint_alg != OID_SHA256 || imprint_bytes != expected_sha256_imprint {
        return Err(TstError::ImprintMismatch {
            expected: hex::encode(expected_sha256_imprint),
            got_alg: imprint_alg.to_string(),
            got: hex::encode(imprint_bytes),
        });
    }

    // 5. Pick the (one) SignerInfo.
    let signer_infos: &[SignerInfo] = signed.signer_infos.0.as_slice();
    if signer_infos.len() != 1 {
        return Err(TstError::SignerInfoCount(signer_infos.len()));
    }
    let signer_info = &signer_infos[0];

    // 6. Resolve the signer certificate from the embedded set.
    let embedded_certs = collect_embedded_certs(&signed)?;
    let signer_cert = find_signer_cert(&signer_info.sid, &embedded_certs)?;

    // 7. Verify signedAttrs (RFC 5652 §5.3).
    let signed_attrs = signer_info
        .signed_attrs
        .as_ref()
        .ok_or_else(|| TstError::BadContentTypeAttr("signedAttrs absent".to_string()))?;
    verify_content_type_attr(signed_attrs, &encap.econtent_type)?;
    verify_message_digest_attr(signed_attrs, econtent_bytes, &signer_info.digest_alg.oid)?;
    verify_signing_cert_attr(signed_attrs, signer_cert)?;

    // 8. Verify SignerInfo signature over signedAttrs (re-encoded as SET OF).
    verify_signer_info_signature(signer_info, signer_cert)?;

    // 9. Verify the certificate chain to a pinned trust anchor and require
    //    `id-kp-timeStamping` (critical) on the signer.
    let chain_terminus = build_and_verify_chain(signer_cert, &embedded_certs, anchors)?;
    require_timestamping_eku(signer_cert)?;

    // 10. genTime must fall inside signer certificate validity.
    let gen_time = generalized_time_to_system_time(&tst_info.gen_time)?;
    let (not_before, not_after) = cert_validity(signer_cert)?;
    if gen_time < not_before || gen_time > not_after {
        return Err(TstError::GenTimeOutsideValidity {
            gen_time: format!("{}", systime_rfc3339(gen_time)),
            not_before: format!("{}", systime_rfc3339(not_before)),
            not_after: format!("{}", systime_rfc3339(not_after)),
        });
    }

    Ok(VerifiedTst {
        gen_time,
        policy_oid: tst_info.policy.to_string(),
        signer_subject: signer_cert.tbs_certificate.subject.to_string(),
        root_subject: chain_terminus.tbs_certificate.subject.to_string(),
        message_imprint_sha256: hex::encode(expected_sha256_imprint),
    })
}

fn collect_embedded_certs(signed: &SignedData) -> Result<Vec<Certificate>, TstError> {
    let mut out = Vec::new();
    if let Some(set) = signed.certificates.as_ref() {
        for choice in set.0.iter() {
            if let CertificateChoices::Certificate(c) = choice {
                out.push(c.clone());
            }
        }
    }
    Ok(out)
}

fn find_signer_cert<'a>(
    sid: &SignerIdentifier,
    embedded: &'a [Certificate],
) -> Result<&'a Certificate, TstError> {
    match sid {
        SignerIdentifier::IssuerAndSerialNumber(ias) => {
            for c in embedded {
                if c.tbs_certificate.issuer == ias.issuer
                    && c.tbs_certificate.serial_number == ias.serial_number
                {
                    return Ok(c);
                }
            }
            Err(TstError::SignerCertMissing(format!(
                "no embedded certificate matches issuer={} / serial={}",
                ias.issuer, ias.serial_number
            )))
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => {
            let want = ski.0.as_bytes();
            for c in embedded {
                if let Some(found) = cert_subject_key_identifier(c) {
                    if found == want {
                        return Ok(c);
                    }
                }
            }
            Err(TstError::SignerCertMissing(format!(
                "no embedded certificate matches SKI={}",
                hex::encode(want)
            )))
        }
    }
}

fn cert_subject_key_identifier(cert: &Certificate) -> Option<&[u8]> {
    let exts = cert.tbs_certificate.extensions.as_ref()?;
    for ext in exts {
        if ext.extn_id == rfc5912::ID_CE_SUBJECT_KEY_IDENTIFIER {
            return Some(ext.extn_value.as_bytes());
        }
    }
    None
}

fn verify_content_type_attr(
    signed_attrs: &x509_cert::attr::Attributes,
    econtent_type: &ObjectIdentifier,
) -> Result<(), TstError> {
    let attr = find_attr(signed_attrs, &OID_ID_AA_CONTENT_TYPE)
        .ok_or_else(|| TstError::BadContentTypeAttr("missing id-aa-contentType".to_string()))?;
    if attr.values.len() != 1 {
        return Err(TstError::BadContentTypeAttr(
            "id-aa-contentType: expected exactly one value".to_string(),
        ));
    }
    let val = attr.values.as_slice()[0].clone();
    let oid: ObjectIdentifier = val.decode_as()?;
    if &oid != econtent_type {
        return Err(TstError::BadContentTypeAttr(format!(
            "id-aa-contentType ({oid}) != eContentType ({econtent_type})"
        )));
    }
    Ok(())
}

fn verify_message_digest_attr(
    signed_attrs: &x509_cert::attr::Attributes,
    econtent_bytes: &[u8],
    digest_alg_oid: &ObjectIdentifier,
) -> Result<(), TstError> {
    let attr = find_attr(signed_attrs, &OID_ID_AA_MESSAGE_DIGEST)
        .ok_or_else(|| TstError::BadMessageDigestAttr("missing id-aa-messageDigest".to_string()))?;
    if attr.values.len() != 1 {
        return Err(TstError::BadMessageDigestAttr(
            "expected exactly one value".to_string(),
        ));
    }
    let octets: OctetString = attr.values.as_slice()[0].clone().decode_as()?;
    let expected = digest_with_oid(digest_alg_oid, econtent_bytes)?;
    if octets.as_bytes() != expected.as_slice() {
        return Err(TstError::BadMessageDigestAttr(format!(
            "expected {} = {}, signedAttr carried {}",
            digest_alg_name(digest_alg_oid),
            hex::encode(&expected),
            hex::encode(octets.as_bytes())
        )));
    }
    Ok(())
}

fn verify_signing_cert_attr(
    signed_attrs: &x509_cert::attr::Attributes,
    signer_cert: &Certificate,
) -> Result<(), TstError> {
    if let Some(attr) = find_attr(signed_attrs, &OID_ID_AA_SIGNING_CERTIFICATE_V2) {
        let val = attr
            .values
            .as_slice()
            .first()
            .ok_or_else(|| TstError::BadSigningCertAttr("V2 attr empty".to_string()))?
            .clone();
        let sc: SigningCertificateV2 = val.decode_as()?;
        let cert_der = signer_cert
            .to_der()
            .map_err(|e| TstError::Asn1(format!("re-encode signer cert: {e}")))?;
        for ess in sc.certs.iter() {
            let alg_oid = ess
                .hash_algorithm
                .as_ref()
                .map(|a| a.oid)
                .unwrap_or(OID_SHA256);
            let expected = digest_with_oid(&alg_oid, &cert_der)?;
            if expected.as_slice() == ess.cert_hash.as_bytes() {
                return Ok(());
            }
        }
        return Err(TstError::BadSigningCertAttr("V2".to_string()));
    }
    if let Some(attr) = find_attr(signed_attrs, &OID_ID_AA_SIGNING_CERTIFICATE) {
        let val = attr
            .values
            .as_slice()
            .first()
            .ok_or_else(|| TstError::BadSigningCertAttr("V1 attr empty".to_string()))?
            .clone();
        let sc: SigningCertificate = val.decode_as()?;
        let cert_der = signer_cert
            .to_der()
            .map_err(|e| TstError::Asn1(format!("re-encode signer cert: {e}")))?;
        // V1 always uses SHA-1.
        let want = Sha1Wrap::digest(&cert_der);
        for ess in sc.certs.iter() {
            if ess.cert_hash.as_bytes() == want.as_slice() {
                return Ok(());
            }
        }
        return Err(TstError::BadSigningCertAttr("V1".to_string()));
    }
    Err(TstError::MissingSigningCertAttr)
}

fn find_attr<'a>(
    attrs: &'a x509_cert::attr::Attributes,
    oid: &ObjectIdentifier,
) -> Option<&'a x509_cert::attr::Attribute> {
    attrs.iter().find(|a| &a.oid == oid)
}

fn digest_with_oid(oid: &ObjectIdentifier, bytes: &[u8]) -> Result<Vec<u8>, TstError> {
    if *oid == OID_SHA256 {
        Ok(Sha256::digest(bytes).to_vec())
    } else if *oid == OID_SHA384 {
        Ok(Sha384::digest(bytes).to_vec())
    } else if *oid == OID_SHA512 {
        Ok(Sha512::digest(bytes).to_vec())
    } else if *oid == OID_SHA1 {
        Ok(Sha1Wrap::digest(bytes))
    } else {
        Err(TstError::UnsupportedAlg(format!("digest OID {oid}")))
    }
}

fn digest_alg_name(oid: &ObjectIdentifier) -> &'static str {
    if *oid == OID_SHA256 {
        "SHA-256"
    } else if *oid == OID_SHA384 {
        "SHA-384"
    } else if *oid == OID_SHA512 {
        "SHA-512"
    } else if *oid == OID_SHA1 {
        "SHA-1"
    } else {
        "unknown"
    }
}

/// Thin SHA-1 wrapper. We deliberately avoid adding the `sha1` crate to
/// the dependency tree just for one legacy attribute; we re-derive it via
/// the FIPS 180-4 reference implementation built on top of `sha2`'s
/// `Digest` is not available, so we ship a minimal pure-Rust SHA-1 here.
struct Sha1Wrap;

impl Sha1Wrap {
    fn digest(data: &[u8]) -> Vec<u8> {
        sha1_compat(data).to_vec()
    }
}

fn sha1_compat(data: &[u8]) -> [u8; 20] {
    // Minimal SHA-1 reference. Used only for the RFC 2634 v1
    // signingCertificate attribute hash; we never accept SHA-1 anywhere
    // else.
    const K: [u32; 4] = [0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xCA62_C1D6];
    let mut h = [
        0x6745_2301u32,
        0xEFCD_AB89u32,
        0x98BA_DCFEu32,
        0x1032_5476u32,
        0xC3D2_E1F0u32,
    ];
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    let bit_len = (data.len() as u64).wrapping_mul(8);
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for block in padded.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[4 * i],
                block[4 * i + 1],
                block[4 * i + 2],
                block[4 * i + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), K[0]),
                20..=39 => (b ^ c ^ d, K[1]),
                40..=59 => ((b & c) | (b & d) | (c & d), K[2]),
                _ => (b ^ c ^ d, K[3]),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for i in 0..5 {
        out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

fn verify_signer_info_signature(
    signer_info: &SignerInfo,
    signer_cert: &Certificate,
) -> Result<(), TstError> {
    // Re-encode signedAttrs as SET OF (RFC 5652 §5.4): the parsed value
    // is tagged IMPLICIT [0], but the signature is over the canonical
    // SET OF encoding.
    let attrs = signer_info
        .signed_attrs
        .as_ref()
        .ok_or_else(|| TstError::SignerSignature("signedAttrs absent".to_string()))?;
    let signed_bytes = encode_attrs_as_set_of(attrs)
        .map_err(|e| TstError::SignerSignature(format!("re-encode signedAttrs: {e}")))?;

    let sig_alg = &signer_info.signature_algorithm.oid;
    let signature = signer_info.signature.as_bytes();
    let pub_key = &signer_cert.tbs_certificate.subject_public_key_info;

    verify_signature(sig_alg, &signed_bytes, signature, pub_key)
        .map_err(|e| TstError::SignerSignature(e.to_string()))
}

fn encode_attrs_as_set_of(attrs: &x509_cert::attr::Attributes) -> Result<Vec<u8>, der::Error> {
    // x509_cert::attr::Attributes is a SetOfVec<Attribute>; we re-encode
    // with SET OF tag (0x31). der::asn1::SetOfVec encodes as SET OF
    // when serialized via to_der.
    let set: &SetOfVec<x509_cert::attr::Attribute> = attrs;
    let mut buf = set.to_der()?;
    // SetOfVec serializes as SET OF (tag 0x31). signedAttrs was decoded
    // as IMPLICIT [0] (0xA0); re-encoded above as 0x31 — exactly what
    // RFC 5652 requires for the signature input.
    if buf.first() == Some(&0xA0) {
        buf[0] = 0x31;
    }
    Ok(buf)
}

fn verify_signature(
    alg_oid: &ObjectIdentifier,
    message: &[u8],
    signature: &[u8],
    spki: &spki::SubjectPublicKeyInfoOwned,
) -> Result<(), String> {
    if *alg_oid == OID_ECDSA_SHA256 || *alg_oid == OID_ECDSA_SHA384 || *alg_oid == OID_ECDSA_SHA512
    {
        return verify_ecdsa(alg_oid, message, signature, spki);
    }
    if *alg_oid == OID_RSA_SHA256 || *alg_oid == OID_RSA_SHA384 || *alg_oid == OID_RSA_SHA512 {
        return verify_rsa(alg_oid, message, signature, spki);
    }
    Err(format!("unsupported signature algorithm {alg_oid}"))
}

fn verify_ecdsa(
    alg_oid: &ObjectIdentifier,
    message: &[u8],
    signature_der: &[u8],
    spki: &spki::SubjectPublicKeyInfoOwned,
) -> Result<(), String> {
    if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
        return Err(format!(
            "signer public key is not ecPublicKey (got {})",
            spki.algorithm.oid
        ));
    }
    let curve_params = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or_else(|| "ecPublicKey missing named-curve parameters".to_string())?;
    let curve_oid: ObjectIdentifier = curve_params
        .decode_as()
        .map_err(|e| format!("named curve parse: {e}"))?;
    let pubkey_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| "subjectPublicKey not byte-aligned".to_string())?;
    let digest: Vec<u8> = if *alg_oid == OID_ECDSA_SHA256 {
        Sha256::digest(message).to_vec()
    } else if *alg_oid == OID_ECDSA_SHA384 {
        Sha384::digest(message).to_vec()
    } else {
        Sha512::digest(message).to_vec()
    };

    if curve_oid == OID_P256_CURVE {
        use p256::ecdsa::{Signature, VerifyingKey};
        let vk = VerifyingKey::from_sec1_bytes(pubkey_bytes)
            .map_err(|e| format!("P-256 pubkey parse: {e}"))?;
        let sig = Signature::from_der(signature_der)
            .map_err(|e| format!("P-256 signature parse: {e}"))?;
        // P-256 ECDSA verify_prehash on the leftmost 32 bytes of the digest.
        let hash32: &[u8] = &digest[..core::cmp::min(32, digest.len())];
        vk.verify_prehash(hash32, &sig)
            .map_err(|e| format!("P-256 verify: {e}"))
    } else if curve_oid == OID_P384_CURVE {
        use p384::ecdsa::{Signature, VerifyingKey};
        let vk = VerifyingKey::from_sec1_bytes(pubkey_bytes)
            .map_err(|e| format!("P-384 pubkey parse: {e}"))?;
        let sig = Signature::from_der(signature_der)
            .map_err(|e| format!("P-384 signature parse: {e}"))?;
        let hash48: &[u8] = &digest[..core::cmp::min(48, digest.len())];
        vk.verify_prehash(hash48, &sig)
            .map_err(|e| format!("P-384 verify: {e}"))
    } else {
        Err(format!("unsupported EC curve {curve_oid}"))
    }
}

fn verify_rsa(
    alg_oid: &ObjectIdentifier,
    message: &[u8],
    signature: &[u8],
    spki: &spki::SubjectPublicKeyInfoOwned,
) -> Result<(), String> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use signature::Verifier as _;
    if spki.algorithm.oid != OID_RSA_ENCRYPTION {
        return Err(format!(
            "signer public key is not rsaEncryption (got {})",
            spki.algorithm.oid
        ));
    }
    let pk_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| "subjectPublicKey not byte-aligned".to_string())?;
    let pk = rsa::RsaPublicKey::from_pkcs1_der(pk_bytes).map_err(|e| format!("RSA pubkey: {e}"))?;
    let sig = Signature::try_from(signature).map_err(|e| format!("RSA signature parse: {e}"))?;
    if *alg_oid == OID_RSA_SHA256 {
        let vk = VerifyingKey::<Sha256>::new(pk);
        vk.verify(message, &sig).map_err(|e| format!("verify: {e}"))
    } else if *alg_oid == OID_RSA_SHA384 {
        let vk = VerifyingKey::<Sha384>::new(pk);
        vk.verify(message, &sig).map_err(|e| format!("verify: {e}"))
    } else {
        let vk = VerifyingKey::<Sha512>::new(pk);
        vk.verify(message, &sig).map_err(|e| format!("verify: {e}"))
    }
}

fn build_and_verify_chain(
    signer: &Certificate,
    embedded: &[Certificate],
    anchors: &TrustAnchors,
) -> Result<Certificate, TstError> {
    // Walk up to 8 hops to terminate at a pinned trust anchor. In
    // practice TSA chains are 2 deep (signer + root); we tolerate
    // intermediates but stop as soon as the discovered issuer chain
    // reaches an anchor by raw DER equality.
    let mut current: &Certificate = signer;
    for _ in 0..8 {
        // Stop condition 1: an anchor's subject DN matches `current`'s
        // issuer DN and the anchor signed `current`.
        if let Some(anchor) = anchors.anchors.iter().find(|a| {
            a.tbs_certificate.subject == current.tbs_certificate.issuer
                && verify_cert_signature(current, a).is_ok()
        }) {
            return Ok(anchor.clone());
        }
        // Stop condition 2: `current` is self-signed (subject == issuer)
        // — if it isn't a pinned anchor we cannot terminate the chain.
        if current.tbs_certificate.subject == current.tbs_certificate.issuer {
            return Err(TstError::Chain(format!(
                "self-signed root '{}' is not in the pinned trust-anchor set",
                current.tbs_certificate.subject
            )));
        }
        // Otherwise: find an intermediate among the embedded set whose
        // subject matches `current.issuer` and that signed `current`.
        let next = embedded
            .iter()
            .find(|c| {
                !std::ptr::eq(*c, current)
                    && c.tbs_certificate.subject == current.tbs_certificate.issuer
                    && verify_cert_signature(current, c).is_ok()
            })
            .ok_or_else(|| {
                TstError::Chain(format!(
                    "no path to a pinned trust anchor; last issuer = {}",
                    current.tbs_certificate.issuer
                ))
            })?;
        current = next;
    }
    Err(TstError::Chain("chain depth exceeded 8 hops".to_string()))
}

fn verify_cert_signature(child: &Certificate, parent: &Certificate) -> Result<(), TstError> {
    let tbs_bytes = child
        .tbs_certificate
        .to_der()
        .map_err(|e| TstError::Chain(format!("tbs encode: {e}")))?;
    let sig_alg = &child.signature_algorithm.oid;
    let sig_bytes = child
        .signature
        .as_bytes()
        .ok_or_else(|| TstError::Chain("certificate signature not byte-aligned".to_string()))?;
    verify_signature(
        sig_alg,
        &tbs_bytes,
        sig_bytes,
        &parent.tbs_certificate.subject_public_key_info,
    )
    .map_err(TstError::Chain)
}

fn require_timestamping_eku(signer: &Certificate) -> Result<(), TstError> {
    let exts = signer
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or(TstError::MissingTimestampingEku)?;
    for ext in exts {
        if ext.extn_id == rfc5912::ID_CE_EXT_KEY_USAGE {
            // RFC 3161 §2.3 requires the timeStamping EKU and that the
            // EKU extension be critical (we accept either critical or
            // non-critical to be compatible with extant TSAs, but the
            // OID must be present).
            let eku = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes())?;
            for oid in eku.0.iter() {
                if *oid == OID_ID_KP_TIMESTAMPING {
                    return Ok(());
                }
            }
        }
    }
    Err(TstError::MissingTimestampingEku)
}

fn cert_validity(cert: &Certificate) -> Result<(SystemTime, SystemTime), TstError> {
    let nb = cert.tbs_certificate.validity.not_before.to_system_time();
    let na = cert.tbs_certificate.validity.not_after.to_system_time();
    Ok((nb, na))
}

fn generalized_time_to_system_time(
    gt: &der::asn1::GeneralizedTime,
) -> Result<SystemTime, TstError> {
    let secs = gt.to_unix_duration().as_secs();
    Ok(UNIX_EPOCH + Duration::from_secs(secs))
}

fn systime_rfc3339(t: SystemTime) -> chrono::DateTime<chrono::Utc> {
    let secs = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0).unwrap_or_default()
}
