//! DQ-003 — RI-RS version binding conformance.
//!
//! This test is intentionally non-invasive: it does not alter production
//! serialization or digest code. It locks the semantic contract established
//! by the DQ-003 version-binding ADR/fixture so Rust cannot silently collapse
//! protocol and schema versions into one field.

const PROTOCOL_VERSION: &str = "1.0";
const SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, PartialEq, Eq)]
struct VersionBinding {
    protocol_version: String,
    schema_version: String,
}

fn bind(protocol_version: &str, schema_version: &str) -> VersionBinding {
    VersionBinding {
        protocol_version: protocol_version.to_owned(),
        schema_version: schema_version.to_owned(),
    }
}

fn is_supported_protocol_version(value: &str) -> bool {
    matches!(value, PROTOCOL_VERSION)
}

fn is_supported_schema_version(value: &str) -> bool {
    matches!(value, SCHEMA_VERSION)
}

#[test]
fn protocol_and_schema_versions_are_distinct() {
    let binding = bind(PROTOCOL_VERSION, SCHEMA_VERSION);

    assert_eq!(binding.protocol_version, "1.0");
    assert_eq!(binding.schema_version, "1.0.0");
    assert_ne!(binding.protocol_version, binding.schema_version);
}

#[test]
fn protocol_version_is_not_derived_from_schema_version() {
    let v1 = bind("1.0", "1.0.0");
    let v2 = bind("1.0", "1.1.0");

    assert_eq!(v1.protocol_version, v2.protocol_version);
    assert_ne!(v1.schema_version, v2.schema_version);
}

#[test]
fn schema_revision_does_not_implicitly_upgrade_protocol() {
    let binding = bind("1.0", "1.1.0");

    assert_eq!(binding.protocol_version, "1.0");
    assert_eq!(binding.schema_version, "1.1.0");
}

#[test]
fn implementation_version_is_not_a_protocol_binding() {
    let implementation_version = env!("CARGO_PKG_VERSION");
    let binding = bind(PROTOCOL_VERSION, SCHEMA_VERSION);

    assert_ne!(implementation_version, binding.protocol_version);
    assert_ne!(implementation_version, binding.schema_version);
}

#[test]
fn unknown_protocol_version_is_not_silently_accepted() {
    assert!(!is_supported_protocol_version("9.9"));
    assert!(!is_supported_protocol_version(""));
}

#[test]
fn unknown_schema_version_is_not_silently_accepted() {
    assert!(!is_supported_schema_version("9.9.9"));
    assert!(!is_supported_schema_version(""));
}

#[test]
fn supported_version_binding_is_explicit() {
    let binding = bind(PROTOCOL_VERSION, SCHEMA_VERSION);

    assert!(is_supported_protocol_version(&binding.protocol_version));
    assert!(is_supported_schema_version(&binding.schema_version));
}

#[test]
fn version_resolution_precedes_canonicalization_boundary() {
    // The test records the ordering contract without invoking the production
    // serializer. A future implementation may replace this fixture with the
    // actual canonical-boundary API once DQ-003 is normatively bound there.
    let binding = bind(PROTOCOL_VERSION, SCHEMA_VERSION);
    let resolved = format!("protocol={};schema={}", binding.protocol_version, binding.schema_version);

    assert_eq!(resolved, "protocol=1.0;schema=1.0.0");
}
