//! `aura-sign-policy` — small utility to generate / use Ed25519 keys and
//! sign YAML policy files.
//!
//! Sub-commands:
//!
//! * `keygen --out policies/aura.key` — generate a fresh keypair (writes the
//!   secret key as `aura.key` and the public key as `aura.key.pub`, both
//!   hex-encoded). The public key is also appended to `trusted_signers.json`
//!   under the supplied signer ID.
//! * `sign --key <secret.key> --signer <id> <policy.yaml>` — sign one or more
//!   policy YAML files in place. Writes `<policy>.sig` (hex Ed25519) and
//!   `<policy>.signer` (signer ID).

#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde_json::{json, Map, Value};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(name = "aura-sign-policy", version = env!("CARGO_PKG_VERSION"))]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Generate a fresh Ed25519 keypair and register the public key as trusted.
    Keygen {
        /// Path to write the secret key (hex).
        #[arg(long, default_value = "policies/aura.key")]
        out: PathBuf,
        /// Signer ID under which to register the public key.
        #[arg(long, default_value = "aura-engineering")]
        signer: String,
        /// Trusted-signers JSON file to update.
        #[arg(long, default_value = "policies/trusted_signers.json")]
        trusted_signers: PathBuf,
    },
    /// Sign one or more policy YAML files in place.
    Sign {
        /// Path to the secret key (hex-encoded 32 bytes).
        #[arg(long, default_value = "policies/aura.key")]
        key: PathBuf,
        /// Signer ID to record alongside the signature.
        #[arg(long, default_value = "aura-engineering")]
        signer: String,
        /// One or more policy YAML files to sign.
        files: Vec<PathBuf>,
    },
}

fn main() -> ExitCode {
    match Args::parse().cmd {
        Cmd::Keygen {
            out,
            signer,
            trusted_signers,
        } => match keygen(out, signer, trusted_signers) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        },
        Cmd::Sign { key, signer, files } => match sign(key, signer, files) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        },
    }
}

fn keygen(out: PathBuf, signer: String, trusted_signers: PathBuf) -> anyhow::Result<()> {
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    let secret_hex = hex::encode(signing_key.to_bytes());
    let public_hex = hex::encode(verifying_key.to_bytes());

    std::fs::write(&out, format!("{secret_hex}\n"))?;
    std::fs::write(out.with_extension("key.pub"), format!("{public_hex}\n"))?;

    let mut current: Map<String, Value> = if trusted_signers.exists() {
        let raw = std::fs::read_to_string(&trusted_signers)?;
        serde_json::from_str(&raw).unwrap_or_default()
    } else {
        Map::new()
    };
    current.insert(signer.clone(), Value::String(public_hex.clone()));
    if let Some(parent) = trusted_signers.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        &trusted_signers,
        serde_json::to_string_pretty(&Value::Object(current))?,
    )?;

    println!(
        "{}",
        json!({
            "signer": signer,
            "secret_key_path": out.display().to_string(),
            "public_key_hex": public_hex,
            "trusted_signers_path": trusted_signers.display().to_string(),
        })
    );
    Ok(())
}

fn sign(key_path: PathBuf, signer: String, files: Vec<PathBuf>) -> anyhow::Result<()> {
    let secret_hex = std::fs::read_to_string(&key_path)?.trim().to_string();
    let secret_bytes = hex::decode(secret_hex)?;
    let signing_key = SigningKey::from_bytes(
        secret_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("secret key must be 32 bytes"))?,
    );

    for file in files {
        let bytes = std::fs::read(&file)?;
        let signature = signing_key.sign(&bytes);
        let sig_path = file.with_extension(format!(
            "{}.sig",
            file.extension().and_then(|s| s.to_str()).unwrap_or("yaml")
        ));
        let signer_path = file.with_extension(format!(
            "{}.signer",
            file.extension().and_then(|s| s.to_str()).unwrap_or("yaml")
        ));
        std::fs::write(
            &sig_path,
            format!("{}\n", hex::encode(signature.to_bytes())),
        )?;
        std::fs::write(&signer_path, format!("{signer}\n"))?;
        println!(
            "signed: {} -> {} ({})",
            file.display(),
            sig_path.display(),
            signer_path.display()
        );
    }
    Ok(())
}
