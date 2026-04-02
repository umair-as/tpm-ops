use anyhow::{Context, Result};
use log::info;

use tss_esapi::{
    handles::KeyHandle,
    interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy},
    structures::{EccParameter, EccSignature, MaxBuffer, Public, PublicKeyRsa, RsaSignature, Signature},
    Context as TpmContext,
};

use crate::tpm::{parse_handle, persistent_to_esys};

/// Verify a signature produced by `tpm-ops sign --key`.
///
/// sig_hex encoding:
///   RSA: raw PKCS#1 signature bytes as hex
///   ECC: R||S concatenated (32 bytes each = 64 bytes / 128 hex chars for P-256)
pub(crate) fn cmd_verify(
    context: &mut TpmContext,
    data: &str,
    handle_str: &str,
    sig_hex: &str,
) -> Result<()> {
    let handle_val = parse_handle(handle_str)?;
    let obj_handle = persistent_to_esys(context, handle_val)?;
    let key_handle = KeyHandle::from(obj_handle);

    let (public, _, _) = context
        .read_public(key_handle)
        .context("Failed to read public area")?;

    let is_ecc = matches!(public, Public::Ecc { .. });

    // Hash the data identically to how sign.rs does it.
    let data_bytes = data.as_bytes();
    let buffer = MaxBuffer::try_from(data_bytes).context("Data too large")?;
    let (digest, _) = context
        .hash(buffer, HashingAlgorithm::Sha256, Hierarchy::Null)
        .context("Failed to hash data")?;

    let sig_bytes = hex::decode(sig_hex.trim()).context("Invalid signature hex")?;

    let signature = if is_ecc {
        if sig_bytes.len() != 64 {
            anyhow::bail!(
                "ECC signature must be R||S (64 bytes = 128 hex chars), got {} bytes",
                sig_bytes.len()
            );
        }
        let r = EccParameter::try_from(sig_bytes[..32].to_vec()).context("Invalid R component")?;
        let s = EccParameter::try_from(sig_bytes[32..].to_vec()).context("Invalid S component")?;
        let sig_ecc = EccSignature::create(HashingAlgorithm::Sha256, r, s)
            .context("Failed to build ECC signature struct")?;
        Signature::EcDsa(sig_ecc)
    } else {
        let rsa_bytes =
            PublicKeyRsa::try_from(sig_bytes).context("Invalid RSA signature bytes")?;
        let sig_rsa = RsaSignature::create(HashingAlgorithm::Sha256, rsa_bytes)
            .context("Failed to build RSA signature struct")?;
        Signature::RsaSsa(sig_rsa)
    };

    info!(
        "Verifying {} signature against key 0x{:08X}...",
        if is_ecc { "ECC" } else { "RSA" },
        handle_val
    );

    match context.verify_signature(key_handle, digest, signature) {
        Ok(_) => {
            println!("Data: {}", data);
            println!(
                "Key: 0x{:08X} ({})",
                handle_val,
                if is_ecc { "ECC" } else { "RSA" }
            );
            println!("\nSignature VALID [OK]");
            Ok(())
        }
        Err(e) => {
            println!("Data: {}", data);
            println!(
                "Key: 0x{:08X} ({})",
                handle_val,
                if is_ecc { "ECC" } else { "RSA" }
            );
            println!("\nSignature INVALID");
            Err(anyhow::anyhow!("Verification failed: {}", e))
        }
    }
}
