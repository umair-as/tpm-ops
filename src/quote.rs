use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result};
use log::info;

use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
        session_handles::AuthSession,
    },
    structures::{
        AttestInfo, Data, EccParameter, EccPoint, EccScheme, EccSignature, HashScheme,
        KeyDerivationFunctionScheme, MaxBuffer, Public, PublicBuffer, PublicBuilder,
        PublicEccParametersBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaExponent,
        RsaScheme, RsaSignature, Signature, SignatureScheme,
    },
    traits::{Marshall, UnMarshall},
    Context as TpmContext,
};

use crate::tpm::{create_srk, parse_pcr_indices, pcr_selection_sha256, KeyGuard};

const QUOTE_BLOB_MAGIC: &str = "TPM_OPS_QUOTE_V1";

struct QuoteBlob {
    algo: String,
    pcrs: String,
    nonce_hex: String,
    attest_hex: String,
    sig_hex: String,
    ak_pub_hex: String,
}

impl QuoteBlob {
    fn serialize(&self) -> String {
        format!(
            "{magic}\nalgo={algo}\npcrs={pcrs}\nnonce={nonce}\nattest={attest}\nsig={sig}\nak_pub={ak_pub}\n",
            magic = QUOTE_BLOB_MAGIC,
            algo = self.algo,
            pcrs = self.pcrs,
            nonce = self.nonce_hex,
            attest = self.attest_hex,
            sig = self.sig_hex,
            ak_pub = self.ak_pub_hex,
        )
    }

    fn parse(input: &str) -> Result<Self> {
        let mut lines = input.lines();
        let magic = lines
            .next()
            .ok_or_else(|| anyhow::anyhow!("Invalid blob: empty file"))?;
        if magic.trim() != QUOTE_BLOB_MAGIC {
            anyhow::bail!("Invalid quote blob header: expected {}", QUOTE_BLOB_MAGIC);
        }

        let mut kv = BTreeMap::<String, String>::new();
        for line in lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (k, v) = line
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("Invalid blob line: {}", line))?;
            kv.insert(k.trim().to_string(), v.trim().to_string());
        }

        macro_rules! field {
            ($name:expr) => {
                kv.remove($name)
                    .ok_or_else(|| anyhow::anyhow!("Missing field: {}", $name))?
            };
        }

        Ok(Self {
            algo: field!("algo"),
            pcrs: field!("pcrs"),
            nonce_hex: field!("nonce"),
            attest_hex: field!("attest"),
            sig_hex: field!("sig"),
            ak_pub_hex: field!("ak_pub"),
        })
    }
}

fn normalize_sha256_hex(value: &str, field: &str) -> Result<String> {
    let bytes = hex::decode(value.trim()).with_context(|| format!("Invalid {field} hex"))?;
    if bytes.len() != 32 {
        anyhow::bail!("{field} must be 32 bytes, got {}", bytes.len());
    }
    Ok(hex::encode(bytes))
}

fn ak_public_fingerprint(context: &mut TpmContext, public_bytes: &[u8]) -> Result<String> {
    let buffer =
        MaxBuffer::try_from(public_bytes).context("AK public area is too large to fingerprint")?;
    let (digest, _) = context
        .hash(buffer, HashingAlgorithm::Sha256, Hierarchy::Null)
        .context("Failed to fingerprint AK public area")?;
    Ok(hex::encode(digest.value()))
}

pub(crate) fn quote_public_fingerprint_from_file(
    context: &mut TpmContext,
    in_path: &str,
) -> Result<String> {
    let raw = fs::read_to_string(Path::new(in_path))
        .with_context(|| format!("Failed to read quote blob from {}", in_path))?;
    let blob = QuoteBlob::parse(&raw)?;
    let public_bytes = hex::decode(&blob.ak_pub_hex).context("Invalid ak_pub hex in blob")?;
    ak_public_fingerprint(context, &public_bytes)
}

/// Create an ephemeral restricted RSA signing key (AK) under the SRK.
fn create_ak_rsa(
    srk: tss_esapi::handles::KeyHandle,
    context: &mut TpmContext,
) -> Result<(tss_esapi::handles::KeyHandle, Public)> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_restricted(true)
        .with_no_da(true)
        .build()
        .context("Failed to build AK attributes")?;

    let rsa_params = PublicRsaParametersBuilder::new()
        .with_scheme(RsaScheme::RsaSsa(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_key_bits(RsaKeyBits::Rsa2048)
        .with_exponent(RsaExponent::default())
        .with_is_signing_key(true)
        .with_is_decryption_key(false)
        .with_restricted(true)
        .build()
        .context("Failed to build AK RSA parameters")?;

    let template = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_rsa_parameters(rsa_params)
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .context("Failed to build RSA AK template")?;

    let result = context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.create(srk, template, None, None, None, None)
        })
        .context("Failed to create RSA AK")?;

    let ak_pub = result.out_public;
    let ak_handle = context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.load(srk, result.out_private, ak_pub.clone())
        })
        .context("Failed to load RSA AK")?;

    Ok((ak_handle, ak_pub))
}

/// Create an ephemeral restricted ECC signing key (AK) under the SRK.
fn create_ak_ecc(
    srk: tss_esapi::handles::KeyHandle,
    context: &mut TpmContext,
) -> Result<(tss_esapi::handles::KeyHandle, Public)> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_restricted(true)
        .with_no_da(true)
        .build()
        .context("Failed to build AK attributes")?;

    let ecc_params = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_curve(EccCurve::NistP256)
        .with_is_signing_key(true)
        .with_is_decryption_key(false)
        .with_restricted(true)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()
        .context("Failed to build AK ECC parameters")?;

    let template = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .context("Failed to build ECC AK template")?;

    let result = context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.create(srk, template, None, None, None, None)
        })
        .context("Failed to create ECC AK")?;

    let ak_pub = result.out_public;
    let ak_handle = context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.load(srk, result.out_private, ak_pub.clone())
        })
        .context("Failed to load ECC AK")?;

    Ok((ak_handle, ak_pub))
}

fn sig_to_hex(sig: &Signature) -> Result<String> {
    let bytes = match sig {
        Signature::RsaSsa(s) => s.signature().value().to_vec(),
        Signature::EcDsa(s) => {
            let mut r = s.signature_r().value().to_vec();
            let mut sv = s.signature_s().value().to_vec();
            while r.len() < 32 {
                r.insert(0, 0);
            }
            while sv.len() < 32 {
                sv.insert(0, 0);
            }
            let mut out = r;
            out.extend_from_slice(&sv);
            out
        }
        other => anyhow::bail!("Unexpected signature type in quote: {:?}", other),
    };
    Ok(hex::encode(bytes))
}

fn sig_from_hex(sig_hex: &str, is_ecc: bool) -> Result<Signature> {
    let bytes = hex::decode(sig_hex).context("Invalid signature hex in quote blob")?;
    if is_ecc {
        if bytes.len() != 64 {
            anyhow::bail!("ECC signature must be 64 bytes (R||S), got {}", bytes.len());
        }
        let r = EccParameter::try_from(bytes[..32].to_vec()).context("Invalid R component")?;
        let s = EccParameter::try_from(bytes[32..].to_vec()).context("Invalid S component")?;
        Ok(Signature::EcDsa(
            EccSignature::create(HashingAlgorithm::Sha256, r, s)
                .context("Failed to build ECC signature")?,
        ))
    } else {
        let rsa_bytes = PublicKeyRsa::try_from(bytes).context("Invalid RSA signature bytes")?;
        Ok(Signature::RsaSsa(
            RsaSignature::create(HashingAlgorithm::Sha256, rsa_bytes)
                .context("Failed to build RSA signature")?,
        ))
    }
}

/// Generate a TPM quote over the selected PCRs and write it to a file (or stdout).
///
/// An ephemeral restricted Attestation Key (AK) is created under the SRK for
/// each invocation and flushed on completion. The quote blob contains everything
/// needed for offline verification: the marshalled TPMS_ATTEST structure, the
/// signature, and the AK public area.
pub(crate) fn cmd_quote(
    context: &mut TpmContext,
    pcrs: &str,
    nonce_opt: Option<&str>,
    algo: &str,
    out_opt: Option<&str>,
) -> Result<()> {
    let pcr_indices = parse_pcr_indices(pcrs)?;
    let pcrs_normalized = pcr_indices
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let pcr_selection = pcr_selection_sha256(&pcr_indices)?;

    // Nonce: provided hex or freshly generated 32 random bytes.
    let nonce_bytes: Vec<u8> = match nonce_opt {
        Some(hex_str) => hex::decode(hex_str).context("Invalid nonce hex")?,
        None => {
            let rand = context.get_random(32).context("Failed to generate nonce")?;
            rand.value().to_vec()
        }
    };
    let qualifying_data =
        Data::try_from(nonce_bytes.as_slice()).context("Nonce too large (max 64 bytes)")?;
    let nonce_hex = hex::encode(&nonce_bytes);

    let normalized_algo = algo.to_lowercase();
    let is_ecc = match normalized_algo.as_str() {
        "rsa" => false,
        "ecc" => true,
        _ => anyhow::bail!(
            "Unsupported quote algorithm: {} (expected rsa or ecc)",
            algo
        ),
    };

    info!("Creating ephemeral {} AK under SRK...", algo.to_uppercase());
    let srk = create_srk(context)?;
    let (ak_handle, ak_pub) = if is_ecc {
        create_ak_ecc(srk, context)?
    } else {
        create_ak_rsa(srk, context)?
    };
    let ak_guard = KeyGuard::new(context, ak_handle);
    let ak_handle_copy = ak_guard.handle();

    info!("Running TPM2_Quote (PCRs SHA-256:{})...", pcrs_normalized);

    // Restricted keys use the key's own scheme; pass Null to the quote call.
    let (attest, signature) = ak_guard
        .context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.quote(
                ak_handle_copy,
                qualifying_data,
                SignatureScheme::Null,
                pcr_selection,
            )
        })
        .context("TPM2_Quote failed")?;

    let attest_bytes = attest
        .marshall()
        .context("Failed to marshal attest structure")?;
    let sig_hex = sig_to_hex(&signature)?;
    let ak_pub_buffer = PublicBuffer::try_from(ak_pub).context("Failed to encode AK public")?;
    let ak_pub_hex = hex::encode(ak_pub_buffer.value());
    let ak_pub_sha256 = ak_public_fingerprint(ak_guard.context, ak_pub_buffer.value())?;

    // Print summary.
    println!("PCRs:        SHA-256:{}", pcrs_normalized);
    println!("Nonce:       {}", nonce_hex);
    println!("Algo:        {}", algo.to_uppercase());
    println!("AK SHA-256:  {}", ak_pub_sha256);
    println!("Firmware:    0x{:016X}", attest.firmware_version());
    if let AttestInfo::Quote { info } = attest.attested() {
        println!("PCR digest:  {}", hex::encode(info.pcr_digest().value()));
    }

    let blob = QuoteBlob {
        algo: normalized_algo,
        pcrs: pcrs_normalized,
        nonce_hex,
        attest_hex: hex::encode(&attest_bytes),
        sig_hex,
        ak_pub_hex,
    };

    match out_opt {
        Some(path) => {
            fs::write(Path::new(path), blob.serialize())
                .with_context(|| format!("Failed to write quote blob to {}", path))?;
            println!("\nQuote written to {}", path);
        }
        None => {
            println!("\n--- Quote Blob ---");
            print!("{}", blob.serialize());
        }
    }

    println!("\nQuote [OK]");
    Ok(())
}

/// Verify a quote blob: check the signature and display the attested PCR state.
///
/// The AK public key stored in the blob is loaded as an external key. The
/// TPMS_ATTEST bytes are hashed and the signature is verified against them.
pub(crate) fn cmd_quote_verify(
    context: &mut TpmContext,
    in_path: &str,
    expected_nonce_hex: &str,
    expected_ak_pub_sha256: &str,
    expected_pcrs: &str,
) -> Result<()> {
    let raw = fs::read_to_string(Path::new(in_path))
        .with_context(|| format!("Failed to read quote blob from {}", in_path))?;
    let blob = QuoteBlob::parse(&raw)?;
    let is_ecc = match blob.algo.as_str() {
        "rsa" => false,
        "ecc" => true,
        other => anyhow::bail!("Unsupported quote algorithm in blob: {}", other),
    };

    let expected_nonce =
        hex::decode(expected_nonce_hex.trim()).context("Invalid expected nonce hex")?;
    if expected_nonce.is_empty() {
        anyhow::bail!("Expected nonce must not be empty");
    }
    let expected_ak_pub_sha256 =
        normalize_sha256_hex(expected_ak_pub_sha256, "Expected AK fingerprint")?;
    let expected_pcr_indices = parse_pcr_indices(expected_pcrs)?;
    let expected_pcr_selection = pcr_selection_sha256(&expected_pcr_indices)?;
    let expected_pcrs_normalized = expected_pcr_indices
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",");

    // Decode and parse the TPMS_ATTEST structure.
    let attest_bytes = hex::decode(&blob.attest_hex).context("Invalid attest hex in blob")?;
    let attest = tss_esapi::structures::Attest::unmarshall(&attest_bytes)
        .context("Failed to parse attest structure")?;

    // Hash the raw TPMS_ATTEST bytes — that is what the TPM signed.
    let buffer = MaxBuffer::try_from(attest_bytes.as_slice())
        .context("Attest bytes too large for MaxBuffer")?;
    let (digest, _) = context
        .hash(buffer, HashingAlgorithm::Sha256, Hierarchy::Null)
        .context("Failed to hash attest bytes")?;

    // Reconstruct the signature.
    let signature = sig_from_hex(&blob.sig_hex, is_ecc)?;

    // Load the AK public key as an external object (no hierarchy binding needed).
    let ak_pub_bytes = hex::decode(&blob.ak_pub_hex).context("Invalid ak_pub hex in blob")?;
    let actual_ak_pub_sha256 = ak_public_fingerprint(context, &ak_pub_bytes)?;
    if actual_ak_pub_sha256 != expected_ak_pub_sha256 {
        anyhow::bail!(
            "AK public key fingerprint mismatch: expected {}, got {}",
            expected_ak_pub_sha256,
            actual_ak_pub_sha256
        );
    }
    let ak_pub_buffer =
        PublicBuffer::try_from(ak_pub_bytes).context("Failed to decode AK public buffer")?;
    let ak_pub = Public::try_from(ak_pub_buffer).context("Failed to decode AK public area")?;

    let ak_ext = context
        .load_external_public(ak_pub, Hierarchy::Null)
        .context("Failed to load AK public key into TPM")?;

    let verify_result = context.verify_signature(ak_ext, digest, signature);
    // Best-effort flush — ignore error since the context will flush on drop anyway.
    let _ = context.flush_context(ak_ext.into());

    if let Err(error) = verify_result {
        anyhow::bail!("Quote signature verification FAILED: {}", error);
    }

    // Display attested fields.
    if attest.extra_data().value() != expected_nonce.as_slice() {
        anyhow::bail!("Quote nonce does not match the verifier's expected nonce");
    }
    let stored_nonce = hex::decode(&blob.nonce_hex).context("Invalid nonce in blob")?;
    if stored_nonce != expected_nonce {
        anyhow::bail!("Quote blob nonce metadata does not match the verifier's expected nonce");
    }

    let quote_info = match attest.attested() {
        AttestInfo::Quote { info } => info,
        _ => anyhow::bail!("Signed attestation is not a TPM quote"),
    };
    if quote_info.pcr_selection() != &expected_pcr_selection {
        anyhow::bail!("Signed PCR selection does not match the verifier's expected PCR selection");
    }
    if blob.pcrs != expected_pcrs_normalized {
        anyhow::bail!(
            "Quote blob PCR metadata does not match the verifier's expected PCR selection"
        );
    }

    println!("Signature:   VALID [OK]");
    println!("\n--- Attested State ---");
    println!(
        "PCRs:        SHA-256:{} (verified)",
        expected_pcrs_normalized
    );
    println!("Nonce:       {} (verified)", hex::encode(expected_nonce));
    println!("AK SHA-256:  {} (trusted)", actual_ak_pub_sha256);
    println!(
        "Clock:       {} ms  (resets={}, restarts={})",
        attest.clock_info().clock(),
        attest.clock_info().reset_count(),
        attest.clock_info().restart_count(),
    );
    println!("Firmware:    0x{:016X}", attest.firmware_version());
    println!(
        "PCR digest:  {}",
        hex::encode(quote_info.pcr_digest().value())
    );

    println!("\nQuote verify [OK]");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::normalize_sha256_hex;

    #[test]
    fn sha256_fingerprint_is_normalized() {
        let uppercase = "AA".repeat(32);
        assert_eq!(
            normalize_sha256_hex(&uppercase, "fingerprint").unwrap(),
            "aa".repeat(32)
        );
    }

    #[test]
    fn sha256_fingerprint_rejects_wrong_length() {
        let error = normalize_sha256_hex("abcd", "fingerprint").unwrap_err();
        assert!(error.to_string().contains("must be 32 bytes"));
    }

    #[test]
    fn sha256_fingerprint_rejects_non_hex_input() {
        let error = normalize_sha256_hex(&"zz".repeat(32), "fingerprint").unwrap_err();
        assert!(error.to_string().contains("Invalid fingerprint hex"));
    }
}
