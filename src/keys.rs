use anyhow::{Context, Result};
use log::info;

use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    constants::{tss::TPM2_PERSISTENT_FIRST, CapabilityType},
    handles::{KeyHandle, PersistentTpmHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        dynamic_handles::Persistent,
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::Provision,
        session_handles::AuthSession,
    },
    structures::{
        CapabilityData, Digest, EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme,
        Public, PublicBuilder, PublicEccParametersBuilder, PublicKeyRsa,
        PublicRsaParametersBuilder, RsaExponent, RsaScheme,
    },
    Context as TpmContext,
};

use crate::pem::{der_to_pem, encode_ec_pubkey_der, encode_rsa_pubkey_der};
use crate::tpm::{
    create_srk, parse_handle, parse_pcr_indices, pcr_policy_digest, pcr_selection_sha256,
    persistent_handle_exists, persistent_to_esys, PERSISTENT_SRK_HANDLE,
};

fn pad_ec_coordinate(value: &[u8], coordinate_size: usize) -> Result<Vec<u8>> {
    if value.len() > coordinate_size {
        anyhow::bail!(
            "ECC coordinate is {} bytes, larger than the curve size {}",
            value.len(),
            coordinate_size
        );
    }
    let mut padded = vec![0; coordinate_size - value.len()];
    padded.extend_from_slice(value);
    Ok(padded)
}

/// Build a public template for an unrestricted signing child key.
///
/// When `policy_digest` is `Some`, the key is bound to a PolicyPCR auth policy
/// computed at creation time: password auth is disabled (`user_with_auth(false)`)
/// and policy auth is required (`admin_with_policy(true)`), mirroring
/// `sealed_public()` in `seal.rs`. Without it, behavior is unchanged from before
/// policy-bound keys existed (plain password-authorized signing key).
fn signing_key_template(algo: &str, policy_digest: Option<Digest>) -> Result<Public> {
    let is_policy_bound = policy_digest.is_some();
    match algo.to_lowercase().as_str() {
        "rsa" => {
            let attrs = ObjectAttributesBuilder::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(!is_policy_bound)
                .with_admin_with_policy(is_policy_bound)
                .with_sign_encrypt(true)
                .with_restricted(false)
                .build()
                .context("Failed to build object attributes")?;

            let rsa_params = PublicRsaParametersBuilder::new()
                .with_scheme(RsaScheme::RsaSsa(HashScheme::new(HashingAlgorithm::Sha256)))
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_exponent(RsaExponent::default())
                .with_is_signing_key(true)
                .with_is_decryption_key(false)
                .with_restricted(false)
                .build()
                .context("Failed to build RSA parameters")?;

            let mut builder = PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::Rsa)
                .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                .with_object_attributes(attrs)
                .with_rsa_parameters(rsa_params)
                .with_rsa_unique_identifier(PublicKeyRsa::default());
            if let Some(digest) = policy_digest {
                builder = builder.with_auth_policy(digest);
            }
            builder
                .build()
                .context("Failed to build RSA public template")
        }
        "ecc" => {
            let attrs = ObjectAttributesBuilder::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(!is_policy_bound)
                .with_admin_with_policy(is_policy_bound)
                .with_sign_encrypt(true)
                .with_restricted(false)
                .build()
                .context("Failed to build object attributes")?;

            let ecc_params = PublicEccParametersBuilder::new()
                .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
                .with_curve(EccCurve::NistP256)
                .with_is_signing_key(true)
                .with_is_decryption_key(false)
                .with_restricted(false)
                .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                .build()
                .context("Failed to build ECC parameters")?;

            let mut builder = PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::Ecc)
                .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                .with_object_attributes(attrs)
                .with_ecc_parameters(ecc_params)
                .with_ecc_unique_identifier(EccPoint::default());
            if let Some(digest) = policy_digest {
                builder = builder.with_auth_policy(digest);
            }
            builder
                .build()
                .context("Failed to build ECC public template")
        }
        _ => anyhow::bail!("Unsupported algorithm '{}' — use 'rsa' or 'ecc'", algo),
    }
}

/// Create a child signing key under the SRK and persist it.
///
/// `policy_pcrs`, if given (e.g. "0,7"), binds the key's auth policy to the
/// current value of those PCRs via a trial PolicyPCR session — the same
/// machinery `seal.rs` uses for data. The PCR list is not recoverable from the
/// key afterward (a policy digest is one-way): the caller must remember and
/// re-supply the same list at sign time.
pub(crate) fn cmd_key_create(
    context: &mut TpmContext,
    algo: &str,
    persist_str: &str,
    policy_pcrs: Option<&str>,
) -> Result<()> {
    let handle_val = parse_handle(persist_str)?;

    // Owner hierarchy persistent range — platform range (0x81800000+) requires platform auth.
    // 0x81000000 is reserved for the persistent SRK — reject it.
    if handle_val <= PERSISTENT_SRK_HANDLE || handle_val > 0x817FFFFF {
        anyhow::bail!(
            "Handle must be in owner persistent range 0x81000001..0x817FFFFF \
             (0x81000000 is reserved for the SRK)"
        );
    }

    if persistent_handle_exists(context, handle_val)? {
        anyhow::bail!(
            "Handle 0x{:08X} is already in use — delete it first",
            handle_val
        );
    }

    let policy = match policy_pcrs {
        Some(pcrs) => {
            let indices = parse_pcr_indices(pcrs)?;
            let pcrs_normalized = indices
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let selection = pcr_selection_sha256(&indices)?;
            let digest = pcr_policy_digest(context, selection)?;
            Some((pcrs_normalized, digest))
        }
        None => None,
    };

    info!("Creating {} child key under SRK...", algo.to_uppercase());

    let srk_handle = create_srk(context)?;

    let policy_digest = policy.as_ref().map(|(_, digest)| digest.clone());
    let child_template = signing_key_template(algo, policy_digest)?;

    let create_result = context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.create(srk_handle, child_template, None, None, None, None)
        })
        .context("Failed to create child key")?;

    info!("Child key created, loading...");

    let child_handle = context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.load(
                srk_handle,
                create_result.out_private,
                create_result.out_public,
            )
        })
        .context("Failed to load child key")?;

    // SRK is persistent — do not flush it.

    let persistent_tpm_handle =
        PersistentTpmHandle::new(handle_val).context("Invalid persistent handle")?;
    let persistent = Persistent::Persistent(persistent_tpm_handle);

    context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.evict_control(Provision::Owner, child_handle.into(), persistent)
        })
        .context("Failed to persist key")?;

    if let Err(flush_error) = context.flush_context(child_handle.into()) {
        let rollback_result = cmd_key_delete(context, persist_str);
        match rollback_result {
            Ok(()) => {
                return Err(flush_error)
                    .context("Failed to flush transient child handle; persistent key rolled back");
            }
            Err(rollback_error) => {
                anyhow::bail!(
                    "Failed to flush transient child handle: {}; \
                     rollback of persistent key {} also failed: {:#}",
                    flush_error,
                    persist_str,
                    rollback_error
                );
            }
        }
    }

    println!(
        "Created {} signing key at 0x{:08X}",
        algo.to_uppercase(),
        handle_val
    );
    println!(
        "  Algorithm: {}",
        match algo.to_lowercase().as_str() {
            "rsa" => "RSA-2048 / RSA-SSA / SHA-256",
            "ecc" => "ECC P-256 / ECDSA / SHA-256",
            _ => algo,
        }
    );
    println!("  Parent: SRK (Owner hierarchy)");
    match &policy {
        Some((pcrs_normalized, digest)) => {
            println!(
                "  Type: persistent, unrestricted signing, policy-bound (PCR {})",
                pcrs_normalized
            );
            println!("  Policy: PCR(SHA256:{})", pcrs_normalized);
            println!("  Policy digest: {}", hex::encode(digest.value()));
            println!(
                "  NOTE: the policy digest is one-way — the TPM cannot recover this PCR list \
                 from the key. Pass --policy-pcrs {} to `sign` for every signature.",
                pcrs_normalized
            );
        }
        None => {
            println!("  Type: persistent, unrestricted signing");
        }
    }
    println!("\nKey persisted [OK]");
    Ok(())
}

/// List all persistent handles and their key types.
pub(crate) fn cmd_key_list(context: &mut TpmContext) -> Result<()> {
    info!("Enumerating persistent handles...");

    let mut property = TPM2_PERSISTENT_FIRST;
    let mut count = 0u32;

    loop {
        let (capability_data, more) = context
            .get_capability(CapabilityType::Handles, property, 20)
            .context("Failed to enumerate persistent handles")?;

        if let CapabilityData::Handles(handles) = capability_data {
            for &tpm_handle in handles.as_ref() {
                let handle_val: u32 = tpm_handle.into();
                count += 1;

                match persistent_to_esys(context, handle_val) {
                    Ok(obj_handle) => {
                        let key_handle = KeyHandle::from(obj_handle);
                        match context.read_public(key_handle) {
                            Ok((public, _, _)) => {
                                let (algo, attrs, auth_policy_empty) = match &public {
                                    Public::Rsa {
                                        object_attributes,
                                        auth_policy,
                                        ..
                                    } => {
                                        ("RSA", *object_attributes, auth_policy.value().is_empty())
                                    }
                                    Public::Ecc {
                                        object_attributes,
                                        auth_policy,
                                        ..
                                    } => {
                                        ("ECC", *object_attributes, auth_policy.value().is_empty())
                                    }
                                    other => {
                                        println!("  0x{:08X}  {:?}", handle_val, other);
                                        continue;
                                    }
                                };
                                let policy_bound = !attrs.user_with_auth() && !auth_policy_empty;
                                let usage = if attrs.sign_encrypt() && !attrs.decrypt() {
                                    "signing"
                                } else if !attrs.sign_encrypt() && attrs.decrypt() {
                                    "decrypt"
                                } else if attrs.sign_encrypt() && attrs.decrypt() {
                                    "general"
                                } else {
                                    "unknown"
                                };
                                let restricted = if attrs.restricted() {
                                    "restricted"
                                } else {
                                    "unrestricted"
                                };
                                let srk_note = if handle_val == PERSISTENT_SRK_HANDLE {
                                    "  (SRK)"
                                } else {
                                    ""
                                };
                                let policy_note = if policy_bound { "  policy-bound" } else { "" };
                                println!(
                                    "  0x{:08X}  {}  {}  {}{}{}",
                                    handle_val, algo, restricted, usage, srk_note, policy_note
                                );
                            }
                            Err(e) => {
                                println!("  0x{:08X}  (read_public failed: {})", handle_val, e);
                            }
                        }
                    }
                    Err(e) => {
                        println!("  0x{:08X}  (inaccessible: {})", handle_val, e);
                    }
                }

                property = handle_val + 1;
            }
        }

        if !more {
            break;
        }
    }

    if count == 0 {
        println!("No persistent keys found.");
    } else {
        println!("\n{} persistent handle(s) found.", count);
    }

    Ok(())
}

/// Delete a persistent key by evicting it from the TPM.
pub(crate) fn cmd_key_delete(context: &mut TpmContext, handle_str: &str) -> Result<()> {
    let handle_val = parse_handle(handle_str)?;

    if handle_val == PERSISTENT_SRK_HANDLE {
        anyhow::bail!(
            "0x{:08X} is the persistent SRK — refusing to delete it. \
             Use 'tpm-ops key delete-srk' if you really need to reset it.",
            PERSISTENT_SRK_HANDLE
        );
    }

    info!("Deleting persistent key at 0x{:08X}...", handle_val);

    let obj_handle = persistent_to_esys(context, handle_val)?;

    let persistent_tpm_handle =
        PersistentTpmHandle::new(handle_val).context("Invalid persistent handle")?;
    let persistent = Persistent::Persistent(persistent_tpm_handle);

    context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.evict_control(Provision::Owner, obj_handle, persistent)
        })
        .context("Failed to evict persistent key")?;

    println!("Deleted persistent key at 0x{:08X} [OK]", handle_val);
    Ok(())
}

/// Export the public portion of a persistent key as PEM.
pub(crate) fn cmd_key_export_pub(context: &mut TpmContext, handle_str: &str) -> Result<()> {
    let handle_val = parse_handle(handle_str)?;
    let obj_handle = persistent_to_esys(context, handle_val)?;
    let key_handle = KeyHandle::from(obj_handle);

    let (public, _, _) = context
        .read_public(key_handle)
        .context("Failed to read public area")?;

    match public {
        Public::Rsa {
            parameters, unique, ..
        } => {
            let exponent = match parameters.exponent().value() {
                0 => 65_537,
                value => value,
            };
            let exponent_bytes = exponent.to_be_bytes();
            let first_nonzero = exponent_bytes
                .iter()
                .position(|&byte| byte != 0)
                .unwrap_or(exponent_bytes.len() - 1);
            let der = encode_rsa_pubkey_der(unique.value(), &exponent_bytes[first_nonzero..]);
            let pem = der_to_pem(&der, "RSA PUBLIC KEY");
            println!("{}", pem);
        }
        Public::Ecc {
            parameters, unique, ..
        } => {
            let (curve_oid, coordinate_size): (&[u8], usize) = match parameters.ecc_curve() {
                EccCurve::NistP192 => (
                    &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01],
                    24,
                ),
                EccCurve::NistP224 => (&[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x21], 28),
                EccCurve::NistP256 => (
                    &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
                    32,
                ),
                EccCurve::NistP384 => (&[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22], 48),
                EccCurve::NistP521 => (&[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23], 66),
                curve => anyhow::bail!("PEM export does not support ECC curve {:?}", curve),
            };
            let x = pad_ec_coordinate(unique.x().value(), coordinate_size)?;
            let y = pad_ec_coordinate(unique.y().value(), coordinate_size)?;
            let mut point = Vec::with_capacity(1 + x.len() + y.len());
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);

            let der = encode_ec_pubkey_der(&point, curve_oid);
            let pem = der_to_pem(&der, "PUBLIC KEY");
            println!("{}", pem);
        }
        _ => anyhow::bail!("Unsupported key type at 0x{:08X}", handle_val),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::pad_ec_coordinate;

    #[test]
    fn ec_coordinates_are_left_padded_to_curve_size() {
        assert_eq!(
            pad_ec_coordinate(&[0x01, 0x02], 4).unwrap(),
            vec![0x00, 0x00, 0x01, 0x02]
        );
    }

    #[test]
    fn oversized_ec_coordinates_are_rejected() {
        assert!(pad_ec_coordinate(&[0; 5], 4).is_err());
    }
}
