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
        CapabilityData, EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, Public,
        PublicBuilder, PublicEccParametersBuilder, PublicKeyRsa, PublicRsaParametersBuilder,
        RsaExponent, RsaScheme,
    },
    utils::PublicKey,
    Context as TpmContext,
};

use crate::pem::{der_to_pem, encode_ec_pubkey_der, encode_rsa_pubkey_der};
use crate::tpm::{create_srk, parse_handle, persistent_to_esys};

/// Build a public template for an unrestricted signing child key.
fn signing_key_template(algo: &str) -> Result<Public> {
    match algo.to_lowercase().as_str() {
        "rsa" => {
            let attrs = ObjectAttributesBuilder::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(true)
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

            PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::Rsa)
                .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                .with_object_attributes(attrs)
                .with_rsa_parameters(rsa_params)
                .with_rsa_unique_identifier(PublicKeyRsa::default())
                .build()
                .context("Failed to build RSA public template")
        }
        "ecc" => {
            let attrs = ObjectAttributesBuilder::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(true)
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

            PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::Ecc)
                .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                .with_object_attributes(attrs)
                .with_ecc_parameters(ecc_params)
                .with_ecc_unique_identifier(EccPoint::default())
                .build()
                .context("Failed to build ECC public template")
        }
        _ => anyhow::bail!("Unsupported algorithm '{}' — use 'rsa' or 'ecc'", algo),
    }
}

/// Create a child signing key under the SRK and persist it.
pub(crate) fn cmd_key_create(context: &mut TpmContext, algo: &str, persist_str: &str) -> Result<()> {
    let handle_val = parse_handle(persist_str)?;

    if handle_val < 0x81000000 || handle_val > 0x81FFFFFF {
        anyhow::bail!("Handle must be in persistent range 0x81000000..0x81FFFFFF");
    }

    if persistent_to_esys(context, handle_val).is_ok() {
        anyhow::bail!("Handle 0x{:08X} is already in use — delete it first", handle_val);
    }

    info!("Creating {} child key under SRK...", algo.to_uppercase());

    let srk_handle = create_srk(context)?;

    let child_template = signing_key_template(algo)?;

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

    context.flush_context(srk_handle.into())
        .context("Failed to flush SRK")?;

    let persistent_tpm_handle =
        PersistentTpmHandle::new(handle_val).context("Invalid persistent handle")?;
    let persistent = Persistent::Persistent(persistent_tpm_handle);

    context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.evict_control(
                Provision::Owner,
                child_handle.into(),
                persistent,
            )
        })
        .context("Failed to persist key")?;

    context
        .flush_context(child_handle.into())
        .context("Failed to flush transient child handle")?;

    println!("Created {} signing key at 0x{:08X}", algo.to_uppercase(), handle_val);
    println!(
        "  Algorithm: {}",
        match algo.to_lowercase().as_str() {
            "rsa" => "RSA-2048 / RSA-SSA / SHA-256",
            "ecc" => "ECC P-256 / ECDSA / SHA-256",
            _ => algo,
        }
    );
    println!("  Parent: SRK (Owner hierarchy)");
    println!("  Type: persistent, unrestricted signing");
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
                                let (algo, attrs) = match &public {
                                    Public::Rsa { object_attributes, .. } => {
                                        ("RSA", *object_attributes)
                                    }
                                    Public::Ecc { object_attributes, .. } => {
                                        ("ECC", *object_attributes)
                                    }
                                    other => {
                                        println!(
                                            "  0x{:08X}  {:?}",
                                            handle_val, other
                                        );
                                        continue;
                                    }
                                };
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
                                println!(
                                    "  0x{:08X}  {}  {}  {}",
                                    handle_val, algo, restricted, usage
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

    let pub_key = PublicKey::try_from(public)
        .map_err(|_| anyhow::anyhow!("Unsupported key type at 0x{:08X}", handle_val))?;

    match pub_key {
        PublicKey::Rsa(modulus_bytes) => {
            let der = encode_rsa_pubkey_der(&modulus_bytes, &[0x01, 0x00, 0x01]);
            let pem = der_to_pem(&der, "RSA PUBLIC KEY");
            println!("{}", pem);
        }
        PublicKey::Ecc { x, y } => {
            let mut point = Vec::with_capacity(1 + x.len() + y.len());
            point.push(0x04);
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);

            let der = encode_ec_pubkey_der(&point);
            let pem = der_to_pem(&der, "PUBLIC KEY");
            println!("{}", pem);
        }
    }

    Ok(())
}
