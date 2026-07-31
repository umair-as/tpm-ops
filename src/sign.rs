use anyhow::{Context, Result};
use log::debug;

use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    constants::Tss2ResponseCodeKind,
    handles::KeyHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
        session_handles::AuthSession,
    },
    structures::{
        EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, MaxBuffer, Public,
        PublicBuilder, PublicEccParametersBuilder, PublicKeyRsa, PublicRsaParametersBuilder,
        RsaExponent, RsaScheme, SignatureScheme,
    },
    Context as TpmContext, Error as TssError,
};

use crate::commands::resolve_text_arg;
use crate::output::{print_json, Json};
use crate::tpm::{
    parse_handle, parse_pcr_indices, pcr_selection_sha256, persistent_to_esys,
    start_pcr_policy_session, KeyGuard,
};

#[allow(clippy::too_many_arguments)]
pub(crate) fn cmd_sign(
    context: &mut TpmContext,
    data: Option<&str>,
    file: Option<&str>,
    use_ecc: bool,
    key_handle: Option<&str>,
    policy_pcrs: Option<&str>,
    json: bool,
) -> Result<()> {
    let data = resolve_text_arg(data, file)?;
    match key_handle {
        Some(h) => cmd_sign_persistent(context, &data, h, policy_pcrs, json),
        None => {
            if policy_pcrs.is_some() {
                anyhow::bail!(
                    "--policy-pcrs requires --key — it only applies to signing with a \
                     persistent policy-bound key"
                );
            }
            cmd_sign_ephemeral(context, &data, use_ecc, json)
        }
    }
}

/// Sign with a persistent key, returning (is_ecc, digest_hex, sig_bytes).
/// For ECC sig_bytes = R||S (each component zero-padded to 32 bytes).
/// For RSA sig_bytes = raw PKCS#1 signature.
///
/// `policy_pcrs`, if given, must match the PCR list the key was created with
/// (`key create --policy-pcrs`) — the TPM cannot recover that list from the key
/// itself (a policy digest is one-way), so the caller must supply it. A fresh
/// real PolicyPCR session is started and consumed by this single signature; no
/// client-side check of whether current PCR state matches is performed — the
/// TPM is the sole arbiter of that.
pub(crate) fn sign_with_persistent_key(
    context: &mut TpmContext,
    data: &str,
    handle_str: &str,
    policy_pcrs: Option<&str>,
) -> Result<(bool, String, Vec<u8>)> {
    let handle_val = parse_handle(handle_str)?;
    let obj_handle = persistent_to_esys(context, handle_val)?;
    let key_handle = KeyHandle::from(obj_handle);

    let (public, _, _) = context
        .read_public(key_handle)
        .context("Failed to read public area of persistent key")?;

    let is_ecc = matches!(public, Public::Ecc { .. });
    let is_policy_key = !public.object_attributes().user_with_auth();

    match (is_policy_key, policy_pcrs) {
        (true, None) => anyhow::bail!(
            "Key 0x{:08X} is policy-bound (password auth disabled) — pass --policy-pcrs <list> \
             matching the PCRs it was created with",
            handle_val
        ),
        (false, Some(_)) => anyhow::bail!(
            "Key 0x{:08X} is not policy-bound (password auth enabled) — --policy-pcrs does not apply",
            handle_val
        ),
        _ => {}
    }

    let data_bytes = data.as_bytes();
    let buffer = MaxBuffer::try_from(data_bytes).context("Data too large")?;

    let (digest, ticket) = context
        .hash(buffer, HashingAlgorithm::Sha256, Hierarchy::Null)
        .context("Failed to hash data")?;

    let scheme = if is_ecc {
        SignatureScheme::EcDsa {
            hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
        }
    } else {
        SignatureScheme::RsaSsa {
            hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
        }
    };

    let signature = match policy_pcrs {
        None => context
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.sign(key_handle, digest.clone(), scheme, ticket)
            })
            .context("Failed to sign data")?,
        Some(pcrs) => {
            let indices = parse_pcr_indices(pcrs)?;
            let pcr_selection = pcr_selection_sha256(&indices)?;
            let (policy_guard, policy_session) = start_pcr_policy_session(context, pcr_selection)?;

            let sign_result = policy_guard
                .context
                .execute_with_session(Some(policy_session), |ctx| {
                    ctx.sign(key_handle, digest.clone(), scheme, ticket)
                });

            match sign_result {
                Ok(sig) => sig,
                Err(TssError::Tss2Error(code))
                    if code.kind() == Some(Tss2ResponseCodeKind::PolicyFail) =>
                {
                    anyhow::bail!(
                        "Sign refused by TPM: current PCR state does not satisfy the key's policy"
                    );
                }
                Err(e) => return Err(e).context("Failed to sign data"),
            }
        }
    };

    let digest_hex = hex::encode(digest.value());

    let sig_bytes = match &signature {
        tss_esapi::structures::Signature::RsaSsa(s) => s.signature().value().to_vec(),
        tss_esapi::structures::Signature::EcDsa(s) => {
            // Pad each component to 32 bytes for P-256
            let mut r = s.signature_r().value().to_vec();
            let mut s_bytes = s.signature_s().value().to_vec();
            // Left-pad with zeros if shorter than 32 bytes
            while r.len() < 32 {
                r.insert(0, 0);
            }
            while s_bytes.len() < 32 {
                s_bytes.insert(0, 0);
            }
            let mut out = r;
            out.extend_from_slice(&s_bytes);
            out
        }
        other => anyhow::bail!("Unexpected signature type: {:?}", other),
    };

    Ok((is_ecc, digest_hex, sig_bytes))
}

/// Sign with a persistent key and print results. Detects RSA vs ECC from the key's public area.
fn cmd_sign_persistent(
    context: &mut TpmContext,
    data: &str,
    handle_str: &str,
    policy_pcrs: Option<&str>,
    json: bool,
) -> Result<()> {
    let handle_val = parse_handle(handle_str)?;

    debug!("Signing with persistent key at 0x{:08X}...", handle_val);

    let (is_ecc, digest_hex, sig_bytes) =
        sign_with_persistent_key(context, data, handle_str, policy_pcrs)?;

    if json {
        let mut fields = vec![
            (
                "algorithm",
                Json::Str(if is_ecc { "ecdsa" } else { "rsa-ssa" }.to_string()),
            ),
            ("key", Json::Str(format!("0x{:08x}", handle_val))),
            ("digest", Json::Str(digest_hex)),
            ("signature", Json::Str(hex::encode(&sig_bytes))),
        ];
        if is_ecc {
            fields.push(("r", Json::Str(hex::encode(&sig_bytes[..32]))));
            fields.push(("s", Json::Str(hex::encode(&sig_bytes[32..]))));
        }
        if let Some(pcrs) = policy_pcrs {
            fields.push(("policy_pcrs", Json::Str(pcrs.to_string())));
        }
        print_json("tpm-ops.sign.v1", fields);
        return Ok(());
    }

    println!("\nData: {}", data);
    println!("Digest (SHA256): {}", digest_hex);
    println!(
        "Key: 0x{:08X} (persistent, {}{})",
        handle_val,
        if is_ecc { "ECC" } else { "RSA" },
        match policy_pcrs {
            Some(pcrs) => format!(", policy-bound, PCR {}", pcrs),
            None => String::new(),
        }
    );

    if is_ecc {
        println!("\nSignature (ECDSA):");
        println!("Algorithm: ECDSA");
        println!("R: {}", hex::encode(&sig_bytes[..32]));
        println!("S: {}", hex::encode(&sig_bytes[32..]));
        println!("Sig (R||S): {}", hex::encode(&sig_bytes));
    } else {
        println!("\nSignature (RSA-SSA):");
        println!("Algorithm: RSA-SSA");
        println!("Signature: {}", hex::encode(&sig_bytes));
    }

    println!("\nData signed with persistent key [OK]");
    Ok(())
}

/// Sign with an ephemeral primary key (original behavior).
fn cmd_sign_ephemeral(
    context: &mut TpmContext,
    data: &str,
    use_ecc: bool,
    json: bool,
) -> Result<()> {
    debug!(
        "Creating ephemeral {} primary key in TPM...",
        if use_ecc { "ECC" } else { "RSA" }
    );

    let primary_key = if use_ecc {
        create_ecc_primary(context)?
    } else {
        create_rsa_primary(context)?
    };

    let guard = KeyGuard::new(context, primary_key);

    debug!("Primary key created: {:?}", guard.handle());

    let data_bytes = data.as_bytes();
    let buffer = MaxBuffer::try_from(data_bytes).context("Data too large")?;

    let (digest, ticket) = guard
        .context
        .hash(buffer, HashingAlgorithm::Sha256, Hierarchy::Null)
        .context("Failed to hash data")?;

    debug!("Signing data...");

    let scheme = if use_ecc {
        SignatureScheme::EcDsa {
            hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
        }
    } else {
        SignatureScheme::RsaSsa {
            hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
        }
    };

    let key_handle = guard.handle();
    let signature = guard
        .context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.sign(key_handle, digest.clone(), scheme, ticket)
        })
        .context("Failed to sign data")?;

    if json {
        let (algorithm, sig_hex, r, s) = match &signature {
            tss_esapi::structures::Signature::RsaSsa(sig) => {
                ("rsa-ssa", hex::encode(sig.signature().value()), None, None)
            }
            tss_esapi::structures::Signature::EcDsa(sig) => (
                "ecdsa",
                String::new(),
                Some(hex::encode(sig.signature_r().value())),
                Some(hex::encode(sig.signature_s().value())),
            ),
            _ => ("unknown", String::new(), None, None),
        };
        let mut fields = vec![
            ("algorithm", Json::Str(algorithm.to_string())),
            ("key", Json::Str("ephemeral".to_string())),
            ("digest", Json::Str(hex::encode(digest.value()))),
        ];
        match (r, s) {
            (Some(r), Some(s)) => {
                fields.push(("r", Json::Str(r)));
                fields.push(("s", Json::Str(s)));
            }
            _ => fields.push(("signature", Json::Str(sig_hex))),
        }
        print_json("tpm-ops.sign.v1", fields);
        return Ok(());
    }

    println!("\nData: {}", data);
    println!("Digest (SHA256): {}", hex::encode(digest.value()));
    print_signature(&signature);
    println!("\nKey created, data signed, key flushed [OK]");
    Ok(())
}

fn print_signature(signature: &tss_esapi::structures::Signature) {
    println!("\nSignature:");
    match signature {
        tss_esapi::structures::Signature::RsaSsa(sig) => {
            println!("Algorithm: RSA-SSA");
            println!("Signature: {}", hex::encode(sig.signature().value()));
        }
        tss_esapi::structures::Signature::EcDsa(sig) => {
            println!("Algorithm: ECDSA");
            println!("R: {}", hex::encode(sig.signature_r().value()));
            println!("S: {}", hex::encode(sig.signature_s().value()));
        }
        _ => println!("{:?}", signature),
    }
}

fn create_rsa_primary(context: &mut TpmContext) -> Result<KeyHandle> {
    let object_attributes = ObjectAttributesBuilder::new()
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

    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(rsa_params)
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .context("Failed to build public template")?;

    let result = context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)
        })
        .context("Failed to create RSA primary key")?;

    Ok(result.key_handle)
}

fn create_ecc_primary(context: &mut TpmContext) -> Result<KeyHandle> {
    let object_attributes = ObjectAttributesBuilder::new()
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

    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .context("Failed to build public template")?;

    let result = context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)
        })
        .context("Failed to create ECC primary key")?;

    Ok(result.key_handle)
}
