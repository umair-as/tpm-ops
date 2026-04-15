use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result};
use log::info;

use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    constants::SessionType,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        session_handles::{AuthSession, PolicySession},
    },
    structures::{
        Digest, KeyedHashScheme, PcrSelectionList, Public, PublicBuffer, PublicBuilder,
        PublicKeyedHashParameters, SensitiveData, SymmetricDefinition,
    },
    Context as TpmContext,
};

use crate::tpm::{create_srk, parse_pcr_indices, pcr_selection_sha256, KeyGuard};

const SEALED_BLOB_MAGIC: &str = "TPM_OPS_SEALED_V1";

struct SealedBlob {
    pcrs: String,
    policy_digest_hex: String,
    private_hex: String,
    public_hex: String,
}

impl SealedBlob {
    fn parse(input: &str) -> Result<Self> {
        let mut lines = input.lines();
        let magic = lines
            .next()
            .ok_or_else(|| anyhow::anyhow!("Invalid blob: empty file"))?;
        if magic.trim() != SEALED_BLOB_MAGIC {
            anyhow::bail!("Invalid blob header: expected {}", SEALED_BLOB_MAGIC);
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

        let pcrs = kv
            .remove("pcrs")
            .ok_or_else(|| anyhow::anyhow!("Invalid blob: missing pcrs"))?;
        let policy_digest_hex = kv
            .remove("policy_digest")
            .ok_or_else(|| anyhow::anyhow!("Invalid blob: missing policy_digest"))?;
        let private_hex = kv
            .remove("private")
            .ok_or_else(|| anyhow::anyhow!("Invalid blob: missing private"))?;
        let public_hex = kv
            .remove("public")
            .ok_or_else(|| anyhow::anyhow!("Invalid blob: missing public"))?;

        Ok(Self {
            pcrs,
            policy_digest_hex,
            private_hex,
            public_hex,
        })
    }

    fn serialize(&self) -> String {
        format!(
            "{magic}\npcrs={pcrs}\npolicy_digest={policy}\nprivate={private}\npublic={public}\n",
            magic = SEALED_BLOB_MAGIC,
            pcrs = self.pcrs,
            policy = self.policy_digest_hex,
            private = self.private_hex,
            public = self.public_hex,
        )
    }
}

fn policy_digest_for_current_pcr(
    context: &mut TpmContext,
    pcr_selection: PcrSelectionList,
) -> Result<Digest> {
    let trial_auth = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Trial,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )
        .context("Failed to start trial policy session")?
        .ok_or_else(|| anyhow::anyhow!("TPM returned no trial policy session handle"))?;

    let trial_policy =
        PolicySession::try_from(trial_auth).context("Failed to create policy session handle")?;

    context
        .policy_pcr(trial_policy, Digest::default(), pcr_selection)
        .context("Failed to apply trial PolicyPCR")?;

    context
        .policy_get_digest(trial_policy)
        .context("Failed to read trial policy digest")
}

fn sealed_public(policy_digest: Digest) -> Result<Public> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_no_da(true)
        .with_admin_with_policy(true)
        .with_user_with_auth(false)
        .with_sensitive_data_origin(false)
        .build()
        .context("Failed to build sealed object attributes")?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_auth_policy(policy_digest)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Default::default())
        .build()
        .context("Failed to build sealed object template")
}

pub(crate) fn cmd_seal(
    context: &mut TpmContext,
    data: &str,
    pcrs: &str,
    out_path: &str,
) -> Result<()> {
    let pcr_indices = parse_pcr_indices(pcrs)?;
    let pcrs_normalized = pcr_indices
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",");

    let pcr_selection = pcr_selection_sha256(&pcr_indices)?;
    let policy_digest = policy_digest_for_current_pcr(context, pcr_selection.clone())?;

    let sensitive_data =
        SensitiveData::try_from(data.as_bytes()).context("Data too large to seal for this TPM")?;

    let public = sealed_public(policy_digest.clone())?;

    info!(
        "Sealing {} bytes with PolicyPCR(SHA256:{})...",
        data.len(),
        pcrs_normalized
    );

    let srk = create_srk(context)?;
    let created = context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.create(srk, public, None, Some(sensitive_data), None, None)
        })
        .context("Failed to create sealed object")?;

    let public_blob = PublicBuffer::try_from(created.out_public)
        .context("Failed to encode sealed public blob")?;

    let blob = SealedBlob {
        pcrs: pcrs_normalized.clone(),
        policy_digest_hex: hex::encode(policy_digest.value()),
        private_hex: hex::encode(created.out_private.value()),
        public_hex: hex::encode(public_blob.value()),
    };

    fs::write(Path::new(out_path), blob.serialize())
        .with_context(|| format!("Failed to write sealed blob to {}", out_path))?;

    println!("Sealed data written to {}", out_path);
    println!("  Bytes: {}", data.len());
    println!("  Policy: PCR(SHA256:{})", pcrs_normalized);
    println!("  Policy digest: {}", hex::encode(policy_digest.value()));
    println!("\nSeal operation [OK]");

    Ok(())
}

pub(crate) fn unseal_from_file(
    context: &mut TpmContext,
    in_path: &str,
    pcrs: &str,
) -> Result<Vec<u8>> {
    let raw = fs::read_to_string(Path::new(in_path))
        .with_context(|| format!("Failed to read sealed blob from {}", in_path))?;
    let blob = SealedBlob::parse(&raw)?;

    let requested = parse_pcr_indices(pcrs)?;
    let requested_str = requested
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",");

    if blob.pcrs != requested_str {
        anyhow::bail!(
            "PCR selection mismatch: blob uses '{}' but command used '{}'",
            blob.pcrs,
            requested_str
        );
    }

    let pcr_selection = pcr_selection_sha256(&requested)?;
    let current_digest = policy_digest_for_current_pcr(context, pcr_selection.clone())?;
    let expected_digest =
        hex::decode(&blob.policy_digest_hex).context("Invalid policy_digest encoding in blob")?;

    if current_digest.value() != expected_digest.as_slice() {
        anyhow::bail!("Current PCR state does not satisfy blob policy (digest mismatch)");
    }

    let private_bytes = hex::decode(&blob.private_hex).context("Invalid private blob hex")?;
    let public_bytes = hex::decode(&blob.public_hex).context("Invalid public blob hex")?;

    let private = tss_esapi::structures::Private::try_from(private_bytes)
        .context("Failed to decode private blob")?;
    let public_buffer =
        PublicBuffer::try_from(public_bytes).context("Failed to decode public blob")?;
    let public = Public::try_from(public_buffer).context("Failed to decode public area")?;

    let srk = create_srk(context)?;
    let object = context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.load(srk, private, public)
        })
        .context("Failed to load sealed object")?;
    let guard = KeyGuard::new(context, object);

    let policy_auth = guard
        .context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )
        .context("Failed to start policy session")?
        .ok_or_else(|| anyhow::anyhow!("TPM returned no policy session handle"))?;

    let policy_session =
        PolicySession::try_from(policy_auth).context("Failed to convert policy session handle")?;

    guard
        .context
        .policy_pcr(policy_session, Digest::default(), pcr_selection)
        .context("Failed to apply PolicyPCR")?;

    let object_handle = guard.handle();
    let unsealed = guard
        .context
        .execute_with_session(Some(AuthSession::from(policy_session)), |ctx| {
            ctx.unseal(object_handle.into())
        })
        .context("Unseal failed (policy mismatch or corrupted blob)")?;

    Ok(unsealed.value().to_vec())
}

pub(crate) fn cmd_unseal(context: &mut TpmContext, in_path: &str, pcrs: &str) -> Result<()> {
    let secret = unseal_from_file(context, in_path, pcrs)?;

    println!("Unsealed {} bytes", secret.len());
    println!("Data (hex): {}", hex::encode(&secret));

    match std::str::from_utf8(&secret) {
        Ok(text) => println!("Data (utf8): {}", text),
        Err(_) => println!("Data (utf8): <non-UTF8>"),
    }

    println!("\nUnseal operation [OK]");
    Ok(())
}
