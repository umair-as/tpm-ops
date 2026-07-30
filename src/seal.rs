use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context, Result};
use log::info;

use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        session_handles::AuthSession,
    },
    structures::{
        Digest, KeyedHashScheme, Public, PublicBuffer, PublicBuilder, PublicKeyedHashParameters,
        SensitiveData,
    },
    Context as TpmContext,
};

use crate::tpm::{
    create_srk, parse_pcr_indices, pcr_policy_digest, pcr_selection_sha256,
    start_pcr_policy_session, KeyGuard,
};

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
    let policy_digest = pcr_policy_digest(context, pcr_selection.clone())?;

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
    let current_digest = pcr_policy_digest(context, pcr_selection.clone())?;
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
    let object_handle = guard.handle();

    let (policy_guard, policy_session) = start_pcr_policy_session(guard.context, pcr_selection)?;

    let unsealed = policy_guard
        .context
        .execute_with_session(Some(policy_session), |ctx| ctx.unseal(object_handle.into()))
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
