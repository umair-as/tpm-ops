use anyhow::{Context, Result};
use log::{debug, info};

use tss_esapi::{
    handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, TpmHandle},
    interface_types::{
        algorithm::HashingAlgorithm,
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
        session_handles::AuthSession,
    },
    structures::{RsaExponent, SymmetricDefinitionObject},
    Context as TpmContext,
};

/// Parse a hex handle string like "0x81000001" into a u32.
pub(crate) fn parse_handle(s: &str) -> Result<u32> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u32::from_str_radix(s, 16).context("Invalid handle — expected hex like 0x81000001")
}

/// Create an ESYS ObjectHandle from a persistent TPM handle value.
pub(crate) fn persistent_to_esys(context: &mut TpmContext, handle_val: u32) -> Result<ObjectHandle> {
    let persistent_handle =
        PersistentTpmHandle::new(handle_val).context("Invalid persistent handle range")?;
    context
        .tr_from_tpm_public(TpmHandle::Persistent(persistent_handle))
        .context("Failed to load persistent handle — key may not exist")
}

pub(crate) fn parse_hash_algo(algo: &str) -> Result<HashingAlgorithm> {
    match algo.to_lowercase().as_str() {
        "sha256" => Ok(HashingAlgorithm::Sha256),
        "sha1" => Ok(HashingAlgorithm::Sha1),
        "sha384" => Ok(HashingAlgorithm::Sha384),
        _ => anyhow::bail!("Unsupported hash algorithm: {}", algo),
    }
}

/// RAII guard that flushes a transient TPM key handle on drop.
pub(crate) struct KeyGuard<'a> {
    pub context: &'a mut TpmContext,
    handle: Option<KeyHandle>,
}

impl<'a> KeyGuard<'a> {
    pub fn new(context: &'a mut TpmContext, handle: KeyHandle) -> Self {
        Self {
            context,
            handle: Some(handle),
        }
    }

    pub fn handle(&self) -> KeyHandle {
        self.handle.expect("KeyGuard: handle already consumed (bug)")
    }
}

impl Drop for KeyGuard<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            if let Err(e) = self.context.flush_context(h.into()) {
                debug!("KeyGuard: failed to flush key handle: {}", e);
            }
        }
    }
}

/// Create an SRK (Storage Root Key) under the owner hierarchy.
/// Standard TCG template: RSA-2048, restricted, decrypt, AES-128-CFB inner symmetric.
/// Returns a transient handle — caller must flush when done.
pub(crate) fn create_srk(context: &mut TpmContext) -> Result<KeyHandle> {
    info!("Creating SRK (Storage Root Key)...");

    let srk_public = tss_esapi::utils::create_restricted_decryption_rsa_public(
        SymmetricDefinitionObject::AES_128_CFB,
        RsaKeyBits::Rsa2048,
        RsaExponent::default(),
    )
    .context("Failed to build SRK public template")?;

    let result = context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.create_primary(Hierarchy::Owner, srk_public, None, None, None, None)
        })
        .context("Failed to create SRK")?;

    debug!("SRK created: {:?}", result.key_handle);
    Ok(result.key_handle)
}
