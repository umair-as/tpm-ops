use anyhow::{Context, Result};
use log::debug;

use tss_esapi::{
    constants::{CapabilityType, SessionType},
    handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, SessionHandle, TpmHandle},
    interface_types::{
        algorithm::HashingAlgorithm,
        dynamic_handles::Persistent,
        key_bits::RsaKeyBits,
        resource_handles::{Hierarchy, Provision},
        session_handles::{AuthSession, PolicySession},
    },
    structures::{
        CapabilityData, Digest, PcrSelectionList, PcrSelectionListBuilder, PcrSlot, RsaExponent,
        SymmetricDefinition, SymmetricDefinitionObject,
    },
    tss2_esys::TPMS_PCR_SELECTION,
    Context as TpmContext,
};

/// Reserved handle for the persistent SRK. Never exposed to users as a signing key slot.
pub(crate) const PERSISTENT_SRK_HANDLE: u32 = 0x81000000;

/// Parse a hex handle string like "0x81000001" into a u32.
pub(crate) fn parse_handle(s: &str) -> Result<u32> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u32::from_str_radix(s, 16).context("Invalid handle — expected hex like 0x81000001")
}

/// Create an ESYS ObjectHandle from a persistent TPM handle value.
///
/// Probes existence via `persistent_handle_exists` (GetCapability) first and
/// fails cleanly if the handle is absent, rather than calling
/// `tr_from_tpm_public` on a handle the TPM doesn't have — the latter reaches
/// the tss2 C library's own error path, which logs `WARNING:esys:...` /
/// `ERROR:esys:...` lines straight to the process's stderr regardless of the
/// Rust `log` crate's level. Every caller of this function (`sign`, `verify`,
/// `key export-pub`, `key delete`) gets the clean failure for free.
pub(crate) fn persistent_to_esys(
    context: &mut TpmContext,
    handle_val: u32,
) -> Result<ObjectHandle> {
    if !persistent_handle_exists(context, handle_val)? {
        anyhow::bail!("No key found at handle 0x{:08X}", handle_val);
    }
    let persistent_handle =
        PersistentTpmHandle::new(handle_val).context("Invalid persistent handle range")?;
    context
        .tr_from_tpm_public(TpmHandle::Persistent(persistent_handle))
        .context("Failed to load persistent handle")
}

/// Validate a single PCR index (0..23). Shared by every command that takes a
/// bare index — `parse_pcr_indices` (comma lists) uses the identical message
/// for its per-token check, so `pcr -i 99` and `seal -p 99` fail the same way.
pub(crate) fn check_pcr_index(index: u8) -> Result<()> {
    if index > 23 {
        anyhow::bail!("PCR index out of range: {} (expected 0..23)", index);
    }
    Ok(())
}

/// Check whether a persistent handle exists without issuing a ReadPublic command.
///
/// Uses GetCapability(Handles) instead of tr_from_tpm_public so that probing
/// an absent handle does not trigger tss2 C-library error logs.
pub(crate) fn persistent_handle_exists(context: &mut TpmContext, handle_val: u32) -> Result<bool> {
    // Persistent handles are defined by the TPM 2.0 spec to have MSO (top byte)
    // 0x81 (TPM_HT_PERSISTENT); anything else can't exist as one. Reject before
    // ever calling GetCapability: passing a wrongly-typed handle as its `property`
    // argument is itself a TPM-level error, and — unlike an absent-but-correctly-typed
    // handle — that genuinely reaches the TPM and triggers the same tss2 C-library
    // stderr spam this function exists to avoid (confirmed with e.g. 0x99999999).
    if handle_val >> 24 != 0x81 {
        return Ok(false);
    }

    // GetCapability returns handles >= property, up to count. Ask for 1 starting
    // at our exact handle — if it exists it will be the first (and only) result.
    let (cap, _more) = context
        .get_capability(CapabilityType::Handles, handle_val, 1)
        .context("Failed to query persistent handles")?;

    if let CapabilityData::Handles(handles) = cap {
        for &h in handles.as_ref() {
            let v: u32 = h.into();
            if v == handle_val {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub(crate) fn parse_hash_algo(algo: &str) -> Result<HashingAlgorithm> {
    match algo.to_lowercase().as_str() {
        "sha256" => Ok(HashingAlgorithm::Sha256),
        "sha1" => Ok(HashingAlgorithm::Sha1),
        "sha384" => Ok(HashingAlgorithm::Sha384),
        _ => anyhow::bail!("Unsupported hash algorithm: {}", algo),
    }
}

pub(crate) fn hash_algo_name(algo: HashingAlgorithm) -> &'static str {
    match algo {
        HashingAlgorithm::Sha1 => "sha1",
        HashingAlgorithm::Sha256 => "sha256",
        HashingAlgorithm::Sha384 => "sha384",
        HashingAlgorithm::Sha512 => "sha512",
        HashingAlgorithm::Sm3_256 => "sm3_256",
        _ => "unknown",
    }
}

/// Hash algorithms with at least one PCR bank actually allocated on this TPM.
///
/// Used to give a useful error when a PCR read comes back empty: on hardware
/// where a bank exists in the spec but was never allocated (e.g. SHA-1 on
/// this reference SLB9672), a `pcr_read` for that bank returns an empty
/// digest list — indistinguishable, from the response alone, from asking for
/// an out-of-range index. This lets the caller tell the two apart.
pub(crate) fn allocated_hash_algorithms(context: &mut TpmContext) -> Result<Vec<HashingAlgorithm>> {
    let (cap, _more) = context
        .get_capability(CapabilityType::AssignedPcr, 0, 8)
        .context("Failed to query allocated PCR banks")?;

    let CapabilityData::AssignedPcr(list) = cap else {
        return Ok(Vec::new());
    };

    Ok(list
        .get_selections()
        .iter()
        .filter(|selection| !selection.is_empty())
        .filter_map(|selection| {
            let raw: TPMS_PCR_SELECTION = (*selection).into();
            HashingAlgorithm::try_from(raw.hash).ok()
        })
        .collect())
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
        self.handle
            .expect("KeyGuard: handle already consumed (bug)")
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

/// RAII guard that flushes a TPM auth/policy session handle on drop.
///
/// Trial and real policy sessions occupy TPM session slots just like transient
/// key handles. `tpm-ops test` starts many of them in a single process, which is
/// a latent exhaustion risk on real hardware (stricter than swtpm) if a session
/// is never flushed.
pub(crate) struct SessionGuard<'a> {
    pub context: &'a mut TpmContext,
    handle: Option<SessionHandle>,
}

impl<'a> SessionGuard<'a> {
    pub fn new(context: &'a mut TpmContext, handle: SessionHandle) -> Self {
        Self {
            context,
            handle: Some(handle),
        }
    }
}

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            if let Err(e) = self.context.flush_context(h.into()) {
                debug!("SessionGuard: failed to flush session handle: {}", e);
            }
        }
    }
}

/// Compute the PolicyPCR digest for the current PCR state via a trial session.
///
/// This is the create-time half of PolicyPCR: it never authorizes anything, it
/// just asks the TPM what the policy digest would be if `policy_pcr` were applied
/// against `pcr_selection` right now. Used both to seal data (`seal.rs`) and to
/// bind a signing key's auth policy to PCR state at key-creation time.
pub(crate) fn pcr_policy_digest(
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

    let guard = SessionGuard::new(context, SessionHandle::from(trial_auth));

    let trial_policy =
        PolicySession::try_from(trial_auth).context("Failed to create policy session handle")?;

    guard
        .context
        .policy_pcr(trial_policy, Digest::default(), pcr_selection)
        .context("Failed to apply trial PolicyPCR")?;

    guard
        .context
        .policy_get_digest(trial_policy)
        .context("Failed to read trial policy digest")
}

/// Start a real PolicyPCR session against the current PCR state.
///
/// Returns the [`SessionGuard`] (so the session is flushed once the caller is
/// done with it) together with the [`AuthSession`] to hand to
/// `execute_with_session` for the gated command (e.g. `sign`, `unseal`). A
/// policy session is consumed by use — callers must start a fresh one per
/// TPM operation.
pub(crate) fn start_pcr_policy_session<'a>(
    context: &'a mut TpmContext,
    pcr_selection: PcrSelectionList,
) -> Result<(SessionGuard<'a>, AuthSession)> {
    let policy_auth = context
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

    let guard = SessionGuard::new(context, SessionHandle::from(policy_auth));

    guard
        .context
        .policy_pcr(policy_session, Digest::default(), pcr_selection)
        .context("Failed to apply PolicyPCR")?;

    Ok((guard, policy_auth))
}

/// Return the persistent SRK handle, creating and persisting it on first call.
///
/// The SRK lives at PERSISTENT_SRK_HANDLE (0x81000000) permanently.
/// Subsequent calls skip the ~19s RSA-2048 keygen and just load the existing handle.
/// Caller must NOT flush the returned handle — it is a persistent object.
pub(crate) fn create_srk(context: &mut TpmContext) -> Result<KeyHandle> {
    // Fast path: SRK already persisted from a previous run.
    if persistent_handle_exists(context, PERSISTENT_SRK_HANDLE)? {
        let obj_handle = persistent_to_esys(context, PERSISTENT_SRK_HANDLE)?;
        debug!(
            "Using existing persistent SRK at 0x{:08X}",
            PERSISTENT_SRK_HANDLE
        );
        return Ok(KeyHandle::from(obj_handle));
    }

    let spinner = crate::output::Spinner::start(
        "Creating SRK (Storage Root Key) — first-time setup, this takes ~20s...",
    );

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

    let transient = result.key_handle;

    // Persist at the reserved SRK slot.
    let persistent_tpm_handle =
        PersistentTpmHandle::new(PERSISTENT_SRK_HANDLE).context("Invalid SRK handle")?;
    let persistent = Persistent::Persistent(persistent_tpm_handle);
    context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.evict_control(Provision::Owner, transient.into(), persistent)
        })
        .context("Failed to persist SRK")?;

    context
        .flush_context(transient.into())
        .context("Failed to flush transient SRK after persisting")?;

    drop(spinner);
    crate::output::status(&format!(
        "SRK persisted at 0x{:08X} [OK]",
        PERSISTENT_SRK_HANDLE
    ));

    let obj_handle = persistent_to_esys(context, PERSISTENT_SRK_HANDLE)
        .context("Failed to load newly persisted SRK")?;
    Ok(KeyHandle::from(obj_handle))
}

/// Parse a comma-separated list of PCR indices (e.g. "0,7") into a sorted, deduplicated Vec<u8>.
pub(crate) fn parse_pcr_indices(pcrs: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for part in pcrs.split(',') {
        let token = part.trim();
        if token.is_empty() {
            continue;
        }
        let idx: u8 = token
            .parse()
            .with_context(|| format!("Invalid PCR index '{}'", token))?;
        check_pcr_index(idx)?;
        if !out.contains(&idx) {
            out.push(idx);
        }
    }
    if out.is_empty() {
        anyhow::bail!("At least one PCR must be provided (example: 0,7)");
    }
    out.sort_unstable();
    Ok(out)
}

/// Build a SHA-256 PCR selection list from a slice of PCR indices.
pub(crate) fn pcr_selection_sha256(indices: &[u8]) -> Result<PcrSelectionList> {
    let mut slots = Vec::with_capacity(indices.len());
    for &idx in indices {
        let pcr_mask = 1u32
            .checked_shl(idx as u32)
            .ok_or_else(|| anyhow::anyhow!("Invalid PCR shift for index {}", idx))?;
        let slot =
            PcrSlot::try_from(pcr_mask).with_context(|| format!("Invalid PCR slot {}", idx))?;
        slots.push(slot);
    }
    PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &slots)
        .build()
        .context("Failed to build PCR selection")
}
