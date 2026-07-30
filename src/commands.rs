use anyhow::{Context, Result};
use log::{debug, info};

use tss_esapi::{
    constants::PropertyTag,
    handles::PcrHandle,
    interface_types::{
        algorithm::HashingAlgorithm, resource_handles::Hierarchy, session_handles::AuthSession,
    },
    structures::{Digest, DigestValues, MaxBuffer, PcrSelectionListBuilder, PcrSlot},
    Context as TpmContext,
};

use crate::tpm::parse_hash_algo;

/// PCRs that are safe to extend/reset from userspace without extra confirmation:
/// PCR 16 is the debug PCR, PCR 23 is reserved for application use. Both are
/// resettable from locality 0; boot-measurement PCRs (0-15, e.g. firmware/secure
/// boot state) are not, and extending them is irreversible until reboot.
const UNRESTRICTED_PCRS: [u8; 2] = [16, 23];

const VERSION: &str = env!("CARGO_PKG_VERSION");
const GIT_HASH: &str = env!("TPM_OPS_GIT_HASH");

pub(crate) fn cmd_version() -> Result<()> {
    println!("tpm-ops {}", VERSION);
    println!("git: {}", GIT_HASH);
    Ok(())
}

fn get_property(context: &mut TpmContext, tag: PropertyTag) -> Result<Option<u32>> {
    context
        .get_tpm_property(tag)
        .context("Failed to read TPM property")
}

pub(crate) fn cmd_info(context: &mut TpmContext) -> Result<()> {
    info!("=== TPM Information ===");

    let manufacturer = get_property(context, PropertyTag::Manufacturer)?.ok_or_else(|| {
        anyhow::anyhow!("TPM did not report manufacturer — device may be unresponsive")
    })?;

    let mfr_bytes = manufacturer.to_be_bytes();
    let mfr_str: String = mfr_bytes
        .iter()
        .filter(|&&b| b != 0)
        .map(|&b| b as char)
        .collect();

    println!("Manufacturer: {} (0x{:08X})", mfr_str, manufacturer);

    let vendor_vals = [
        PropertyTag::VendorString1,
        PropertyTag::VendorString2,
        PropertyTag::VendorString3,
        PropertyTag::VendorString4,
    ]
    .map(|tag| get_property(context, tag).ok().flatten().unwrap_or(0));

    let vendor_str = vendor_vals
        .iter()
        .flat_map(|v| v.to_be_bytes())
        .filter(|&b| b != 0 && b.is_ascii())
        .map(|b| b as char)
        .collect::<String>();

    if !vendor_str.is_empty() {
        println!("Vendor: {}", vendor_str);
    }

    if let Some(fw1) = get_property(context, PropertyTag::FirmwareVersion1)? {
        println!("Firmware: {}.{}", fw1 >> 16, fw1 & 0xFFFF);
    }

    if let Some(rev) = get_property(context, PropertyTag::Revision)? {
        println!("Spec Revision: {}.{}", rev / 100, rev % 100);
    }

    println!("\nTPM is accessible and responding [OK]");
    Ok(())
}

pub(crate) fn cmd_selftest(context: &mut TpmContext, full: bool) -> Result<()> {
    info!("Running TPM self-test (full={})...", full);

    context.self_test(full).context("TPM self-test failed")?;

    println!("TPM self-test: PASSED");
    println!("  Mode: {}", if full { "full" } else { "incremental" });

    match context.get_test_result() {
        Ok((data, result)) => {
            if result.is_ok() {
                println!("  Result: OK");
            } else {
                println!("  Result: {:?}", result);
            }
            if !data.is_empty() {
                println!("  Test data: {} bytes", data.len());
            }
        }
        Err(e) => {
            debug!("Could not read test result details: {}", e);
        }
    }

    println!("\nTPM health check [OK]");
    Ok(())
}

pub(crate) fn cmd_random(context: &mut TpmContext, num_bytes: usize) -> Result<()> {
    let random_bytes = random_bytes(context, num_bytes)?;

    println!("Random bytes ({} bytes):", random_bytes.len());
    println!("{}", hex::encode(random_bytes));

    Ok(())
}

pub(crate) fn random_bytes(context: &mut TpmContext, num_bytes: usize) -> Result<Vec<u8>> {
    if num_bytes == 0 || num_bytes > 48 {
        anyhow::bail!("Byte count must be between 1 and 48");
    }

    info!("Generating {} random bytes from TPM TRNG...", num_bytes);

    let mut output = Vec::with_capacity(num_bytes);
    while output.len() < num_bytes {
        let random = context
            .get_random(num_bytes - output.len())
            .context("Failed to get random bytes from TPM")?;
        if random.is_empty() {
            anyhow::bail!("TPM returned no random data");
        }
        output.extend_from_slice(random.value());
    }

    Ok(output)
}

pub(crate) fn cmd_pcr(context: &mut TpmContext, index: u8, algo: &str) -> Result<()> {
    let digests = read_pcr_digests(context, index, algo)?;
    for digest in digests {
        println!("PCR[{}] ({}):", index, algo.to_uppercase());
        println!("{}", hex::encode(digest));
    }
    Ok(())
}

pub(crate) fn read_pcr_digests(
    context: &mut TpmContext,
    index: u8,
    algo: &str,
) -> Result<Vec<Vec<u8>>> {
    if index > 23 {
        anyhow::bail!("PCR index must be 0-23");
    }

    let hash_algo = parse_hash_algo(algo)?;
    let pcr_mask = 1u32
        .checked_shl(index as u32)
        .ok_or_else(|| anyhow::anyhow!("Invalid PCR slot index shift"))?;
    let pcr_slot = PcrSlot::try_from(pcr_mask).context("Invalid PCR slot")?;

    let pcr_selection = PcrSelectionListBuilder::new()
        .with_selection(hash_algo, &[pcr_slot])
        .build()
        .context("Failed to build PCR selection")?;

    info!("Reading PCR {} with {}...", index, algo.to_uppercase());

    let (_, _, digest_list) = context
        .pcr_read(pcr_selection)
        .context("Failed to read PCR")?;

    let digests = digest_list.value();
    if digests.is_empty() {
        anyhow::bail!("TPM returned no digest for PCR {}", index);
    }

    Ok(digests
        .iter()
        .map(|digest| digest.value().to_vec())
        .collect())
}

pub(crate) fn cmd_hash(context: &mut TpmContext, data: &str, algo: &str) -> Result<()> {
    let hash_algo = parse_hash_algo(algo)?;

    let data_bytes = if data.chars().all(|c| c.is_ascii_hexdigit()) && data.len().is_multiple_of(2)
    {
        hex::decode(data).unwrap_or_else(|_| data.as_bytes().to_vec())
    } else {
        data.as_bytes().to_vec()
    };

    info!(
        "Hashing {} bytes with {}...",
        data_bytes.len(),
        algo.to_uppercase()
    );

    let digest = hash_bytes(context, &data_bytes, hash_algo)?;

    println!("{} hash:", algo.to_uppercase());
    println!("{}", hex::encode(digest));

    Ok(())
}

/// Pure gate for `pcr extend`: refuse anything outside {16, 23} unless --force.
pub(crate) fn check_pcr_extend_allowed(index: u8, force: bool) -> Result<()> {
    if force || UNRESTRICTED_PCRS.contains(&index) {
        return Ok(());
    }
    anyhow::bail!(
        "Refusing to extend PCR {}: only PCR 16 (debug) and PCR 23 (application) are extended \
         without confirmation. Extending a boot-measurement PCR is irreversible until reboot and \
         can invalidate anything sealed or attested against its current value. Pass --force to \
         proceed anyway.",
        index
    );
}

/// Pure gate for `pcr reset`: only {16, 23} are resettable from locality 0, unconditionally.
pub(crate) fn check_pcr_reset_allowed(index: u8) -> Result<()> {
    if UNRESTRICTED_PCRS.contains(&index) {
        return Ok(());
    }
    anyhow::bail!(
        "Refusing to reset PCR {}: only PCR 16 and PCR 23 are resettable from locality 0. \
         PCRs 0-15 cannot be reset without a platform-level action (e.g. reboot).",
        index
    );
}

fn pcr_handle_from_index(index: u8) -> Result<PcrHandle> {
    use PcrHandle::*;
    Ok(match index {
        0 => Pcr0,
        1 => Pcr1,
        2 => Pcr2,
        3 => Pcr3,
        4 => Pcr4,
        5 => Pcr5,
        6 => Pcr6,
        7 => Pcr7,
        8 => Pcr8,
        9 => Pcr9,
        10 => Pcr10,
        11 => Pcr11,
        12 => Pcr12,
        13 => Pcr13,
        14 => Pcr14,
        15 => Pcr15,
        16 => Pcr16,
        17 => Pcr17,
        18 => Pcr18,
        19 => Pcr19,
        20 => Pcr20,
        21 => Pcr21,
        22 => Pcr22,
        23 => Pcr23,
        _ => anyhow::bail!("PCR index must be 0-23"),
    })
}

/// Extend PCR `index` (SHA-256 bank) with the SHA-256 hash of `data`. Returns the
/// resulting PCR digest. Does not enforce the safety gate — callers (`cmd_pcr_extend`)
/// are responsible for calling `check_pcr_extend_allowed` first.
pub(crate) fn pcr_extend(context: &mut TpmContext, index: u8, data: &[u8]) -> Result<Vec<u8>> {
    let pcr_handle = pcr_handle_from_index(index)?;
    let input_digest = hash_bytes(context, data, HashingAlgorithm::Sha256)?;
    let digest = Digest::try_from(input_digest).context("Failed to build digest for PCR extend")?;

    let mut values = DigestValues::new();
    values.set(HashingAlgorithm::Sha256, digest);

    info!("Extending PCR {} (SHA-256 bank)...", index);
    context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.pcr_extend(pcr_handle, values)
        })
        .context("Failed to extend PCR")?;

    let digests = read_pcr_digests(context, index, "sha256")?;
    digests
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("TPM returned no digest after PCR extend"))
}

/// Reset PCR `index` to its default value. Returns the PCR digest after reset.
/// Does not enforce the safety gate — callers (`cmd_pcr_reset`) call
/// `check_pcr_reset_allowed` first.
pub(crate) fn pcr_reset(context: &mut TpmContext, index: u8) -> Result<Vec<u8>> {
    let pcr_handle = pcr_handle_from_index(index)?;

    info!("Resetting PCR {}...", index);
    context
        .execute_with_session(Some(AuthSession::Password), |ctx| ctx.pcr_reset(pcr_handle))
        .context("Failed to reset PCR")?;

    let digests = read_pcr_digests(context, index, "sha256")?;
    digests
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("TPM returned no digest after PCR reset"))
}

pub(crate) fn cmd_pcr_extend(
    context: &mut TpmContext,
    index: u8,
    data: &str,
    force: bool,
) -> Result<()> {
    check_pcr_extend_allowed(index, force)?;

    let input_digest = hash_bytes(context, data.as_bytes(), HashingAlgorithm::Sha256)?;
    let new_digest = pcr_extend(context, index, data.as_bytes())?;

    println!("Extended PCR {} (SHA-256)", index);
    println!("  Input digest: {}", hex::encode(&input_digest));
    println!("  New PCR value: {}", hex::encode(&new_digest));
    println!("\nPCR extend [OK]");
    Ok(())
}

pub(crate) fn cmd_pcr_reset(context: &mut TpmContext, index: u8) -> Result<()> {
    check_pcr_reset_allowed(index)?;

    let new_digest = pcr_reset(context, index)?;

    println!("Reset PCR {}", index);
    println!("  PCR value: {}", hex::encode(&new_digest));
    println!("\nPCR reset [OK]");
    Ok(())
}

pub(crate) fn hash_bytes(
    context: &mut TpmContext,
    data: &[u8],
    hash_algo: HashingAlgorithm,
) -> Result<Vec<u8>> {
    let buffer = MaxBuffer::try_from(data).context("Data too large for TPM buffer")?;
    let (digest, _ticket) = context
        .hash(buffer, hash_algo, Hierarchy::Null)
        .context("Failed to hash data")?;
    Ok(digest.value().to_vec())
}

#[cfg(test)]
mod tests {
    use super::{check_pcr_extend_allowed, check_pcr_reset_allowed};

    #[test]
    fn extend_allowed_without_force_for_debug_and_application_pcrs() {
        assert!(check_pcr_extend_allowed(16, false).is_ok());
        assert!(check_pcr_extend_allowed(23, false).is_ok());
    }

    #[test]
    fn extend_refused_without_force_for_boot_measurement_pcrs() {
        for index in [0, 1, 4, 7, 15] {
            let err = check_pcr_extend_allowed(index, false).unwrap_err();
            assert!(err.to_string().contains("Refusing to extend"));
        }
    }

    #[test]
    fn extend_allowed_with_force_for_any_index() {
        assert!(check_pcr_extend_allowed(0, true).is_ok());
        assert!(check_pcr_extend_allowed(7, true).is_ok());
    }

    #[test]
    fn reset_allowed_for_debug_and_application_pcrs() {
        assert!(check_pcr_reset_allowed(16).is_ok());
        assert!(check_pcr_reset_allowed(23).is_ok());
    }

    #[test]
    fn reset_refused_unconditionally_for_boot_measurement_pcrs() {
        for index in [0, 1, 4, 7, 15] {
            let err = check_pcr_reset_allowed(index).unwrap_err();
            assert!(err.to_string().contains("Refusing to reset"));
        }
    }
}
