use anyhow::{Context, Result};
use log::{debug, info};

use tss_esapi::{
    constants::PropertyTag,
    interface_types::resource_handles::Hierarchy,
    structures::{MaxBuffer, PcrSelectionListBuilder, PcrSlot},
    Context as TpmContext,
};

use crate::tpm::parse_hash_algo;

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

    let manufacturer = get_property(context, PropertyTag::Manufacturer)?
        .ok_or_else(|| {
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

    context
        .self_test(full)
        .context("TPM self-test failed")?;

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
    if num_bytes == 0 || num_bytes > 48 {
        anyhow::bail!("Byte count must be between 1 and 48");
    }

    info!("Generating {} random bytes from TPM TRNG...", num_bytes);

    let random_bytes = context
        .get_random(num_bytes)
        .context("Failed to get random bytes from TPM")?;

    println!("Random bytes ({} bytes):", num_bytes);
    println!("{}", hex::encode(random_bytes.value()));

    Ok(())
}

pub(crate) fn cmd_pcr(context: &mut TpmContext, index: u8, algo: &str) -> Result<()> {
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

    let (_, _, digest_list) = context.pcr_read(pcr_selection).context("Failed to read PCR")?;

    let digests = digest_list.value();
    if digests.is_empty() {
        println!("PCR[{}]: (empty)", index);
    } else {
        for digest in digests {
            println!("PCR[{}] ({}):", index, algo.to_uppercase());
            println!("{}", hex::encode(digest.value()));
        }
    }

    Ok(())
}

pub(crate) fn cmd_hash(context: &mut TpmContext, data: &str, algo: &str) -> Result<()> {
    let hash_algo = parse_hash_algo(algo)?;

    let data_bytes = if data.chars().all(|c| c.is_ascii_hexdigit()) && data.len() % 2 == 0 {
        hex::decode(data).unwrap_or_else(|_| data.as_bytes().to_vec())
    } else {
        data.as_bytes().to_vec()
    };

    let buffer =
        MaxBuffer::try_from(data_bytes.as_slice()).context("Data too large for TPM buffer")?;

    info!(
        "Hashing {} bytes with {}...",
        data_bytes.len(),
        algo.to_uppercase()
    );

    let (digest, _ticket) = context
        .hash(buffer, hash_algo, Hierarchy::Null)
        .context("Failed to hash data")?;

    println!("{} hash:", algo.to_uppercase());
    println!("{}", hex::encode(digest.value()));

    Ok(())
}
