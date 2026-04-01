use anyhow::Result;
use log::info;
use tss_esapi::Context as TpmContext;

use crate::commands::{cmd_hash, cmd_info, cmd_pcr, cmd_random, cmd_selftest};
use crate::keys::{cmd_key_create, cmd_key_delete};
use crate::sign::cmd_sign;
use crate::tpm::persistent_to_esys;

pub(crate) fn cmd_test(context: &mut TpmContext) -> Result<()> {
    println!("=== TPM Test Suite ===\n");

    println!("--- Test 1: TPM Self-Test ---");
    cmd_selftest(context, false)?;
    println!();

    println!("--- Test 2: TPM Info ---");
    cmd_info(context)?;
    println!();

    println!("--- Test 3: Random Number Generation ---");
    cmd_random(context, 32)?;
    println!();

    println!("--- Test 4: PCR Read ---");
    cmd_pcr(context, 0, "sha256")?;
    println!();

    println!("--- Test 5: TPM Hash ---");
    cmd_hash(context, "Hello, TPM!", "sha256")?;
    println!();

    println!("--- Test 6: RSA Signing (ephemeral) ---");
    cmd_sign(context, "Test message for RSA signing", false, None)?;
    println!();

    println!("--- Test 7: ECC Signing (ephemeral) ---");
    cmd_sign(context, "Test message for ECC signing", true, None)?;
    println!();

    println!("--- Test 8: Persistent Key Lifecycle ---");
    cmd_test_persistent_key(context)?;
    println!();

    println!("=== All Tests Passed! ===");
    Ok(())
}

/// Test persistent key create -> sign -> delete lifecycle.
fn cmd_test_persistent_key(context: &mut TpmContext) -> Result<()> {
    let test_handle = "0x81FFF001";
    let test_handle_val: u32 = 0x81FFF001;

    if persistent_to_esys(context, test_handle_val).is_ok() {
        info!("Cleaning up stale test key...");
        cmd_key_delete(context, test_handle)?;
    }

    println!("  Creating test RSA key...");
    cmd_key_create(context, "rsa", test_handle)?;

    println!("  Signing with persistent key...");
    cmd_sign(context, "persistent-key-test", false, Some(test_handle))?;

    println!("  Deleting test key...");
    cmd_key_delete(context, test_handle)?;

    println!("\nPersistent key lifecycle [OK]");
    Ok(())
}
