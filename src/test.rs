use anyhow::Result;
use log::info;
use tss_esapi::Context as TpmContext;

use crate::commands::{cmd_hash, cmd_info, cmd_pcr, cmd_random, cmd_selftest};
use crate::keys::{cmd_key_create, cmd_key_delete};
use crate::quote::{cmd_quote, cmd_quote_verify};
use crate::seal::{cmd_seal, unseal_from_file};
use crate::sign::{cmd_sign, sign_with_persistent_key};
use crate::tpm::persistent_to_esys;
use crate::verify::cmd_verify;

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

    println!("--- Test 9: Sign + Verify Roundtrip ---");
    cmd_test_sign_verify(context)?;
    println!();

    println!("--- Test 10: Seal + Unseal Roundtrip ---");
    cmd_test_seal_unseal(context)?;
    println!();

    println!("--- Test 11: TPM Quote + Verify ---");
    cmd_test_quote(context)?;
    println!();

    println!("=== All Tests Passed! ===");
    Ok(())
}

/// Test persistent key create -> sign -> delete lifecycle.
fn cmd_test_persistent_key(context: &mut TpmContext) -> Result<()> {
    // Use a handle in the owner persistent range (0x81000000..0x817FFFFF)
    let test_handle = "0x81000FFF";
    let test_handle_val: u32 = 0x81000FFF;

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

/// Test sign + verify roundtrip with both RSA and ECC persistent keys.
fn cmd_test_sign_verify(context: &mut TpmContext) -> Result<()> {
    let test_data = "sign-verify-roundtrip";

    for (algo, handle_str, handle_val) in [
        ("rsa", "0x81000FFE", 0x81000FFEu32),
        ("ecc", "0x81000FFD", 0x81000FFDu32),
    ] {
        // Clean up any stale key from a previous failed run.
        if persistent_to_esys(context, handle_val).is_ok() {
            cmd_key_delete(context, handle_str)?;
        }

        println!("  Creating test {} key...", algo.to_uppercase());
        cmd_key_create(context, algo, handle_str)?;

        println!("  Signing...");
        let (is_ecc, _, sig_bytes) = sign_with_persistent_key(context, test_data, handle_str)?;
        let sig_hex = hex::encode(&sig_bytes);

        println!("  Verifying...");
        cmd_verify(context, test_data, handle_str, &sig_hex)?;

        // Verify that a tampered message is rejected.
        println!("  Verifying tampered message (should fail)...");
        match cmd_verify(context, "tampered-message", handle_str, &sig_hex) {
            Err(_) => println!("  Tampered message correctly rejected [OK]"),
            Ok(_) => anyhow::bail!("Tampered message was incorrectly accepted for {} key", algo),
        }

        let _ = is_ecc; // used implicitly via sig_bytes encoding

        println!("  Deleting test key...");
        cmd_key_delete(context, handle_str)?;

        println!("  {} sign+verify [OK]", algo.to_uppercase());
    }

    println!("\nSign + Verify roundtrip [OK]");
    Ok(())
}

/// Test sealing and unsealing data against a PCR policy.
fn cmd_test_seal_unseal(context: &mut TpmContext) -> Result<()> {
    let path = format!("/tmp/tpm-ops-sealed-test-{}.blob", std::process::id());
    let payload = "sealed-roundtrip-test";

    println!("  Sealing test payload...");
    cmd_seal(context, payload, "0", &path)?;

    println!("  Unsealing with matching PCR policy...");
    let unsealed = unseal_from_file(context, &path, "0")?;
    if unsealed != payload.as_bytes() {
        anyhow::bail!("Unsealed payload mismatch");
    }
    println!("  Roundtrip payload match [OK]");

    println!("  Unsealing with wrong PCR selection (should fail)...");
    match unseal_from_file(context, &path, "1") {
        Err(_) => println!("  Wrong PCR selection correctly rejected [OK]"),
        Ok(_) => anyhow::bail!("Expected unseal to fail with wrong PCR selection"),
    }

    let _ = std::fs::remove_file(&path);
    println!("\nSeal + Unseal roundtrip [OK]");
    Ok(())
}

/// Test TPM2_Quote + verify roundtrip with an auto-generated nonce.
fn cmd_test_quote(context: &mut TpmContext) -> Result<()> {
    let path = format!("/tmp/tpm-ops-quote-test-{}.blob", std::process::id());

    println!("  Generating RSA quote over PCR 0...");
    cmd_quote(context, "0", None, "rsa", Some(&path))?;

    println!("  Verifying quote...");
    cmd_quote_verify(context, &path)?;

    let _ = std::fs::remove_file(&path);
    println!("\nTPM Quote + Verify roundtrip [OK]");
    Ok(())
}
