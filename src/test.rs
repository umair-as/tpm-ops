use anyhow::Result;
use tss_esapi::{interface_types::algorithm::HashingAlgorithm, Context as TpmContext};

use crate::commands::{
    cmd_hash, cmd_info, cmd_pcr, cmd_random, cmd_selftest, hash_bytes, random_bytes,
    read_pcr_digests,
};
use crate::keys::{cmd_key_create, cmd_key_delete};
use crate::quote::{cmd_quote, cmd_quote_verify, quote_public_fingerprint_from_file};
use crate::seal::{cmd_seal, unseal_from_file};
use crate::sign::{cmd_sign, sign_with_persistent_key};
use crate::tpm::persistent_handle_exists;
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
    let random = random_bytes(context, 32)?;
    if random.len() != 32 || random.iter().all(|&byte| byte == 0) {
        anyhow::bail!("TPM random output failed length/non-zero validation");
    }
    println!("Random output length/non-zero validation [OK]");
    println!();

    println!("--- Test 4: PCR Read ---");
    cmd_pcr(context, 0, "sha256")?;
    let pcr_digests = read_pcr_digests(context, 0, "sha256")?;
    if pcr_digests.len() != 1 || pcr_digests[0].len() != 32 {
        anyhow::bail!("PCR read returned an unexpected SHA-256 digest shape");
    }
    println!("PCR digest shape validation [OK]");
    println!();

    println!("--- Test 5: TPM Hash ---");
    cmd_hash(context, "Hello, TPM!", "sha256")?;
    let digest = hash_bytes(context, b"Hello, TPM!", HashingAlgorithm::Sha256)?;
    let expected = hex::decode("4c48a67be006062fd11a2f0333d3c6daf5a924cbc3ffc04a1c64625011e51e89")?;
    if digest != expected {
        anyhow::bail!("TPM SHA-256 result did not match the known-answer vector");
    }
    println!("SHA-256 known-answer validation [OK]");
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

    if persistent_handle_exists(context, test_handle_val)? {
        anyhow::bail!(
            "Test handle {} is occupied; refusing to delete an unverified persistent key",
            test_handle
        );
    }

    println!("  Creating test RSA key...");
    cmd_key_create(context, "rsa", test_handle)?;

    let test_result = {
        println!("  Signing with persistent key...");
        cmd_sign(context, "persistent-key-test", false, Some(test_handle))
    };

    println!("  Deleting test key...");
    let cleanup_result = cmd_key_delete(context, test_handle);
    combine_test_and_cleanup(test_result, cleanup_result, test_handle)?;

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
        if persistent_handle_exists(context, handle_val)? {
            anyhow::bail!(
                "Test handle {} is occupied; refusing to delete an unverified persistent key",
                handle_str
            );
        }

        println!("  Creating test {} key...", algo.to_uppercase());
        cmd_key_create(context, algo, handle_str)?;

        let test_result = (|| {
            println!("  Signing...");
            let (_, _, sig_bytes) = sign_with_persistent_key(context, test_data, handle_str)?;
            let sig_hex = hex::encode(&sig_bytes);

            println!("  Verifying...");
            cmd_verify(context, test_data, handle_str, &sig_hex)?;

            println!("  Verifying tampered message (should fail)...");
            let error = match cmd_verify(context, "tampered-message", handle_str, &sig_hex) {
                Ok(()) => anyhow::bail!("Tampered message was incorrectly accepted"),
                Err(error) => error,
            };
            if !error.to_string().starts_with("Verification failed:") {
                anyhow::bail!(
                    "Tampered-message test failed for an unexpected reason: {:#}",
                    error
                );
            }
            println!("  Tampered message correctly rejected [OK]");
            Ok(())
        })();

        println!("  Deleting test key...");
        let cleanup_result = cmd_key_delete(context, handle_str);
        combine_test_and_cleanup(test_result, cleanup_result, handle_str)?;

        println!("  {} sign+verify [OK]", algo.to_uppercase());
    }

    println!("\nSign + Verify roundtrip [OK]");
    Ok(())
}

/// Test sealing and unsealing data against a PCR policy.
fn cmd_test_seal_unseal(context: &mut TpmContext) -> Result<()> {
    let path = format!("/tmp/tpm-ops-sealed-test-{}.blob", std::process::id());
    let payload = "sealed-roundtrip-test";

    let test_result = (|| {
        println!("  Sealing test payload...");
        cmd_seal(context, payload, "0", &path)?;

        println!("  Unsealing with matching PCR policy...");
        let unsealed = unseal_from_file(context, &path, "0")?;
        if unsealed != payload.as_bytes() {
            anyhow::bail!("Unsealed payload mismatch");
        }
        println!("  Roundtrip payload match [OK]");

        println!("  Unsealing with wrong PCR selection (should fail)...");
        let error = match unseal_from_file(context, &path, "1") {
            Ok(_) => anyhow::bail!("Wrong PCR selection was incorrectly accepted"),
            Err(error) => error,
        };
        if !error.to_string().starts_with("PCR selection mismatch:") {
            anyhow::bail!(
                "Wrong-PCR test failed for an unexpected reason: {:#}",
                error
            );
        }
        println!("  Wrong PCR selection correctly rejected [OK]");
        Ok(())
    })();

    let cleanup_result = remove_test_file(&path);
    combine_test_and_cleanup(test_result, cleanup_result, &path)?;
    println!("\nSeal + Unseal roundtrip [OK]");
    Ok(())
}

/// Test TPM2_Quote + verify with verifier-supplied expectations.
fn cmd_test_quote(context: &mut TpmContext) -> Result<()> {
    let path = format!("/tmp/tpm-ops-quote-test-{}.blob", std::process::id());
    let nonce = "4b3f0d6a8824f25cf3b7e9704ab28af00f6b568d20e193274c11d74368b5f18e";

    let test_result = (|| {
        println!("  Generating RSA quote over PCR 0...");
        cmd_quote(context, "0", Some(nonce), "rsa", Some(&path))?;
        let ak_fingerprint = quote_public_fingerprint_from_file(context, &path)?;

        println!("  Verifying quote with trusted expectations...");
        cmd_quote_verify(context, &path, nonce, &ak_fingerprint, "0")?;

        println!("  Verifying a mismatched challenge is rejected...");
        let wrong_nonce = "0000000000000000000000000000000000000000000000000000000000000000";
        let error = match cmd_quote_verify(context, &path, wrong_nonce, &ak_fingerprint, "0") {
            Ok(()) => anyhow::bail!("Mismatched quote nonce was incorrectly accepted"),
            Err(error) => error,
        };
        if !error
            .to_string()
            .contains("does not match the verifier's expected nonce")
        {
            anyhow::bail!(
                "Mismatched-nonce test failed for an unexpected reason: {:#}",
                error
            );
        }
        println!("  Mismatched challenge correctly rejected [OK]");

        println!("  Verifying an untrusted AK is rejected...");
        let untrusted_fingerprint =
            "0000000000000000000000000000000000000000000000000000000000000000";
        let error = match cmd_quote_verify(context, &path, nonce, untrusted_fingerprint, "0") {
            Ok(()) => anyhow::bail!("Untrusted AK was incorrectly accepted"),
            Err(error) => error,
        };
        if !error
            .to_string()
            .contains("AK public key fingerprint mismatch")
        {
            anyhow::bail!(
                "Untrusted-AK test failed for an unexpected reason: {:#}",
                error
            );
        }
        println!("  Untrusted AK correctly rejected [OK]");

        println!("  Verifying an unexpected PCR selection is rejected...");
        let error = match cmd_quote_verify(context, &path, nonce, &ak_fingerprint, "1") {
            Ok(()) => anyhow::bail!("Unexpected PCR selection was incorrectly accepted"),
            Err(error) => error,
        };
        if !error
            .to_string()
            .contains("Signed PCR selection does not match")
        {
            anyhow::bail!(
                "Unexpected-PCR test failed for an unexpected reason: {:#}",
                error
            );
        }
        println!("  Unexpected PCR selection correctly rejected [OK]");
        Ok(())
    })();

    let cleanup_result = remove_test_file(&path);
    combine_test_and_cleanup(test_result, cleanup_result, &path)?;
    println!("\nTPM Quote + Verify roundtrip [OK]");
    Ok(())
}

fn combine_test_and_cleanup(
    test_result: Result<()>,
    cleanup_result: Result<()>,
    resource: &str,
) -> Result<()> {
    match (test_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(test_error), Ok(())) => Err(test_error),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(test_error), Err(cleanup_error)) => anyhow::bail!(
            "{}; cleanup of {} also failed: {:#}",
            test_error,
            resource,
            cleanup_error
        ),
    }
}

fn remove_test_file(path: &str) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
