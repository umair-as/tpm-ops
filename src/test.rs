use anyhow::{Context, Result};
use tss_esapi::{interface_types::algorithm::HashingAlgorithm, Context as TpmContext};

use crate::commands::{
    cmd_hash, cmd_info, cmd_pcr, cmd_random, cmd_selftest, hash_bytes, pcr_extend, pcr_reset,
    random_bytes, read_pcr_digests,
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
    cmd_selftest(context, false, false)?;
    println!();

    println!("--- Test 2: TPM Info ---");
    cmd_info(context, false)?;
    println!();

    println!("--- Test 3: Random Number Generation ---");
    cmd_random(context, 32, false)?;
    let random = random_bytes(context, 32)?;
    if random.len() != 32 || random.iter().all(|&byte| byte == 0) {
        anyhow::bail!("TPM random output failed length/non-zero validation");
    }
    println!("Random output length/non-zero validation [OK]");
    println!();

    println!("--- Test 4: PCR Read ---");
    cmd_pcr(context, 0, "sha256", false)?;
    let pcr_digests = read_pcr_digests(context, 0, "sha256")?;
    if pcr_digests.len() != 1 || pcr_digests[0].len() != 32 {
        anyhow::bail!("PCR read returned an unexpected SHA-256 digest shape");
    }
    println!("PCR digest shape validation [OK]");
    println!();

    println!("--- Test 5: TPM Hash ---");
    cmd_hash(context, Some("Hello, TPM!"), None, "sha256", false)?;
    let digest = hash_bytes(context, b"Hello, TPM!", HashingAlgorithm::Sha256)?;
    let expected = hex::decode("4c48a67be006062fd11a2f0333d3c6daf5a924cbc3ffc04a1c64625011e51e89")?;
    if digest != expected {
        anyhow::bail!("TPM SHA-256 result did not match the known-answer vector");
    }
    println!("SHA-256 known-answer validation [OK]");
    println!();

    println!("--- Test 6: RSA Signing (ephemeral) ---");
    cmd_sign(
        context,
        Some("Test message for RSA signing"),
        None,
        false,
        None,
        None,
        false,
    )?;
    println!();

    println!("--- Test 7: ECC Signing (ephemeral) ---");
    cmd_sign(
        context,
        Some("Test message for ECC signing"),
        None,
        true,
        None,
        None,
        false,
    )?;
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

    println!("--- Test 12: Policy-Bound Key (PCR Policy Session) ---");
    cmd_test_policy_bound_key(context)?;
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
    cmd_key_create(context, "rsa", test_handle, None, false)?;

    let test_result = {
        println!("  Signing with persistent key...");
        cmd_sign(
            context,
            Some("persistent-key-test"),
            None,
            false,
            Some(test_handle),
            None,
            false,
        )
    };

    println!("  Deleting test key...");
    let cleanup_result = cmd_key_delete(context, test_handle, true, false);
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
        cmd_key_create(context, algo, handle_str, None, false)?;

        let test_result = (|| {
            println!("  Signing...");
            let (_, _, sig_bytes) = sign_with_persistent_key(context, test_data, handle_str, None)?;
            let sig_hex = hex::encode(&sig_bytes);

            println!("  Verifying...");
            cmd_verify(context, test_data, handle_str, &sig_hex, false)?;

            println!("  Verifying tampered message (should fail)...");
            let error = match cmd_verify(context, "tampered-message", handle_str, &sig_hex, false) {
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
        let cleanup_result = cmd_key_delete(context, handle_str, true, false);
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
        cmd_seal(context, payload, "0", &path, false)?;

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

    // Real negative: an actual PCR state change (not just a client-rejected wrong
    // selection) must also invalidate an outstanding seal.
    let path23 = format!("/tmp/tpm-ops-sealed-test-pcr23-{}.blob", std::process::id());
    let payload23 = "sealed-real-pcr-change-test";

    let test_result_23 = (|| {
        println!("  Resetting PCR 23 to establish a known baseline...");
        pcr_reset(context, 23)?;

        println!("  Sealing test payload to PCR 23...");
        cmd_seal(context, payload23, "23", &path23, false)?;

        println!("  Extending PCR 23 (real state change)...");
        pcr_extend(context, 23, b"tamper-seal")?;

        println!("  Unsealing after PCR 23 changed (should fail)...");
        let error = match unseal_from_file(context, &path23, "23") {
            Ok(_) => anyhow::bail!("Unseal succeeded after PCR 23 state changed"),
            Err(error) => error,
        };
        if !error.to_string().contains("does not satisfy blob policy") {
            anyhow::bail!(
                "Post-extend unseal test failed for an unexpected reason: {:#}",
                error
            );
        }
        println!("  Unseal correctly rejected after real PCR 23 change [OK]");
        Ok(())
    })();

    let cleanup_result_23 =
        remove_test_file(&path23).and_then(|()| pcr_reset(context, 23).map(|_| ()));
    combine_test_and_cleanup(test_result_23, cleanup_result_23, &path23)?;

    println!("\nSeal + Unseal roundtrip [OK]");
    Ok(())
}

/// Test TPM2_Quote + verify with verifier-supplied expectations.
fn cmd_test_quote(context: &mut TpmContext) -> Result<()> {
    let path = format!("/tmp/tpm-ops-quote-test-{}.blob", std::process::id());
    let nonce = "4b3f0d6a8824f25cf3b7e9704ab28af00f6b568d20e193274c11d74368b5f18e";

    let test_result = (|| {
        println!("  Generating RSA quote over PCR 0...");
        cmd_quote(context, "0", Some(nonce), "rsa", Some(&path), false)?;
        let ak_fingerprint = quote_public_fingerprint_from_file(context, &path)?;

        println!("  Verifying quote with trusted expectations...");
        cmd_quote_verify(context, &path, nonce, &ak_fingerprint, "0", false)?;

        println!("  Verifying a mismatched challenge is rejected...");
        let wrong_nonce = "0000000000000000000000000000000000000000000000000000000000000000";
        let error = match cmd_quote_verify(context, &path, wrong_nonce, &ak_fingerprint, "0", false)
        {
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
        let error = match cmd_quote_verify(context, &path, nonce, untrusted_fingerprint, "0", false)
        {
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
        let error = match cmd_quote_verify(context, &path, nonce, &ak_fingerprint, "1", false) {
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

/// Test a PCR-policy-bound signing key: sign succeeds while PCR 23 matches the
/// state captured at key-creation time, fails after a real `pcr extend`, and
/// succeeds again after `pcr reset` — proving the gate is state-driven, not a
/// one-way latch. Also re-signs several times in this one process, which is
/// where a session leak in T1's PolicyPCR plumbing would show up on real
/// hardware (swtpm is more forgiving of leaked session slots).
fn cmd_test_policy_bound_key(context: &mut TpmContext) -> Result<()> {
    let test_handle = "0x81000FFC";
    let test_handle_val: u32 = 0x81000FFC;
    let test_data = "policy-bound-sign-test";

    if persistent_handle_exists(context, test_handle_val)? {
        anyhow::bail!(
            "Test handle {} is occupied; refusing to delete an unverified persistent key",
            test_handle
        );
    }

    let test_result = (|| {
        println!("  Resetting PCR 23 to establish a known baseline...");
        let baseline = pcr_reset(context, 23)?;
        println!("  PCR 23 baseline: {}", hex::encode(&baseline));

        println!("  Creating policy-bound ECC key (PCR 23)...");
        cmd_key_create(context, "ecc", test_handle, Some("23"), false)?;

        println!("  Signing with matching PCR policy (should succeed)...");
        let (_, _, sig_bytes) =
            sign_with_persistent_key(context, test_data, test_handle, Some("23"))?;
        let sig_hex = hex::encode(&sig_bytes);

        println!("  Verifying signature round-trips...");
        cmd_verify(context, test_data, test_handle, &sig_hex, false)?;

        println!("  Signing 5 more times in this process (session-leak check)...");
        for attempt in 1..=5 {
            sign_with_persistent_key(context, test_data, test_handle, Some("23")).with_context(
                || {
                    format!(
                        "Repeat policy sign #{} failed (possible session leak)",
                        attempt
                    )
                },
            )?;
        }
        println!("  5 consecutive policy signs succeeded [OK]");

        println!("  Extending PCR 23 (real state change)...");
        pcr_extend(context, 23, b"tamper-policy-key")?;

        println!("  Signing after PCR 23 changed (should fail)...");
        let error = match sign_with_persistent_key(context, test_data, test_handle, Some("23")) {
            Ok(_) => anyhow::bail!("Sign succeeded after PCR 23 state changed"),
            Err(error) => error,
        };
        let expected_prefix =
            "Sign refused by TPM: current PCR state does not satisfy the key's policy";
        if !error.to_string().starts_with(expected_prefix) {
            anyhow::bail!(
                "Post-extend sign test failed for an unexpected reason: {:#}",
                error
            );
        }
        println!("  Sign correctly rejected after real PCR 23 change [OK]");

        println!("  Resetting PCR 23 and signing again (should succeed)...");
        pcr_reset(context, 23)?;
        sign_with_persistent_key(context, test_data, test_handle, Some("23"))
            .context("Sign failed after PCR 23 was reset back to baseline")?;
        println!("  Sign correctly succeeds again after reset [OK]");

        Ok(())
    })();

    println!("  Deleting test key...");
    let cleanup_result = cmd_key_delete(context, test_handle, true, false)
        .and_then(|()| pcr_reset(context, 23).map(|_| ()));
    combine_test_and_cleanup(test_result, cleanup_result, test_handle)?;

    println!("\nPolicy-bound key [OK]");
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
