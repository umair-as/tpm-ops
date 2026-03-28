//! TPM 2.0 operations tool for Infineon SLB9672

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use log::info;
use std::str::FromStr;

use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    constants::{PropertyTag, SessionType},
    handles::KeyHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
    },
    structures::{
        EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, MaxBuffer,
        PcrSelectionListBuilder, PcrSlot, PublicBuilder, PublicEccParametersBuilder,
        PublicKeyRsa, PublicRsaParametersBuilder, RsaExponent, RsaScheme, SignatureScheme,
        SymmetricDefinition,
    },
    tcti_ldr::{DeviceConfig, TctiNameConf},
    Context as TpmContext,
};

#[derive(Parser)]
#[command(name = "tpm-ops")]
#[command(about = "TPM 2.0 operations tool for Infineon SLB9672", long_about = None)]
struct Cli {
    /// TCTI device path
    #[arg(short, long, default_value = "/dev/tpmrm0")]
    device: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display TPM information and capabilities
    Info,

    /// Generate random bytes using TPM TRNG
    Random {
        /// Number of bytes to generate (1-48)
        #[arg(short, long, default_value = "32")]
        bytes: usize,
    },

    /// Read PCR values
    Pcr {
        /// PCR index to read (0-23)
        #[arg(short, long, default_value = "0")]
        index: u8,

        /// Hash algorithm (sha256 or sha1)
        #[arg(short, long, default_value = "sha256")]
        algo: String,
    },

    /// Hash data using TPM
    Hash {
        /// Data to hash (hex string or text)
        data: String,

        /// Hash algorithm (sha256, sha384, sha1)
        #[arg(short, long, default_value = "sha256")]
        algo: String,
    },

    /// Create a key pair in TPM and sign data
    Sign {
        /// Data to sign
        data: String,

        /// Use ECC instead of RSA
        #[arg(short, long)]
        ecc: bool,
    },

    /// Run all tests
    Test,
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    let device_config =
        DeviceConfig::from_str(&cli.device).context("Invalid TCTI device path")?;
    let tcti_conf = TctiNameConf::Device(device_config);

    let mut context = TpmContext::new(tcti_conf).context("Failed to create TPM context")?;

    match cli.command {
        Commands::Info => cmd_info(&mut context),
        Commands::Random { bytes } => cmd_random(&mut context, bytes),
        Commands::Pcr { index, algo } => cmd_pcr(&mut context, index, &algo),
        Commands::Hash { data, algo } => cmd_hash(&mut context, &data, &algo),
        Commands::Sign { data, ecc } => cmd_sign(&mut context, &data, ecc),
        Commands::Test => cmd_test(&mut context),
    }
}

fn get_property(context: &mut TpmContext, tag: PropertyTag) -> Result<Option<u32>> {
    context
        .get_tpm_property(tag)
        .context("Failed to read TPM property")
}

fn cmd_info(context: &mut TpmContext) -> Result<()> {
    info!("=== TPM Information ===");

    // Manufacturer is the critical field — fail if unreadable
    let manufacturer = get_property(context, PropertyTag::Manufacturer)?
        .ok_or_else(|| anyhow::anyhow!("TPM did not report manufacturer — device may be unresponsive"))?;

    let mfr_bytes = manufacturer.to_be_bytes();
    let mfr_str: String = mfr_bytes
        .iter()
        .filter(|&&b| b != 0)
        .map(|&b| b as char)
        .collect();
    println!("Manufacturer: {} (0x{:08X})", mfr_str, manufacturer);

    // Vendor strings are optional — print what we can
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

fn cmd_random(context: &mut TpmContext, num_bytes: usize) -> Result<()> {
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

fn cmd_pcr(context: &mut TpmContext, index: u8, algo: &str) -> Result<()> {
    if index > 23 {
        anyhow::bail!("PCR index must be 0-23");
    }

    let hash_algo = parse_hash_algo(algo)?;
    let pcr_slot = PcrSlot::try_from(index as u32).context("Invalid PCR slot")?;

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

fn cmd_hash(context: &mut TpmContext, data: &str, algo: &str) -> Result<()> {
    let hash_algo = parse_hash_algo(algo)?;

    // Try to parse as hex, otherwise use as UTF-8
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

/// RAII guard that flushes a transient TPM key handle on drop
struct KeyGuard<'a> {
    context: &'a mut TpmContext,
    handle: Option<KeyHandle>,
}

impl<'a> KeyGuard<'a> {
    fn new(context: &'a mut TpmContext, handle: KeyHandle) -> Self {
        Self {
            context,
            handle: Some(handle),
        }
    }

    fn handle(&self) -> KeyHandle {
        self.handle.expect("handle already taken")
    }
}

impl Drop for KeyGuard<'_> {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            let _ = self.context.flush_context(h.into());
        }
    }
}

fn cmd_sign(context: &mut TpmContext, data: &str, use_ecc: bool) -> Result<()> {
    let session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .context("Failed to start auth session")?
        .ok_or_else(|| anyhow::anyhow!("Auth session creation returned None"))?;

    context.set_sessions((Some(session), None, None));

    info!(
        "Creating {} primary key in TPM...",
        if use_ecc { "ECC" } else { "RSA" }
    );

    let primary_key = if use_ecc {
        create_ecc_primary(context)?
    } else {
        create_rsa_primary(context)?
    };

    // Guard ensures flush_context runs even if hash/sign fails below
    let guard = KeyGuard::new(context, primary_key);

    info!("Primary key created: {:?}", guard.handle());

    let data_bytes = data.as_bytes();
    let buffer = MaxBuffer::try_from(data_bytes).context("Data too large")?;

    // hash() returns both digest and the ticket needed for sign()
    let (digest, ticket) = guard
        .context
        .hash(buffer, HashingAlgorithm::Sha256, Hierarchy::Null)
        .context("Failed to hash data")?;

    info!("Signing data...");

    let scheme = if use_ecc {
        SignatureScheme::EcDsa {
            hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
        }
    } else {
        SignatureScheme::RsaSsa {
            hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
        }
    };

    let signature = guard
        .context
        .sign(guard.handle(), digest.clone(), scheme, ticket)
        .context("Failed to sign data")?;

    println!("\nData: {}", data);
    println!("Digest (SHA256): {}", hex::encode(digest.value()));
    println!("\nSignature:");

    match signature {
        tss_esapi::structures::Signature::RsaSsa(sig) => {
            println!("Algorithm: RSA-SSA");
            println!("Signature: {}", hex::encode(sig.signature().value()));
        }
        tss_esapi::structures::Signature::EcDsa(sig) => {
            println!("Algorithm: ECDSA");
            println!("R: {}", hex::encode(sig.signature_r().value()));
            println!("S: {}", hex::encode(sig.signature_s().value()));
        }
        _ => println!("{:?}", signature),
    }

    // guard drops here, flushing the key handle
    println!("\nKey created, data signed, key flushed [OK]");
    Ok(())
}

fn create_rsa_primary(context: &mut TpmContext) -> Result<KeyHandle> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()
        .context("Failed to build object attributes")?;

    let rsa_params = PublicRsaParametersBuilder::new()
        .with_scheme(RsaScheme::RsaSsa(HashScheme::new(
            HashingAlgorithm::Sha256,
        )))
        .with_key_bits(RsaKeyBits::Rsa2048)
        .with_exponent(RsaExponent::default())
        .with_is_signing_key(true)
        .with_is_decryption_key(false)
        .with_restricted(false)
        .build()
        .context("Failed to build RSA parameters")?;

    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(rsa_params)
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .context("Failed to build public template")?;

    let result = context
        .create_primary(Hierarchy::Owner, public, None, None, None, None)
        .context("Failed to create RSA primary key")?;

    Ok(result.key_handle)
}

fn create_ecc_primary(context: &mut TpmContext) -> Result<KeyHandle> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()
        .context("Failed to build object attributes")?;

    let ecc_params = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_curve(EccCurve::NistP256)
        .with_is_signing_key(true)
        .with_is_decryption_key(false)
        .with_restricted(false)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()
        .context("Failed to build ECC parameters")?;

    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .context("Failed to build public template")?;

    let result = context
        .create_primary(Hierarchy::Owner, public, None, None, None, None)
        .context("Failed to create ECC primary key")?;

    Ok(result.key_handle)
}

fn cmd_test(context: &mut TpmContext) -> Result<()> {
    println!("=== TPM Test Suite ===\n");

    println!("--- Test 1: TPM Info ---");
    cmd_info(context)?;
    println!();

    println!("--- Test 2: Random Number Generation ---");
    cmd_random(context, 32)?;
    println!();

    println!("--- Test 3: PCR Read ---");
    cmd_pcr(context, 0, "sha256")?;
    println!();

    println!("--- Test 4: TPM Hash ---");
    cmd_hash(context, "Hello, TPM!", "sha256")?;
    println!();

    println!("--- Test 5: RSA Signing ---");
    cmd_sign(context, "Test message for RSA signing", false)?;
    println!();

    println!("--- Test 6: ECC Signing ---");
    cmd_sign(context, "Test message for ECC signing", true)?;
    println!();

    println!("=== All Tests Passed! ===");
    Ok(())
}

fn parse_hash_algo(algo: &str) -> Result<HashingAlgorithm> {
    match algo.to_lowercase().as_str() {
        "sha256" => Ok(HashingAlgorithm::Sha256),
        "sha1" => Ok(HashingAlgorithm::Sha1),
        "sha384" => Ok(HashingAlgorithm::Sha384),
        _ => anyhow::bail!("Unsupported hash algorithm: {}", algo),
    }
}
