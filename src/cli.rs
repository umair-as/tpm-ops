use clap::{Parser, Subcommand};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(name = "tpm-ops")]
#[command(about = "TPM 2.0 operations tool for Infineon SLB9672", long_about = None)]
#[command(version = VERSION)]
pub(crate) struct Cli {
    /// TCTI string (e.g. device:/dev/tpmrm0, swtpm:path=/tmp/swtpm.sock)
    #[arg(short, long, default_value = "device:/dev/tpmrm0")]
    pub tcti: String,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Display TPM information and capabilities
    Info,

    /// Run TPM self-test and report health status
    Selftest {
        /// Run full self-test (slower but more thorough)
        #[arg(short, long)]
        full: bool,
    },

    /// Generate random bytes using TPM TRNG
    Random {
        /// Number of bytes to generate (1-48)
        #[arg(short, long, default_value = "32")]
        bytes: usize,
    },

    /// Read PCR values, or extend/reset a PCR
    Pcr {
        /// PCR index to read (0-23)
        #[arg(short, long, default_value = "0")]
        index: u8,

        /// Hash algorithm (sha256 or sha1)
        #[arg(short, long, default_value = "sha256")]
        algo: String,

        #[command(subcommand)]
        action: Option<PcrAction>,
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

        /// Persistent key handle to sign with (e.g. 0x81000001)
        #[arg(short, long)]
        key: Option<String>,

        /// PCR list the signing key's auth policy was bound to at creation
        /// time (comma-separated, SHA-256 bank), e.g. 0,7. Required for
        /// policy-bound keys; the TPM — not this client — decides whether
        /// current PCR state satisfies the policy.
        #[arg(long)]
        policy_pcrs: Option<String>,
    },

    /// Verify a signature using a persistent TPM key
    Verify {
        /// Data that was signed
        data: String,

        /// Persistent key handle (e.g. 0x81000001)
        #[arg(short, long)]
        key: String,

        /// Signature hex: raw bytes for RSA; R||S concatenated for ECC (64 bytes / 128 hex chars)
        #[arg(short, long)]
        sig: String,
    },

    /// Seal data to current PCR state and save sealed blob to disk
    Seal {
        /// Data to seal
        data: String,

        /// PCR list (comma-separated, SHA-256 bank), e.g. 0,7
        #[arg(short, long)]
        pcrs: String,

        /// Output file path for sealed blob
        #[arg(short, long)]
        out: String,
    },

    /// Unseal data from a sealed blob if PCR policy is satisfied
    Unseal {
        /// Input sealed blob file path
        #[arg(short = 'i', long = "in", alias = "input")]
        input: String,

        /// PCR list (comma-separated, SHA-256 bank), e.g. 0,7
        #[arg(short, long)]
        pcrs: String,
    },

    /// Generate a TPM quote (TPM2_Quote) over selected PCRs
    Quote {
        /// PCR list (comma-separated, SHA-256 bank), e.g. 0,7
        #[arg(short, long, default_value = "0,7")]
        pcrs: String,

        /// Nonce as hex string, 16-64 bytes (32 random bytes if omitted)
        #[arg(short, long)]
        nonce: Option<String>,

        /// Signing algorithm for the ephemeral AK: rsa or ecc
        #[arg(short, long, default_value = "rsa")]
        algo: String,

        /// Output file path for the quote blob (prints to stdout if omitted)
        #[arg(short, long)]
        out: Option<String>,
    },

    /// Verify a quote blob produced by the quote command
    QuoteVerify {
        /// Path to the quote blob file
        input: String,

        /// Expected challenge nonce as hex, 16-64 bytes (must come from the verifier)
        #[arg(long)]
        nonce: String,

        /// Trusted SHA-256 fingerprint of the AK public area
        #[arg(long)]
        ak_pub_sha256: String,

        /// Expected PCR list (comma-separated, SHA-256 bank), e.g. 0,7
        #[arg(long)]
        pcrs: String,
    },

    /// Manage persistent TPM keys
    #[command(subcommand)]
    Key(KeyCommands),

    /// Run all tests
    Test,

    /// Show version and build information
    Version,
}

#[derive(Subcommand)]
pub(crate) enum PcrAction {
    /// Extend a PCR with the SHA-256 hash of the given data (irreversible until reboot)
    Extend {
        /// PCR index to extend (0-23)
        #[arg(short, long)]
        index: u8,

        /// Data to hash and extend into the PCR
        #[arg(short, long)]
        data: String,

        /// Allow extending a boot-measurement PCR (0-15) outside {16, 23}
        #[arg(long)]
        force: bool,
    },

    /// Reset a PCR to its default value (only PCR 16 and 23 from locality 0)
    Reset {
        /// PCR index to reset (0-23)
        #[arg(short, long)]
        index: u8,
    },
}

#[derive(Subcommand)]
pub(crate) enum KeyCommands {
    /// Create a signing key and persist it in the TPM
    Create {
        /// Algorithm: rsa or ecc
        #[arg(short, long, default_value = "rsa")]
        algo: String,

        /// Persistent handle (e.g. 0x81000001)
        #[arg(short, long)]
        persist: String,

        /// Bind the key's auth policy to the current value of these PCRs
        /// (comma-separated, SHA-256 bank), e.g. 0,7. The TPM will refuse to
        /// use the key unless the same PCR list is supplied at sign time and
        /// the PCR state still matches.
        #[arg(long)]
        policy_pcrs: Option<String>,
    },

    /// List persistent key handles
    List,

    /// Delete a persistent key
    Delete {
        /// Persistent handle to remove (e.g. 0x81000001)
        handle: String,
    },

    /// Export the public key in PEM format
    ExportPub {
        /// Persistent handle (e.g. 0x81000001)
        handle: String,
    },
}
