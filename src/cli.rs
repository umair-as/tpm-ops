use clap::{Parser, Subcommand};
use clap_complete::Shell;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const GIT_HASH: &str = env!("TPM_OPS_GIT_HASH");

fn long_version() -> &'static str {
    Box::leak(format!("{}\ngit: {}", VERSION, GIT_HASH).into_boxed_str())
}

#[derive(Parser)]
#[command(name = "tpm-ops")]
#[command(about = "TPM 2.0 operations tool for Infineon SLB9672", long_about = None)]
#[command(version = VERSION)]
#[command(long_version = long_version())]
#[command(
    after_help = "Exit codes: 0 = success, 1 = runtime/TPM error, 2 = usage error.\n\
Run 'tpm-ops <command> --help' for examples specific to that command."
)]
pub(crate) struct Cli {
    /// TCTI string (e.g. device:/dev/tpmrm0, swtpm:path=/tmp/swtpm.sock)
    #[arg(short, long, default_value = "device:/dev/tpmrm0", global = true)]
    pub tcti: String,

    /// Emit machine-readable JSON on stdout instead of human-readable text.
    /// Logs and progress always go to stderr, so this is safe to pipe into `jq`
    /// with no stderr redirect.
    #[arg(long, global = true)]
    pub json: bool,

    /// Increase log verbosity (-v info, -vv debug, -vvv trace). Overridden by RUST_LOG.
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Silence everything but errors.
    #[arg(short = 'q', long = "quiet", global = true, conflicts_with = "verbose")]
    pub quiet: bool,

    /// Colorize status/error output: auto (default), always, or never. Honours NO_COLOR.
    #[arg(long, default_value = "auto", global = true)]
    pub color: String,

    /// Assume "yes" to any interactive confirmation (e.g. `key delete`).
    /// Implied automatically when stdin is not a TTY or --json is set.
    #[arg(short = 'y', long = "yes", global = true)]
    pub yes: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Display TPM information and capabilities
    #[command(after_help = "Example: tpm-ops info")]
    Info,

    /// Run TPM self-test and report health status
    ///
    /// Not to be confused with the `test` subcommand (the live TPM/swtpm
    /// integration suite) or `cargo test` (unit tests) — see CLAUDE.md.
    #[command(after_help = "Example: tpm-ops selftest --full")]
    Selftest {
        /// Run full self-test (slower but more thorough)
        #[arg(short, long)]
        full: bool,
    },

    /// Generate random bytes using TPM TRNG
    #[command(after_help = "Example: tpm-ops random --bytes 32")]
    Random {
        /// Number of bytes to generate (1-48)
        #[arg(short, long, default_value = "32")]
        bytes: usize,
    },

    /// Read PCR values, or extend/reset a PCR
    #[command(
        after_help = "Examples:\n  tpm-ops pcr -i 0\n  tpm-ops pcr -i 23 extend -d \"event\" \n  tpm-ops pcr -i 23 reset"
    )]
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
    #[command(
        after_help = "Examples:\n  tpm-ops hash \"hello\"\n  tpm-ops hash --file /path/to/file\n  cat file | tpm-ops hash -"
    )]
    Hash {
        /// Data to hash (hex string or text). Use "-" to read from stdin.
        data: Option<String>,

        /// Read data to hash from a file instead of the positional argument
        #[arg(long, conflicts_with = "data")]
        file: Option<String>,

        /// Hash algorithm (sha256, sha384, sha1)
        #[arg(short, long, default_value = "sha256")]
        algo: String,
    },

    /// Create a key pair in TPM and sign data
    #[command(
        after_help = "Examples:\n  tpm-ops sign \"hello\"\n  tpm-ops sign \"hello\" --key 0x81000001\n  tpm-ops sign --file /path/to/file --key 0x81000001"
    )]
    Sign {
        /// Data to sign. Use "-" to read from stdin.
        data: Option<String>,

        /// Read data to sign from a file instead of the positional argument
        #[arg(long, conflicts_with = "data")]
        file: Option<String>,

        /// Algorithm for an ephemeral key: rsa or ecc (canonical form of --ecc)
        #[arg(long, conflicts_with = "ecc")]
        algo: Option<String>,

        /// Use ECC instead of RSA (deprecated: use --algo ecc)
        #[arg(short, long, hide = true)]
        ecc: bool,

        /// Persistent key handle to sign with (e.g. 0x81000001)
        #[arg(short, long, alias = "handle")]
        key: Option<String>,

        /// PCR list the signing key's auth policy was bound to at creation
        /// time (comma-separated, SHA-256 bank), e.g. 0,7. Required for
        /// policy-bound keys; the TPM — not this client — decides whether
        /// current PCR state satisfies the policy.
        #[arg(long)]
        policy_pcrs: Option<String>,
    },

    /// Verify a signature using a persistent TPM key
    #[command(
        after_help = "Example: tpm-ops verify \"hello\" -k 0x81000001 -s <hex-signature>\n         tpm-ops verify \"hello\" -k 0x81000001 --sig-file sig.hex"
    )]
    Verify {
        /// Data that was signed
        data: String,

        /// Persistent key handle (e.g. 0x81000001)
        #[arg(short, long, alias = "handle")]
        key: String,

        /// Signature hex: raw bytes for RSA; R||S concatenated for ECC (64 bytes / 128 hex chars)
        #[arg(short, long, conflicts_with = "sig_file")]
        sig: Option<String>,

        /// Read the signature hex from a file instead of the command line
        /// (use "-" for stdin) — useful since an RSA-2048 signature is a
        /// 512-character hex string.
        #[arg(long)]
        sig_file: Option<String>,
    },

    /// Seal data to current PCR state and save sealed blob to disk
    #[command(after_help = "Example: tpm-ops seal \"secret\" --pcrs 0,7 --out secret.blob")]
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
    #[command(after_help = "Example: tpm-ops unseal --in secret.blob --pcrs 0,7")]
    Unseal {
        /// Input sealed blob file path
        #[arg(short = 'i', long = "in", alias = "input")]
        input: String,

        /// PCR list (comma-separated, SHA-256 bank), e.g. 0,7
        #[arg(short, long)]
        pcrs: String,
    },

    /// Generate a TPM quote (TPM2_Quote) over selected PCRs
    #[command(after_help = "Example: tpm-ops quote --pcrs 0,7 --out quote.blob")]
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
    ///
    /// This deliberately trusts nothing carried inside the blob itself: you
    /// must independently supply --nonce (the challenge you issued),
    /// --pcrs (the selection you expect), and --ak-pub-sha256 (a SHA-256
    /// fingerprint of the attestation key's public area, obtained ahead of
    /// time through a channel you already trust — e.g. provisioned when the
    /// device was enrolled, or printed by `quote-fingerprint` on a blob from
    /// a key you already trust for another reason). See docs/security-model.md
    /// "Quote trust model" for why blob-internal values are never trusted.
    #[command(
        after_help = "Example: tpm-ops quote-verify quote.blob --nonce <hex> --ak-pub-sha256 <hex> --pcrs 0,7"
    )]
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

    /// Print a quote blob's AK public-key fingerprint
    ///
    /// This only tells you what fingerprint is in the blob — it does NOT
    /// mean that fingerprint is trustworthy. Only trust a fingerprint you
    /// obtained through a separate, out-of-band channel; see `quote-verify --help`.
    #[command(after_help = "Example: tpm-ops quote-fingerprint quote.blob")]
    QuoteFingerprint {
        /// Path to the quote blob file
        input: String,
    },

    /// Manage persistent TPM keys
    #[command(subcommand)]
    Key(KeyCommands),

    /// Run the live TPM/swtpm integration suite (not `cargo test` — see CLAUDE.md)
    #[command(alias = "selftest-suite")]
    Test,

    /// Show version and build information
    Version,

    /// Generate shell completions
    #[command(
        hide = true,
        after_help = "Example: tpm-ops completions bash > /etc/bash_completion.d/tpm-ops"
    )]
    Completions {
        /// Shell to generate completions for
        shell: Shell,
    },
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
    #[command(after_help = "Example: tpm-ops key create --algo ecc --persist 0x81000001")]
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
    #[command(after_help = "Example: tpm-ops key list")]
    List,

    /// Delete a persistent key
    #[command(after_help = "Example: tpm-ops key delete 0x81000001")]
    Delete {
        /// Persistent handle to remove (e.g. 0x81000001)
        handle: Option<String>,

        /// Persistent handle to remove (alternative to the positional form)
        #[arg(short = 'k', long, conflicts_with = "handle")]
        handle_flag: Option<String>,
    },

    /// Export the public key in PEM format
    #[command(after_help = "Example: tpm-ops key export-pub 0x81000001")]
    ExportPub {
        /// Persistent handle (e.g. 0x81000001)
        handle: Option<String>,

        /// Persistent handle (alternative to the positional form)
        #[arg(short = 'k', long, conflicts_with = "handle")]
        handle_flag: Option<String>,
    },
}
