//! TPM 2.0 operations tool for Infineon SLB9672

mod cli;
mod commands;
mod keys;
mod pem;
mod quote;
mod seal;
mod sign;
mod test;
mod tpm;
mod verify;

use anyhow::{Context, Result};
use clap::Parser;
use std::str::FromStr;

use cli::{Cli, Commands, KeyCommands};
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    if matches!(cli.command, Commands::Version) {
        return commands::cmd_version();
    }

    let device_config =
        DeviceConfig::from_str(&cli.device).context("Invalid TCTI device path")?;
    let tcti_conf = TctiNameConf::Device(device_config);

    let mut context =
        tss_esapi::Context::new(tcti_conf).context("Failed to create TPM context")?;

    match cli.command {
        Commands::Info => commands::cmd_info(&mut context),
        Commands::Selftest { full } => commands::cmd_selftest(&mut context, full),
        Commands::Random { bytes } => commands::cmd_random(&mut context, bytes),
        Commands::Pcr { index, algo } => commands::cmd_pcr(&mut context, index, &algo),
        Commands::Hash { data, algo } => commands::cmd_hash(&mut context, &data, &algo),
        Commands::Sign { data, ecc, key } => {
            sign::cmd_sign(&mut context, &data, ecc, key.as_deref())
        }
        Commands::Verify { data, key, sig } => {
            verify::cmd_verify(&mut context, &data, &key, &sig)
        }
        Commands::Seal { data, pcrs, out } => seal::cmd_seal(&mut context, &data, &pcrs, &out),
        Commands::Unseal { input, pcrs } => seal::cmd_unseal(&mut context, &input, &pcrs),
        Commands::Quote { pcrs, nonce, algo, out } => {
            quote::cmd_quote(&mut context, &pcrs, nonce.as_deref(), &algo, out.as_deref())
        }
        Commands::QuoteVerify { input } => quote::cmd_quote_verify(&mut context, &input),
        Commands::Key(sub) => match sub {
            KeyCommands::Create { algo, persist } => {
                keys::cmd_key_create(&mut context, &algo, &persist)
            }
            KeyCommands::List => keys::cmd_key_list(&mut context),
            KeyCommands::Delete { handle } => keys::cmd_key_delete(&mut context, &handle),
            KeyCommands::ExportPub { handle } => keys::cmd_key_export_pub(&mut context, &handle),
        },
        Commands::Test => test::cmd_test(&mut context),
        Commands::Version => unreachable!(),
    }
}
