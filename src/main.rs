//! TPM 2.0 operations tool for Infineon SLB9672

mod cli;
mod commands;
mod keys;
mod output;
mod pem;
mod quote;
mod seal;
mod sign;
mod test;
mod tpm;
mod verify;

use std::io::IsTerminal;
use std::str::FromStr;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser};

use cli::{Cli, Commands, KeyCommands, PcrAction};
use output::ColorChoice;
use tss_esapi::tcti_ldr::TctiNameConf;

fn init_logging(cli: &Cli) {
    let level = if cli.quiet {
        "error"
    } else {
        match cli.verbose {
            0 => "warn",
            1 => "info",
            2 => "debug",
            _ => "trace",
        }
    };
    // tss_esapi's own INFO-level chatter (e.g. "Closing context.") is never
    // useful at normal verbosity; only let it through once the user has
    // explicitly asked for deep diagnostics via -vv/-vvv.
    let tss_level = if cli.verbose >= 2 { level } else { "warn" };
    let default_filter =
        format!("warn,tpm_ops={level},tss_esapi={tss_level},tss_esapi_sys={tss_level}");
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_filter))
        .init();
}

fn main() {
    let cli = Cli::parse();
    init_logging(&cli);
    let json = cli.json;
    let color = ColorChoice::parse(&cli.color)
        .unwrap_or(ColorChoice::Auto)
        .enabled();

    if let Err(error) = run(cli) {
        if json {
            output::print_json(
                "tpm-ops.error.v1",
                vec![(
                    "error",
                    output::Json::Str(output::format_error_json(&error)),
                )],
            );
        } else {
            eprintln!("{}", output::format_error_human(&error, color));
        }
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    let json = cli.json;
    // Validate --color eagerly so a typo surfaces immediately rather than only
    // once something tries to print. Actual color decisions are resolved in
    // main() (see ColorChoice::enabled), since they govern error-path output
    // that has to work even if `run` itself never returns.
    ColorChoice::parse(&cli.color)?;
    // stdin is non-interactive whenever it's not a TTY, or --json/--yes was
    // passed — a confirmation prompt must never block a scripted or piped
    // invocation (see `key delete`, called 4x by `tpm-ops test`).
    let assume_yes = cli.yes || json || !std::io::stdin().is_terminal();

    if let Commands::Version = cli.command {
        return commands::cmd_version(json);
    }

    if let Commands::Completions { shell } = cli.command {
        let mut cmd = Cli::command();
        let name = cmd.get_name().to_string();
        clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
        return Ok(());
    }

    let tcti_conf = TctiNameConf::from_str(&cli.tcti).context("Invalid TCTI string")?;
    let mut context = tss_esapi::Context::new(tcti_conf).context("Failed to create TPM context")?;

    match cli.command {
        Commands::Info => commands::cmd_info(&mut context, json),
        Commands::Selftest { full } => commands::cmd_selftest(&mut context, full, json),
        Commands::Random { bytes } => commands::cmd_random(&mut context, bytes, json),
        Commands::Pcr {
            index,
            algo,
            action,
        } => match action {
            None => commands::cmd_pcr(&mut context, index, &algo, json),
            Some(PcrAction::Extend { index, data, force }) => {
                commands::cmd_pcr_extend(&mut context, index, &data, force, json)
            }
            Some(PcrAction::Reset { index }) => commands::cmd_pcr_reset(&mut context, index, json),
        },
        Commands::Hash { data, file, algo } => {
            commands::cmd_hash(&mut context, data.as_deref(), file.as_deref(), &algo, json)
        }
        Commands::Sign {
            data,
            file,
            algo,
            ecc,
            key,
            policy_pcrs,
        } => {
            let use_ecc = match algo.as_deref() {
                Some(a) => match a.to_lowercase().as_str() {
                    "rsa" => false,
                    "ecc" => true,
                    other => {
                        anyhow::bail!("Unsupported algorithm '{}' — use 'rsa' or 'ecc'", other)
                    }
                },
                None => ecc,
            };
            sign::cmd_sign(
                &mut context,
                data.as_deref(),
                file.as_deref(),
                use_ecc,
                key.as_deref(),
                policy_pcrs.as_deref(),
                json,
            )
        }
        Commands::Verify {
            data,
            key,
            sig,
            sig_file,
        } => {
            let sig_hex = resolve_sig(sig, sig_file)?;
            verify::cmd_verify(&mut context, &data, &key, &sig_hex, json)
        }
        Commands::Seal { data, pcrs, out } => {
            seal::cmd_seal(&mut context, &data, &pcrs, &out, json)
        }
        Commands::Unseal { input, pcrs } => seal::cmd_unseal(&mut context, &input, &pcrs, json),
        Commands::Quote {
            pcrs,
            nonce,
            algo,
            out,
        } => quote::cmd_quote(
            &mut context,
            &pcrs,
            nonce.as_deref(),
            &algo,
            out.as_deref(),
            json,
        ),
        Commands::QuoteVerify {
            input,
            nonce,
            ak_pub_sha256,
            pcrs,
        } => quote::cmd_quote_verify(&mut context, &input, &nonce, &ak_pub_sha256, &pcrs, json),
        Commands::QuoteFingerprint { input } => {
            quote::cmd_quote_fingerprint(&mut context, &input, json)
        }
        Commands::Key(sub) => match sub {
            KeyCommands::Create {
                algo,
                persist,
                policy_pcrs,
            } => keys::cmd_key_create(&mut context, &algo, &persist, policy_pcrs.as_deref(), json),
            KeyCommands::List => keys::cmd_key_list(&mut context, json),
            KeyCommands::Delete {
                handle,
                handle_flag,
            } => {
                let handle = resolve_handle(handle, handle_flag)?;
                keys::cmd_key_delete(&mut context, &handle, assume_yes, json)
            }
            KeyCommands::ExportPub {
                handle,
                handle_flag,
            } => {
                let handle = resolve_handle(handle, handle_flag)?;
                keys::cmd_key_export_pub(&mut context, &handle)
            }
        },
        Commands::Test => test::cmd_test(&mut context),
        Commands::Version | Commands::Completions { .. } => unreachable!(),
    }
}

fn resolve_handle(positional: Option<String>, flag: Option<String>) -> Result<String> {
    positional.or(flag).ok_or_else(|| {
        anyhow::anyhow!("Provide a handle: positional argument or --handle <handle>")
    })
}

fn resolve_sig(inline: Option<String>, file: Option<String>) -> Result<String> {
    match (inline, file) {
        (Some(s), None) => Ok(s),
        (None, Some(path)) if path == "-" => {
            use std::io::Read;
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("Failed to read signature from stdin")?;
            Ok(buf.trim().to_string())
        }
        (None, Some(path)) => std::fs::read_to_string(&path)
            .map(|s| s.trim().to_string())
            .with_context(|| format!("Failed to read signature from {}", path)),
        (None, None) => anyhow::bail!("Provide a signature: --sig <hex> or --sig-file <path>"),
        (Some(_), Some(_)) => unreachable!("clap enforces --sig-file conflicts_with --sig"),
    }
}
