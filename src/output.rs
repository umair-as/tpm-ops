//! Output formatting shared across commands: human vs. `--json`, TTY-aware
//! color/status helpers, and cleaned-up error reporting.
//!
//! `--json` commands build a [`Json`] value and print exactly one line to
//! stdout; everything else (progress, status, prompts) goes to stderr so a
//! `| jq .` pipeline never has to redirect stderr to get valid JSON.

use std::io::IsTerminal;

use tss_esapi::constants::{Tss2ResponseCode, Tss2ResponseCodeKind};

/// Minimal hand-rolled JSON value — avoids pulling in serde/serde_json for a
/// handful of flat, schema-versioned output objects (release profile is
/// size-optimized for an embedded target; see CLAUDE.md "Release profile").
pub(crate) enum Json {
    Str(String),
    UInt(u64),
    Bool(bool),
    Array(Vec<Json>),
    Object(Vec<(&'static str, Json)>),
}

impl Json {
    pub(crate) fn write(&self, out: &mut String) {
        match self {
            Json::Str(s) => {
                out.push('"');
                escape_into(s, out);
                out.push('"');
            }
            Json::UInt(n) => out.push_str(&n.to_string()),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Json::Object(fields) => {
                out.push('{');
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push('"');
                    escape_into(k, out);
                    out.push_str("\":");
                    v.write(out);
                }
                out.push('}');
            }
        }
    }

    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }
}

fn escape_into(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}

/// Print a `--json` object to stdout. Always one line, always the sole thing
/// this process writes to stdout for the invocation.
pub(crate) fn print_json(schema: &'static str, mut fields: Vec<(&'static str, Json)>) {
    fields.insert(0, ("schema", Json::Str(schema.to_string())));
    println!("{}", Json::Object(fields).render());
}

/// Map a TSS2 response code kind to its `TPM_RC_*` spec name. Derived
/// mechanically from the enum variant name (e.g. `PcrChanged` ->
/// `TPM_RC_PCR_CHANGED`) — this matches the spec's naming convention for all
/// but a couple of rare compound names, which is an acceptable trade-off for
/// a diagnostic label.
fn tpm_rc_name(kind: Tss2ResponseCodeKind) -> String {
    let debug = format!("{:?}", kind);
    let mut out = String::from("TPM_RC_");
    for (i, ch) in debug.chars().enumerate() {
        if ch.is_uppercase() && i != 0 {
            out.push('_');
        }
        out.push(ch.to_ascii_uppercase());
    }
    out
}

/// Render an error chain for human output: the top-level message, plus a
/// deduplicated, RC-annotated `Caused by:` list.
///
/// tss-esapi's error chain routinely repeats the same message twice (once
/// from `tss_esapi::Error`'s `Display`, once from its `source()` handing back
/// the same `Tss2ResponseCode`) before reaching a raw `Response code value:
/// 0x...` line. This collapses adjacent duplicates and prefixes any hop whose
/// concrete type is a recognized TSS2 response code with its `TPM_RC_*` name,
/// so `TPM_RC_HANDLE` (say) is visible instead of only a bare hex code.
pub(crate) fn format_error_human(error: &anyhow::Error, color: bool) -> String {
    let prefix = if color {
        "\x1b[31mError:\x1b[0m"
    } else {
        "Error:"
    };
    let mut out = format!("{} {}", prefix, error);

    let mut causes: Vec<String> = Vec::new();
    for cause in error.chain().skip(1) {
        let mut msg = cause.to_string();
        if let Some(kind) = response_code_kind(cause) {
            msg = format!("{}: {}", tpm_rc_name(kind), msg);
        }
        if causes.last() != Some(&msg) {
            causes.push(msg);
        }
    }

    if !causes.is_empty() {
        out.push_str("\n\nCaused by:");
        for (i, cause) in causes.iter().enumerate() {
            out.push_str(&format!("\n    {}: {}", i, cause));
        }
    }
    out
}

/// Same dedup/annotation as [`format_error_human`], collapsed to one line for
/// `--json` error objects.
pub(crate) fn format_error_json(error: &anyhow::Error) -> String {
    let mut parts = vec![error.to_string()];
    let mut last = parts[0].clone();
    for cause in error.chain().skip(1) {
        let mut msg = cause.to_string();
        if let Some(kind) = response_code_kind(cause) {
            msg = format!("{}: {}", tpm_rc_name(kind), msg);
        }
        if msg != last {
            parts.push(msg.clone());
        }
        last = msg;
    }
    parts.join(": ")
}

fn response_code_kind(cause: &(dyn std::error::Error + 'static)) -> Option<Tss2ResponseCodeKind> {
    if let Some(tss_esapi::Error::Tss2Error(code)) = cause.downcast_ref::<tss_esapi::Error>() {
        return code.kind();
    }
    if let Some(code) = cause.downcast_ref::<Tss2ResponseCode>() {
        return code.kind();
    }
    None
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ColorChoice {
    Auto,
    Always,
    Never,
}

impl ColorChoice {
    pub(crate) fn parse(s: &str) -> anyhow::Result<Self> {
        match s {
            "auto" => Ok(ColorChoice::Auto),
            "always" => Ok(ColorChoice::Always),
            "never" => Ok(ColorChoice::Never),
            other => anyhow::bail!(
                "Invalid --color value '{}' (expected auto, always, or never)",
                other
            ),
        }
    }

    /// Resolve against NO_COLOR (https://no-color.org) and whether stderr is a TTY.
    /// Status/spinner output goes to stderr, so that's the stream that governs it.
    pub(crate) fn enabled(self) -> bool {
        match self {
            ColorChoice::Always => true,
            ColorChoice::Never => false,
            ColorChoice::Auto => {
                std::env::var_os("NO_COLOR").is_none() && std::io::stderr().is_terminal()
            }
        }
    }
}

/// Print a one-line status message to stderr, unconditionally (not gated by
/// verbosity) — for slow or destructive operations where "nothing printed
/// for 20 seconds" reads as a hang, not as no-news-is-good-news.
pub(crate) fn status(msg: &str) {
    eprintln!("{}", msg);
}

/// Status line for a slow operation, animated with a spinner when stderr is
/// a TTY. Never emits control characters when piped — falls back to a single
/// static line. Drop clears the spinner line and leaves nothing behind.
pub(crate) struct Spinner {
    stop: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Spinner {
    pub(crate) fn start(msg: &str) -> Self {
        if !std::io::stderr().is_terminal() {
            eprintln!("{}", msg);
            return Spinner {
                stop: None,
                handle: None,
            };
        }

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_clone = stop.clone();
        let msg = msg.to_string();
        let handle = std::thread::spawn(move || {
            const FRAMES: [char; 4] = ['|', '/', '-', '\\'];
            let mut i = 0usize;
            while !stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
                eprint!("\r{} {}", FRAMES[i % FRAMES.len()], msg);
                let _ = std::io::Write::flush(&mut std::io::stderr());
                i += 1;
                std::thread::sleep(std::time::Duration::from_millis(150));
            }
            eprint!("\r{}\r", " ".repeat(msg.len() + 2));
            let _ = std::io::Write::flush(&mut std::io::stderr());
        });

        Spinner {
            stop: Some(stop),
            handle: Some(handle),
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
