# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`tpm-ops` is a single-binary Rust CLI for TPM 2.0 operations on the Infineon SLB9672, built on the `tss-esapi` (ESAPI) bindings. Primary target is a Raspberry Pi 5 running a Yocto image, but it runs on any Linux host exposing a TPM resource manager (`/dev/tpmrm0`) or a software TPM (`swtpm`).

## Commands

```bash
# Build
cargo build --release

# Cross-compile for an aarch64 target (needs an aarch64 sysroot with libtss2)
SYSROOT=/path/to/aarch64-sysroot ./scripts/cross-build-aarch64.sh
# See README "Cross-compiling for aarch64" for how to obtain a sysroot.

# Lint / format — CI enforces both strictly (see note below)
cargo fmt --check
cargo clippy --locked -- -D warnings

# Unit tests (pure helpers only — no TPM needed)
cargo test
cargo test nonce_accepts_128_to_512_bits   # run a single test by name

# Live integration suite (needs a real TPM or swtpm) — the `test` subcommand,
# NOT `cargo test`. Exercises sign/verify, seal/unseal, quote/verify end-to-end.
cargo run --release -- --tcti "swtpm:port=2321" test
```

Two distinct test layers exist and are easy to confuse:
- **`cargo test`** runs the `#[cfg(test)]` unit tests (in `keys.rs`, `quote.rs`) — pure functions like nonce/fingerprint validation and EC coordinate padding. No TPM.
- **The `test` subcommand** (`src/test.rs`) is the real hardware/`swtpm` validation suite. CI runs it against `swtpm`. It reserves persistent handles `0x81000FFC`–`0x81000FFF` (`0x81000FFC` is the policy-bound-key test), refuses to run if any are occupied, and never deletes a pre-existing key.

### Running against swtpm (no hardware)

```bash
mkdir -p /tmp/swtpm
swtpm socket --tpmstate dir=/tmp/swtpm --ctrl type=tcp,port=2322 \
  --server type=tcp,port=2321 --tpm2 --flags startup-clear --daemon
cargo run --release -- --tcti "swtpm:port=2321" test
```

The global `--tcti` flag selects the transport for every command; it defaults to `device:/dev/tpmrm0`.

## Architecture

**Dispatch.** `main.rs` parses `Cli` (defined in `cli.rs` with clap-derive), builds one `tss_esapi::Context` from the `--tcti` string, and threads it as `&mut` into exactly one command function per subcommand. `version` is special-cased to run *before* the TPM context is created (so it works with no TPM present). Every other command needs a live context.

**One shared TPM context.** There is no connection pooling or state beyond the single `Context`. Command functions take `&mut TpmContext` and are the unit of work. Reusable primitives live in `commands.rs` (`random_bytes`, `hash_bytes`, `read_pcr_digests`) and are called both by their own `cmd_*` wrappers and by `test.rs` — when adding functionality, expose a raw helper returning data plus a thin `cmd_*` that prints, so the test suite can assert on the data.

**`tpm.rs` is the shared toolbox.** Handle parsing (`parse_handle`), PCR list parsing/selection (`parse_pcr_indices`, `pcr_selection_sha256`), capability-based existence probing (`persistent_handle_exists` — uses `GetCapability` rather than `ReadPublic` to avoid noisy tss2 C-library error logs), the `KeyGuard` RAII wrapper, `create_srk`, and the shared PolicyPCR machinery (`pcr_policy_digest` for a trial-session digest, `start_pcr_policy_session` for a real gated session) all live here.

**SRK model.** A single Storage Root Key is persisted at the reserved handle `0x81000000` (`PERSISTENT_SRK_HANDLE`). `create_srk` lazily creates+persists it on first use (~20s RSA-2048 keygen) and fast-paths to the existing handle afterward. **Every other key is a child created under the SRK.** The SRK is a persistent object — never flush it. User signing keys must land in `0x81000001..=0x817FFFFF` (owner persistent range); `0x81000000` is rejected and `key delete` refuses to remove the SRK.

**Transient handle hygiene.** Any *transient* (loaded/primary) key handle must be flushed. Use `KeyGuard::new(context, handle)` — it flushes on drop. Note its ergonomic quirk: `KeyGuard` borrows the context, so after wrapping you access the TPM through `guard.context` and the handle through `guard.handle()`. Auth/policy *session* handles need the same discipline — trial and real `PolicyPCR` sessions occupy TPM session slots just like transient keys, and `tpm-ops test` starts many in one process. Use `SessionGuard::new(context, handle)` (same borrow ergonomics as `KeyGuard`, access via `guard.context`) — `start_pcr_policy_session` in `tpm.rs` returns one already wired up.

**Key/algorithm conventions.** Signing keys are RSA-2048 (RSA-SSA, SHA-256) or ECC P-256 (ECDSA, SHA-256), always unrestricted signing children. Attestation Keys (AKs) for `quote` are *restricted* signing keys with `no_da`. ECC signatures are serialized as `R||S`, each component left-padded to 32 bytes — this padding convention is load-bearing across `sign`/`verify`/`quote`. **PCR-policy-bound signing keys** (`key create --policy-pcrs <list>`) are still unrestricted signing children — never `restricted` — but swap `user_with_auth(true)` for `user_with_auth(false)` + `admin_with_policy(true)` and carry a `PolicyPCR` digest (computed over current PCR state at creation time) as the object's auth policy, mirroring `sealed_public()` in `seal.rs`. The PCR list is not recoverable from the key afterward (a policy digest is one-way) — callers must resupply the same list to `sign --policy-pcrs`. `sign` performs no client-side check of whether current PCR state satisfies the policy; the TPM alone decides, and a refusal is surfaced as a stable `Sign refused by TPM: ...` message rather than a raw tss2 error.

**`pcr extend`/`pcr reset` safety rule.** PCR extends are irreversible until reboot and PCRs 0-15 cannot be reset at all. `pcr extend` refuses any index outside `{16, 23}` unless `--force` is passed; `pcr reset` refuses any index outside `{16, 23}` unconditionally. The check is a pure, unit-tested function (`check_pcr_extend_allowed`/`check_pcr_reset_allowed` in `commands.rs`) — do not inline the gate into the `cmd_*` printer. CLI shape: an optional clap-derive subcommand nested on the existing `Pcr` variant (`action: Option<PcrAction>`), so bare `pcr`/`pcr -i 0`/`pcr --index 0 --algo sha256` keep resolving to read behavior unchanged.

**On-disk blob formats.** `seal` and `quote` write plain-text `key=value` files with a magic first line (`TPM_OPS_SEALED_V1`, `TPM_OPS_QUOTE_V1`). Parsers reject on a wrong magic and on any missing field. If you add a field, bump the magic version.

**Quote trust model (important, see README "Quote trust model").** `quote-verify` deliberately does **not** trust the nonce, PCR label, or AK public key carried inside the blob. The verifier must independently supply `--nonce`, `--pcrs`, and `--ak-pub-sha256` (a fingerprint provisioned over a trusted channel). Verification cross-checks the signed `TPMS_ATTEST` against all three, and also checks the blob's own metadata matches — do not "simplify" by trusting blob-internal values. The current `quote` command creates an *ephemeral* AK (fingerprint changes every run), suitable for local round-trip diagnostics; production remote attestation needs a pinned, provisioned AK.

**PEM export** (`pem.rs`) hand-encodes DER for RSA (`RSA PUBLIC KEY`) and ECC (`PUBLIC KEY` / SubjectPublicKeyInfo) public areas read back from persistent keys.

## Build metadata

`build.rs` embeds the git short hash into the `TPM_OPS_GIT_HASH` env var at compile time (falls back to `"unknown"` outside a git checkout, e.g. a Yocto fetch) and sets `rerun-if-changed` on git refs. Surfaced via `tpm-ops version`.

## CI and supply chain

`.github/workflows/ci.yml` runs on push/PR to `main` plus a weekly cron: `cargo fmt --check`, `cargo clippy --locked -D warnings`, `cargo build --release --locked`, the `swtpm` integration suite, `cargo audit --deny warnings` (pinned `cargo-audit`), and a CycloneDX 1.5 SBOM (`cargo-cyclonedx`). `.github/workflows/attest.yml` is a **separate privileged workflow that runs only on push to `main`** — it holds the OIDC/attestation write credentials and is kept apart from PR CI so PR-authored workflow changes can't obtain them. `Cargo.lock` is committed; keep it in sync.

`rust-toolchain.toml` pins the stable channel with rustfmt+clippy. Formatting/clippy drift between local and CI toolchains has repeatedly broken CI — always run `cargo fmt` and `cargo clippy --locked -- -D warnings` before pushing, and expect the exact pinned toolchain to matter.

## Deploying to a target

`scripts/deploy-tpm-ops-target.sh --target user@host (--rpm <path> | --bin <path>)` scp's an RPM or raw binary, remounts the target rootfs read-write to install, restores read-only, prints `tpm-ops version`, and runs `pcr`/`sign` smoke checks (`--no-smoke` to skip). Set `TPM_OPS_TARGET` instead of passing `--target`.

## Release profile

The `release` profile is size-optimized (`opt-level = "z"`, LTO, single codegen unit, stripped, `panic = "abort"`) for the embedded target — be aware `panic = "abort"` means no unwinding.
