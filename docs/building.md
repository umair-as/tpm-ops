# Building and testing

## Requirements

### Build

- Rust stable (see [`rust-toolchain.toml`](../rust-toolchain.toml))
- `libtss2-dev` — TPM2 TSS headers and libraries

```bash
# Ubuntu / Debian
sudo apt install libtss2-dev
```

### Runtime

- Linux kernel with `/dev/tpmrm0` (TPM resource manager)
- `libtss2-esys`, `libtss2-tcti-device`

## Native build

```bash
cargo build --release
```

## Cross-compiling for aarch64

`tpm-ops` links `libtss2` (a C library), so a cross build needs an **aarch64 sysroot** that
provides it (along with glibc, the crt startup objects, and libcrypto). Get a sysroot with any of
the methods below, then build against it:

```bash
rustup target add aarch64-unknown-linux-gnu
sudo apt install gcc-aarch64-linux-gnu        # cross linker

SYSROOT=/path/to/aarch64-sysroot ./scripts/cross-build-aarch64.sh
```

The script wires up the cross linker, `--sysroot`, and pkg-config, then reports the binary's
arch, `NEEDED` libraries, and the highest glibc symbol version it requires — so you can confirm
it matches your target before deploying.

**Getting a sysroot** — pick one:

1. **arm64 multiarch packages** (simplest, distro-generic):
   ```bash
   sudo dpkg --add-architecture arm64
   sudo apt update
   sudo apt install libtss2-dev:arm64 libc6-dev:arm64 libssl-dev:arm64
   SYSROOT=/ ./scripts/cross-build-aarch64.sh
   ```
   The resulting binary needs the target's glibc to be at least as new as the sysroot's.

2. **Copy from your target device** (exact ABI match — the binary is linked against the target's
   own libraries):
   ```bash
   ./scripts/pull-device-sysroot.sh user@host   # rsyncs /usr/lib + /usr/include
   ./scripts/cross-build-aarch64.sh             # uses .build/aarch64-sysroot
   ```

3. **A Yocto / vendor SDK** — `source` its `environment-setup-*` script (it sets `CC` and
   `--sysroot`), then `cargo build --target aarch64-unknown-linux-gnu --release`.

A quick sanity check without hardware, using `qemu-aarch64-static`:

```bash
qemu-aarch64-static -L /path/to/aarch64-sysroot \
  target/aarch64-unknown-linux-gnu/release/tpm-ops version
```

CI cross-builds for aarch64 on every push/PR to `main` (the "Cross-build (aarch64)" job), using
option 1 above (arm64 multiarch packages) plus the same `qemu-aarch64-static` smoke check. It
compiles and links only — a GitHub-hosted runner can't execute an aarch64 binary natively beyond
that emulated smoke step — but that's enough to catch a dependency or code change that breaks the
cross build before it's discovered by hand at deploy time.

## Testing with swtpm

No hardware TPM needed for development:

```bash
mkdir -p /tmp/swtpm
swtpm socket \
  --tpmstate dir=/tmp/swtpm \
  --ctrl type=tcp,port=2322 \
  --server type=tcp,port=2321 \
  --tpm2 --flags startup-clear --daemon

tpm-ops --tcti "swtpm:port=2321" test
```

Two distinct test layers exist:

- **`cargo test`** — the `#[cfg(test)]` unit tests (pure helpers: nonce/fingerprint validation,
  EC coordinate padding, the PCR extend/reset safety gate). No TPM needed.
- **The `test` subcommand** (shown above) — the live validation suite against a real TPM or
  `swtpm`. This is what CI runs. See [commands.md](commands.md#test) for what it covers.

Use a fresh `swtpm` state directory (`rm -rf /tmp/swtpm/*`, restart `swtpm`) whenever you need a
clean PCR baseline — PCR extends are not undoable except by resetting the affected PCR or
restarting the simulator entirely.

## Reproducing CI's supply-chain checks locally

`Cargo.lock` is committed so builds, audits, and SBOMs resolve the same dependency versions. CI
runs RustSec vulnerability scanning and CycloneDX SBOM generation on every push and PR (plus a
weekly rescan for newly published advisories). To reproduce locally:

```bash
cargo install cargo-audit --version 0.22.2 --locked
cargo audit --deny warnings

cargo install cargo-cyclonedx --version 0.5.9 --locked
cargo cyclonedx --format json --spec-version 1.5
```

## Changelog

[`CHANGELOG.md`](../CHANGELOG.md) is generated from the git history with
[git-cliff](https://github.com/orhun/git-cliff) and [`cliff.toml`](../cliff.toml) — **it is never
hand-edited.** The commit history is Conventional Commits (`feat:`, `fix:`, `docs:`, etc.), so
`cliff.toml` classifies mostly by commit type, with a keyword match that routes
security/hardening-flavored commits (matching `security`, `harden`, `hardening`, or `cve`
case-insensitively) into their own section even without a conventional prefix, and a catch-all
group so anything else still shows up rather than silently disappearing.

There is no GitHub Releases flow and no CI automation for this — regeneration is a manual step,
done once per version bump:

```bash
GITHUB_REPO=umair-as/tpm-ops git-cliff --config cliff.toml --tag v<new-version> -o CHANGELOG.md
```

Run it *after* bumping `Cargo.toml`'s version but *before* tagging, so the new section's heading
(`v<new-version>`) matches the tag you're about to create. Commit the regenerated
`CHANGELOG.md` alongside the version bump.

## Hardware

Tested on **Raspberry Pi 5** with **Infineon SLB9672** TPM 2.0 over SPI.
