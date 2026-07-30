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

## Hardware

Tested on **Raspberry Pi 5** with **Infineon SLB9672** TPM 2.0 over SPI.
