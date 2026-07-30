# tpm-ops

[![CI](https://github.com/umair-as/tpm-ops/actions/workflows/ci.yml/badge.svg)](https://github.com/umair-as/tpm-ops/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](rust-toolchain.toml)

Rust CLI for TPM 2.0 operations on the Infineon SLB9672. Targets Raspberry Pi 5 running a
Yocto-based image, but works on any Linux system with a TPM kernel resource manager (or a
software TPM, `swtpm`, for development).

A single binary exposes: TPM identity/health/random (`info`, `selftest`, `random`), PCR read and
(gated) extend/reset (`pcr`), hashing (`hash`), persistent and ephemeral signing including
PCR-policy-bound keys (`key`, `sign`, `verify`), PCR-policy-sealed secrets (`seal`, `unseal`),
and remote attestation (`quote`, `quote-verify`).

## Quick start

```bash
sudo apt install libtss2-dev   # TPM2 TSS headers/libraries
cargo build --release

# No hardware TPM needed — run everything against a software TPM:
mkdir -p /tmp/swtpm
swtpm socket --tpmstate dir=/tmp/swtpm --ctrl type=tcp,port=2322 \
  --server type=tcp,port=2321 --tpm2 --flags startup-clear --daemon

./target/release/tpm-ops --tcti "swtpm:port=2321" info
./target/release/tpm-ops --tcti "swtpm:port=2321" test   # full validation suite
```

## Documentation

Start with **[docs/](docs/)**:

- [docs/concepts.md](docs/concepts.md) — the TPM 2.0 ideas this tool exercises, explained as
  implemented here. Start here if you're new to TPM 2.0.
- [docs/commands.md](docs/commands.md) — full command reference with real examples and exit
  codes.
- [docs/blob-formats.md](docs/blob-formats.md) — on-disk spec for the sealed-data and quote blob
  formats.
- [docs/security-model.md](docs/security-model.md) — what the tool protects against and what it
  doesn't, including an honest limitations section. Read this before relying on any of this for
  something that matters.
- [docs/building.md](docs/building.md) — native build, aarch64 cross-compiling via a sysroot, and
  testing against `swtpm`.

## Hardware

Tested on **Raspberry Pi 5** with **Infineon SLB9672** TPM 2.0 over SPI. See
[docs/building.md](docs/building.md) for cross-compiling and swtpm-based development without
hardware.

## License

[MIT](LICENSE)
