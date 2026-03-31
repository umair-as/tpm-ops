# tpm-ops

Rust CLI tool for TPM 2.0 operations targeting the Infineon SLB9672 on Raspberry Pi 5.

## Features

- **info** — Display TPM manufacturer, firmware version, and spec revision
- **selftest** — Run TPM self-test and report health status
- **random** — Generate random bytes from the hardware TRNG (1–48 bytes)
- **pcr** — Read PCR register values (SHA-1, SHA-256, SHA-384)
- **hash** — Compute hashes using the TPM engine
- **sign** — Create ephemeral RSA-2048 or ECC P-256 keys and sign data
- **test** — Run all operations as a validation suite
- **version** — Show tool version and embedded git revision

## Requirements

### Build (host)

- Rust 1.85+ (uses `tss-esapi` 7.x which links against system `libtss2`)
- `libtss2-dev` — TPM2 TSS development headers

```bash
# Ubuntu/Debian
sudo apt install libtss2-dev
```

### Runtime (target)

- Linux kernel with `/dev/tpmrm0` (TPM kernel resource manager)
- `libtss2-esys`, `libtss2-tcti-device` shared libraries

## Build

```bash
cargo build --release
```

### Cross-compile for aarch64 (Yocto SDK)

```bash
source /opt/poky/4.0/environment-setup-cortexa76-poky-linux
cargo build --target aarch64-unknown-linux-gnu --release
```

## Usage

```
tpm-ops [OPTIONS] <COMMAND>

Options:
  -d, --device <DEVICE>  TCTI device path [default: /dev/tpmrm0]

Commands:
  info      Display TPM information and capabilities
  selftest  Run TPM self-test and report health status
  random    Generate random bytes using TPM TRNG
  pcr       Read PCR values
  hash      Hash data using TPM
  sign      Create a key pair in TPM and sign data
  test      Run all operations as a validation suite
  version   Show version and build information
```

### Examples

```bash
tpm-ops info                    # Manufacturer, firmware, spec revision
tpm-ops selftest                # Incremental TPM self-test
tpm-ops selftest --full         # Full TPM self-test
tpm-ops random -b 32            # 32 random bytes from TRNG
tpm-ops pcr -i 0                # Read PCR[0] SHA-256
tpm-ops hash "hello"            # TPM-computed SHA-256
tpm-ops sign "test"             # RSA-2048 sign
tpm-ops sign "test" --ecc       # ECC P-256 sign
tpm-ops version                 # Binary version + git hash
tpm-ops test                    # Run full validation suite
```

## Troubleshooting

- `Missing authorization session` during `sign`: use a build that includes commit `4e48d8e` or newer.
- `Invalid PCR slot` for `pcr -i 0`: use a build that includes commit `4e48d8e` or newer.

## Hardware

Tested on Raspberry Pi 5 with Infineon SLB9672 TPM 2.0 connected via SPI (RP1 SPI0 CS1).

## License

MIT
