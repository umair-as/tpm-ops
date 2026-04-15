# tpm-ops

[![CI](https://github.com/umair-as/tpm-ops/actions/workflows/ci.yml/badge.svg)](https://github.com/umair-as/tpm-ops/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](rust-toolchain.toml)

Rust CLI for TPM 2.0 operations on the Infineon SLB9672. Targets Raspberry Pi 5 running a Yocto-based image, but works on any Linux system with a TPM kernel resource manager.

---

## Commands

| Command | Description |
|---------|-------------|
| `info` | Manufacturer, firmware version, spec revision |
| `selftest` | Incremental or full TPM self-test |
| `random` | Hardware TRNG bytes (1–48) |
| `pcr` | Read PCR register (SHA-1 / SHA-256 / SHA-384) |
| `hash` | Hash data using the TPM engine |
| `sign` | Sign with ephemeral RSA-2048 or ECC P-256 key |
| `verify` | Verify signature against a persistent key |
| `key` | Persistent key management — create / list / delete / export-pub |
| `seal` | Seal a secret to PCR policy, write blob to disk |
| `unseal` | Unseal blob when PCR policy is satisfied |
| `quote` | TPM2_Quote over selected PCRs with nonce |
| `quote-verify` | Verify a quote blob |
| `test` | Run the full validation suite |
| `version` | Binary version and embedded git revision |

---

## Requirements

### Build

- Rust stable (see [`rust-toolchain.toml`](rust-toolchain.toml))
- `libtss2-dev` — TPM2 TSS headers and libraries

```bash
# Ubuntu / Debian
sudo apt install libtss2-dev
```

### Runtime

- Linux kernel with `/dev/tpmrm0` (TPM resource manager)
- `libtss2-esys`, `libtss2-tcti-device`

---

## Build

```bash
cargo build --release
```

**Cross-compile for aarch64 (Yocto SDK):**

```bash
source /opt/poky/4.0/environment-setup-cortexa76-poky-linux
cargo build --target aarch64-unknown-linux-gnu --release
```

---

## Usage

```
tpm-ops [OPTIONS] <COMMAND>

Options:
  -t, --tcti <TCTI>  TCTI string [default: device:/dev/tpmrm0]
```

### Examples

```bash
# Basic ops
tpm-ops info
tpm-ops selftest --full
tpm-ops random -b 32
tpm-ops pcr -i 0
tpm-ops hash "hello world"

# Ephemeral signing
tpm-ops sign "message"
tpm-ops sign "message" --ecc

# Persistent keys
tpm-ops key create --algo rsa --persist 0x81000001
tpm-ops key list
tpm-ops sign "message" --key 0x81000001
tpm-ops verify "message" --key 0x81000001 --sig <hex>
tpm-ops key delete 0x81000001

# Seal / unseal
tpm-ops seal "my-secret" --pcrs 0,7 --out sealed.blob
tpm-ops unseal --in sealed.blob --pcrs 0,7

# Attestation
tpm-ops quote --pcrs 0,7 --out quote.blob
tpm-ops quote-verify quote.blob

# Software TPM (testing)
tpm-ops --tcti "swtpm:port=2321" test
```

---

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

---

## Hardware

Tested on **Raspberry Pi 5** with **Infineon SLB9672** TPM 2.0 over SPI (RP1 SPI0 CS1).

---

## License

[MIT](LICENSE)
