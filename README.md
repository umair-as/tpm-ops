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

# Attestation: the verifier supplies the challenge and expected PCR selection.
tpm-ops quote --pcrs 0,7 --nonce <challenge-hex> --out quote.blob

# Provision the printed "AK SHA-256" fingerprint through a trusted channel,
# then require all three independent expectations during verification.
tpm-ops quote-verify quote.blob \
  --nonce <challenge-hex> \
  --ak-pub-sha256 <trusted-ak-fingerprint> \
  --pcrs 0,7

# Software TPM (testing)
tpm-ops --tcti "swtpm:port=2321" test
```

### Quote trust model

`quote-verify` deliberately does not trust the nonce, PCR label, or AK public
key carried inside the quote blob. The verifier must provide:

- the challenge nonce it issued;
- the expected SHA-256 PCR selection; and
- a SHA-256 fingerprint of the AK public area obtained through a trusted
  provisioning channel.

The current `quote` command creates an ephemeral AK, so its fingerprint changes
for every quote. This is suitable for local round-trip diagnostics when the
fingerprint is transferred over an authenticated channel. A production remote
attestation deployment should provision and pin a stable AK identity.

The hardware test suite reserves persistent handles `0x81000FFD` through
`0x81000FFF`. It now refuses to run if any of those handles are occupied and
never deletes a pre-existing key.

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
