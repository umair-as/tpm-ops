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
| `pcr` | Read PCR register (SHA-1 / SHA-256 / SHA-384); `pcr extend` / `pcr reset` a PCR |
| `hash` | Hash data using the TPM engine |
| `sign` | Sign with ephemeral RSA-2048 or ECC P-256 key, or a policy-bound persistent key |
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

---

## Cross-compiling for aarch64

`tpm-ops` links `libtss2` (a C library), so a cross build needs an **aarch64
sysroot** that provides it (along with glibc, the crt startup objects, and
libcrypto). Get a sysroot with any of the methods below, then build against it:

```bash
rustup target add aarch64-unknown-linux-gnu
sudo apt install gcc-aarch64-linux-gnu        # cross linker

SYSROOT=/path/to/aarch64-sysroot ./scripts/cross-build-aarch64.sh
```

The script wires up the cross linker, `--sysroot`, and pkg-config, then reports
the binary's arch, `NEEDED` libraries, and the highest glibc symbol version it
requires — so you can confirm it matches your target before deploying.

**Getting a sysroot** — pick one:

1. **arm64 multiarch packages** (simplest, distro-generic):
   ```bash
   sudo dpkg --add-architecture arm64
   sudo apt update
   sudo apt install libtss2-dev:arm64 libc6-dev:arm64 libssl-dev:arm64
   SYSROOT=/ ./scripts/cross-build-aarch64.sh
   ```
   The resulting binary needs the target's glibc to be at least as new as the
   sysroot's.

2. **Copy from your target device** (exact ABI match — the binary is linked
   against the target's own libraries):
   ```bash
   ./scripts/pull-device-sysroot.sh user@host   # rsyncs /usr/lib + /usr/include
   ./scripts/cross-build-aarch64.sh             # uses .build/aarch64-sysroot
   ```

3. **A Yocto / vendor SDK** — `source` its `environment-setup-*` script (it sets
   `CC` and `--sysroot`), then
   `cargo build --target aarch64-unknown-linux-gnu --release`.

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

# PCR extend / reset (see "PCR extend safety rule" below)
tpm-ops pcr extend -i 23 -d "tamper"
tpm-ops pcr reset -i 23
tpm-ops pcr extend -i 0 -d "measurement" --force   # refused without --force

# Ephemeral signing
tpm-ops sign "message"
tpm-ops sign "message" --ecc

# Persistent keys
tpm-ops key create --algo rsa --persist 0x81000001
tpm-ops key list
tpm-ops sign "message" --key 0x81000001
tpm-ops verify "message" --key 0x81000001 --sig <hex>
tpm-ops key delete 0x81000001

# PCR-policy-bound key: signing only works while PCR 23 matches the value
# captured at key-creation time (see "PCR-policy-bound keys" below).
tpm-ops key create --algo ecc --persist 0x81000002 --policy-pcrs 23
tpm-ops sign "message" --key 0x81000002 --policy-pcrs 23
tpm-ops pcr extend -i 23 -d "tamper"
tpm-ops sign "message" --key 0x81000002 --policy-pcrs 23   # refused by the TPM
tpm-ops pcr reset -i 23
tpm-ops sign "message" --key 0x81000002 --policy-pcrs 23   # succeeds again

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

### PCR extend safety rule

PCR extends are irreversible until reboot, and PCRs 0-15 cannot be reset at
all. On the target platform, PCR 0 (firmware) and PCR 7 (secure boot state)
are the sealing PCRs for production — extending either would corrupt the
firmware-measurement baseline that sealed secrets and attestation depend on.

- `pcr extend` refuses any index outside `{16, 23}` unless `--force` is
  passed; the refusal message names the risk.
- `pcr reset` refuses any index outside `{16, 23}` unconditionally — those
  are the only PCRs resettable from locality 0 on this platform.

PCR 16 is the debug PCR and PCR 23 is reserved for application use, so both
commands work on them without confirmation.

### PCR-policy-bound keys

`key create --policy-pcrs <list>` binds a persistent signing key's auth
policy to the current value of the given PCRs (via a trial `PolicyPCR`
session, the same machinery `seal`/`unseal` use for data). Password
authentication is disabled on the key (`user_with_auth = false`); the TPM
will only perform a signing operation under a real `PolicyPCR` session that
proves the current PCR state matches.

**The PCR list is not recoverable from the key.** A policy digest is a
one-way hash — the TPM has no way to report which PCRs a key's policy
covers, so `sign --key <handle> --policy-pcrs <list>` requires the caller to
supply the same list used at `key create` time. Getting this list wrong
looks identical, from the TPM's point of view, to genuine PCR drift: the
sign is refused either way. Record the PCR list alongside the handle when
you provision a policy-bound key.

`sign` performs no client-side check of whether current PCR state satisfies
the policy — the TPM alone decides. A refusal surfaces as:

```
Error: Sign refused by TPM: current PCR state does not satisfy the key's policy
```

`key list` marks policy-bound keys with `policy-bound` in its output.

### Quote trust model

`quote-verify` deliberately does not trust the nonce, PCR label, or AK public
key carried inside the quote blob. The verifier must provide:

- the challenge nonce it issued;
- the expected SHA-256 PCR selection; and
- a SHA-256 fingerprint of the AK public area obtained through a trusted
  provisioning channel.

Challenge nonces must contain 16 to 64 bytes. When `--nonce` is omitted during
quote generation, the TPM RNG is read until a complete 32-byte nonce is
available.

The current `quote` command creates an ephemeral AK, so its fingerprint changes
for every quote. This is suitable for local round-trip diagnostics when the
fingerprint is transferred over an authenticated channel. A production remote
attestation deployment should provision and pin a stable AK identity.

The hardware test suite reserves persistent handles `0x81000FFC` through
`0x81000FFF` (`0x81000FFC` is used by the policy-bound-key test). It refuses
to run if any of those handles are occupied and never deletes a pre-existing
key.

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

## Supply-chain security

`Cargo.lock` is committed so builds, audits, and SBOMs resolve the same dependency
versions. CI performs the following checks:

- RustSec vulnerability and informational-warning scanning on every push and
  pull request, plus a weekly rescan for newly published advisories;
- 90-day retention of the machine-readable RustSec JSON report;
- CycloneDX 1.5 JSON SBOM generation with `cargo-cyclonedx`;
- 90-day retention of the SBOM as a workflow artifact; and
- a signed GitHub SBOM attestation for builds pushed to `main`.

To reproduce the checks locally:

```bash
cargo install cargo-audit --version 0.22.2 --locked
cargo audit --deny warnings

cargo install cargo-cyclonedx --version 0.5.9 --locked
cargo cyclonedx --format json --spec-version 1.5
```

---

## Hardware

Tested on **Raspberry Pi 5** with **Infineon SLB9672** TPM 2.0 over SPI (RP1 SPI0 CS1).

---

## License

[MIT](LICENSE)
