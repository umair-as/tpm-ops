# Security model

What `tpm-ops` actually protects against, the trust boundaries built into each command, and where
those protections currently fall short on the reference target. Read this before relying on any
of it for something that matters.

## What the tool protects against

- **Private key exfiltration.** Every signing key `tpm-ops` creates (`key create`, and the
  ephemeral keys `sign`/`quote` create on the fly) has `sensitiveDataOrigin = true` and is never
  exported — the private key material is generated inside the TPM and never crosses the ESAPI
  boundary in cleartext. `key export-pub` only ever exports the public half.
- **Secrets at rest, conditional on platform state.** `seal`/`unseal` bind arbitrary small
  payloads to a `PolicyPCR` policy: the TPM will not release the data unless the named PCRs
  currently hold the value they held at seal time.
- **Signing, conditional on platform state.** `key create --policy-pcrs` extends the same idea to
  a signing key: the TPM will not perform a signing operation with that key unless the named PCRs
  match. See [concepts.md](concepts.md#policy-bound-signing-keys).
- **Remote proof of PCR state at a point in time.** `quote`/`quote-verify` produce and check a
  TPM-signed statement of PCR values plus a replay-preventing nonce.

All of the above depend on PCRs actually reflecting something meaningful — see
**Limitations** below for why that's not automatic.

## Quote trust model

`quote-verify` deliberately does **not** trust the nonce, PCR selection, or AK public key carried
inside the quote blob (see [blob-formats.md](blob-formats.md#tpm_ops_quote_v1)). The verifier must
independently supply:

- `--nonce` — the challenge it issued, not one read back from the blob;
- `--pcrs` — the PCR selection it expects to have been quoted, not one read back from the blob;
- `--ak-pub-sha256` — a SHA-256 fingerprint of the AK's public area, obtained through a channel
  the verifier already trusts (out of band from the quote itself).

Verification cross-checks the signed `TPMS_ATTEST` structure against all three independently, and
*also* checks that the blob's own metadata agrees with them — an inconsistency between "what the
blob claims" and "what the TPM actually signed" is itself a rejection reason. The reasoning: a
blob is untrusted input by definition. If `quote-verify` trusted blob-internal values for the
things that matter (which nonce was challenged, which PCRs were meant, whose key this is), an
attacker who controls the blob could simply assert favorable values for all three and the
signature check alone wouldn't catch it — the signature only proves the *quoted* PCR digest and
nonce are self-consistent, not that they're the ones the verifier actually cares about.

## Why `sign` performs no client-side policy pre-check

`sign --key <handle> --policy-pcrs <list>` starts a real `PolicyPCR` session and asks the TPM to
sign through it — full stop. It does not first read the named PCRs and compare them against
anything. This is intentional: the entire point of a policy-bound key is that *the TPM* is the
sole arbiter of whether the current platform state satisfies the policy. A client-side pre-check
would let a compromised or modified client simply skip the check and call the signing operation
directly — which would still fail, because the guard that actually matters is inside the TPM, not
in `tpm-ops`. Adding a redundant client-side check would only create the appearance of a second
line of defense that doesn't add one.

(`unseal_from_file`'s check that the requested `--pcrs` matches the blob's recorded `--pcrs` is a
different thing: it's a client-side *usage* check — catching "you asked for the wrong PCR list"
before wasting a round trip — not a security boundary. The TPM's own `PolicyPCR` check still runs
regardless and is what actually decides whether the secret is released.)

## PCR extend/reset safety rule

PCR extends are irreversible until reboot, and PCRs 0–15 cannot be reset at all through this tool.
`pcr extend` therefore refuses any index outside `{16, 23}` unless `--force` is passed, and the
refusal names the risk explicitly. `pcr reset` refuses any index outside `{16, 23}`
**unconditionally** — there is no override, because those are the only PCRs resettable from
locality 0 in the first place; a bad reset attempt on any other PCR is a confusing TPM-level
failure rather than a useful one.

If you do pass `--force` to extend a boot-measurement PCR (0–15): understand that this change
persists until the next reboot, cannot be undone, and will invalidate any sealed data or
policy-bound key whose policy covers that PCR.

## Platform boot security model on this target

Measured boot — PCRs reflecting "this specific firmware/kernel actually ran unmodified" — is not
achievable on the RPi5 + SLB9672 reference target in any near-term supportable way. This is not a
missing feature to be filed and eventually fixed; it's the result of a deliberate platform design
decision plus two independent implementation gaps below it:

- **The RPi5's own security model is *signed* boot, not measured boot, by design.** The bootROM
  requires firmware signed by both the Raspberry Pi key and a customer key whose hash is burned
  into OTP; nothing in the chain extends a PCR. A Raspberry Pi engineer has stated the platform's
  position on measured boot directly: it's "somewhat fragile," since a malicious bootloader "could
  just lie about the hashes to the TPM." This is not expected to change — verified boot is the
  platform's actual answer, and it's a legitimate one; it's simply not attestable the way PCR
  measurement is. (See the [RPi5 secure/measured/encrypted boot thread](https://forums.raspberrypi.com/viewtopic.php?t=374103).)
- **U-Boot has no RP1 SPI driver**, and the SLB9672 sits on RP1's SPI bus (`tpm_tis_spi spi0.1`
  unlike RPi4, where SPI is SoC-native). The Feb 2025 SUSE RFC series that brought RPi5 support to
  U-Boot added PCIe/RP1 enumeration, clocks, GPIO, and Ethernet — but not SPI. Even if it existed,
  U-Boot measuring itself after an unmeasured proprietary bootloader would anchor trust in the
  wrong place, since the point above means nothing upstream of it is measured either.
- **IMA cannot bind to the TPM at boot** — [`raspberrypi/linux#6217`](https://github.com/raspberrypi/linux/issues/6217),
  open and unresolved. IMA initializes from a `late_initcall` before the SPI TPM driver has probed
  the device, so it activates TPM-bypass and `boot_aggregate` reads all-zero. Verified on hardware:
  `ima: No TPM chip found, activating TPM-bypass!` at 0.214s, `tpm_tis_spi spi0.1: 2.0 TPM` at
  5.729s. This is the only tractable blocker of the three — a kernel initcall-ordering problem, not
  a hardware or vendor-policy one — but fixing it would only measure userspace files into PCR 10,
  not firmware or kernel load.
- The obvious escape hatch, UEFI via [`worproject/rpi5-uefi`](https://github.com/worproject/rpi5-uefi),
  was archived 2025-02-04 with no TCG/TPM support ever added.

**The coherent architecture on this target is signed boot for chain integrity, plus the TPM for
key protection and anti-rollback** — a different security model from PCR attestation, not a
degraded version of it. State this as the actual model, not a fallback: the bootROM/EEPROM/`boot.img`
signature chain is what vouches for "the firmware that ran is the firmware we shipped," and the TPM's
job is everything signed boot can't do — keeping key material non-exportable, enforcing anti-rollback
counters, and (see below) still meaningfully binding secrets to *this chip* even without PCR binding.

## Limitations

Stated plainly, not as an apology — know these before you build on top of this tool.

- **PCR-bound features currently bind to an all-zero PCR state on the reference RPi5 + SLB9672
  target**, for the reasons above. Verified on hardware — every PCR reads as all-zero, on every
  boot.

  **What this means in practice:** `seal`/`unseal` and PCR-policy-bound keys work correctly and
  mechanically as designed — the TPM really does refuse the operation if the named PCRs change —
  but on this target they bind to a PCR state that is identical on *every* unmeasured boot of
  *every* device of this kind, not a state that reflects "this specific firmware/kernel actually
  ran unmodified." Sealing to PCR 0 or PCR 7 here does **not** give you firmware-tamper detection;
  it gives you a functional demonstration of the mechanism, which will start providing genuine
  tamper detection only once something in the boot chain actually extends those PCRs. PCR 16
  (debug) and 23 (application-reserved) are unaffected by this — they're meant to be driven
  directly by an application, which is exactly what `pcr extend`/`pcr reset` and the test suite do.

  What's unaffected: features that bind to *this chip* rather than to PCR state don't need any of
  the above. A non-exportable signing key (`key create`) and an empty-PCR-list TPM binding (e.g.
  `systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=`) still defeat the threat of key/disk
  material being copied off the device — they just don't add firmware-tamper detection on top,
  which is the piece that specifically requires working PCR measurement.

- **`quote` uses an ephemeral Attestation Key.** A new AK is created under the SRK on every
  `quote` invocation and flushed afterward, so its fingerprint changes every time. This is fine
  for local round-trip diagnostics (which is what the automated test suite uses it for), but it
  is not sufficient for production remote attestation — a real deployment needs a persistent,
  provisioned AK whose fingerprint is enrolled with a verifier once, not re-established every
  quote. That provisioning flow does not exist yet.

- **`--force` on `pcr extend` is irreversible until reboot**, as noted above. There is no
  software-level undo.
