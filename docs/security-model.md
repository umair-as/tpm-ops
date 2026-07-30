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

## Limitations

Stated plainly, not as an apology — know these before you build on top of this tool.

- **PCR-bound features currently bind to an all-zero PCR state on the reference RPi5 + SLB9672
  target.** Nothing in the current boot chain measures into the TPM there: the firmware does not
  extend PCRs, the bootloader stage has no support for this particular TPM's bus path, and the
  kernel's own measurement subsystem falls back to a TPM-bypass mode before the TPM driver has
  even probed the device (an initialization-ordering issue, not a fundamentally missing
  capability). Verified on hardware — every PCR reads as all-zero, on every boot.

  **What this means in practice:** `seal`/`unseal` and PCR-policy-bound keys work correctly and
  mechanically as designed — the TPM really does refuse the operation if the named PCRs change —
  but on this target they bind to a PCR state that is identical on *every* unmeasured boot of
  *every* device of this kind, not a state that reflects "this specific firmware/kernel actually
  ran unmodified." Sealing to PCR 0 or PCR 7 here does **not** give you firmware-tamper detection;
  it gives you a functional demonstration of the mechanism, which will start providing genuine
  tamper detection only once something in the boot chain actually extends those PCRs. PCR 16
  (debug) and 23 (application-reserved) are unaffected by this — they're meant to be driven
  directly by an application, which is exactly what `pcr extend`/`pcr reset` and the test suite do.

- **`quote` uses an ephemeral Attestation Key.** A new AK is created under the SRK on every
  `quote` invocation and flushed afterward, so its fingerprint changes every time. This is fine
  for local round-trip diagnostics (which is what the automated test suite uses it for), but it
  is not sufficient for production remote attestation — a real deployment needs a persistent,
  provisioned AK whose fingerprint is enrolled with a verifier once, not re-established every
  quote. That provisioning flow does not exist yet.

- **`--force` on `pcr extend` is irreversible until reboot**, as noted above. There is no
  software-level undo.
