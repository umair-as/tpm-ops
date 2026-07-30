# TPM 2.0 concepts, as exercised by tpm-ops

This is not a general TPM 2.0 tutorial. It explains the specific mechanisms `tpm-ops` uses,
in the order you'll meet them, so the command reference and security model make sense without
having to read the TPM 2.0 specification first.

## The key hierarchy: SRK, primary keys, and child keys

A TPM does not store keys the way a filesystem stores files. Every key is either:

- **Primary** — derived deterministically from the TPM's internal seed plus a template. Creating
  the same template under the same hierarchy and seed always yields the same key. Primary keys
  are expensive to create (RSA-2048 generation takes several seconds).
- **Child** — created *under* a parent key (primary or another child), and encrypted for storage
  outside the TPM as a private/public blob pair. Cheap to create, but must be reloaded into the
  TPM before use.

`tpm-ops` uses a single **Storage Root Key (SRK)**, a primary key created once under the owner
hierarchy and persisted at the reserved handle `0x81000000`. `create_srk` does the ~20-second
RSA-2048 generation exactly once, evicts it to that persistent handle, and every later run just
loads the existing handle. **Every other key `tpm-ops` creates — signing keys, policy-bound
keys — is a child of the SRK.** The SRK itself is never flushed or deleted (`key delete` refuses
to remove it) because every other persisted key depends on it existing.

User signing keys land in the owner persistent range `0x81000001`–`0x817FFFFF`; `key create`
picks the handle you ask for.

## Transient vs. persistent handles

A freshly created or loaded key occupies a **transient** handle — a slot in the TPM's limited
object memory. Transient handles disappear when flushed or when the session ends; if you never
flush one, you eventually exhaust the TPM's object slots (real hardware has far fewer slots than
a software TPM tolerates).

A **persistent** handle is different: `evict_control` copies a key into non-volatile storage at
a fixed handle number, where it survives power cycles and reloads instantly (no re-derivation, no
private-blob loading). `key create --persist 0x81000001` creates a transient child key, then
immediately persists it and flushes the transient copy — you're left with only the persistent
handle.

Every code path that creates a transient handle for its own use (an ephemeral signing key, an
attestation key, a loaded sealed object) must flush it afterward. This isn't optional bookkeeping:
a long-running process (like `tpm-ops test`, which exercises dozens of TPM operations in one
invocation) will otherwise run the TPM out of transient object slots partway through.

## PCRs: Platform Configuration Registers

A PCR is not a value you can set directly. It only supports two operations:

- **Extend** — replace `PCR[n]` with `hash(PCR[n] || new_data)`. One-way and cumulative: you
  cannot undo an extend, only make the register reflect a different (still cumulative) history.
- **Reset** — return a PCR to its default value (usually all-zero). Only a subset of PCRs are
  resettable, and only from certain localities (see [security-model.md](security-model.md) for
  which ones `tpm-ops` allows).

PCRs exist so the TPM can attest to *what ran*, not just *sign something*. Firmware, bootloader,
and kernel each extend PCRs with measurements of the next stage before handing off control — in
principle, an unmodified boot chain always produces the same PCR values, and a tampered one
produces different ones. `tpm-ops` reads PCR values with `pcr`, and can extend/reset them
directly (`pcr extend`/`pcr reset`) for demonstrating PCR-gated behavior without a real measured
boot chain in place — see [security-model.md](security-model.md) for the honest limitations of
that on the reference target.

## PolicyPCR: trial sessions vs. real sessions

A PCR *policy* is a way to say "this operation is only authorized if these PCRs currently hold
these values" without hard-coding the values as a password. `tpm-ops` uses exactly one policy
assertion, `PolicyPCR`, in two different session types:

- **Trial session** (`SessionType::Trial`) — never actually authorizes anything. You start one,
  apply `PolicyPCR` against a PCR selection, and ask the TPM for the resulting **policy digest**.
  This is a pure computation: given a PCR selection and its current values, the digest is
  deterministic. `tpm-ops` uses a trial session at *creation* time — when sealing data
  (`seal`) or creating a policy-bound key (`key create --policy-pcrs`) — to compute the digest
  that becomes the object's permanent auth policy.
- **Real session** (`SessionType::Policy`) — actually gates a command. You start one, apply
  `PolicyPCR` against a PCR selection, and then pass the session to the gated operation
  (`unseal`, or `sign` on a policy-bound key). The TPM checks that the resulting policy digest
  matches the one baked into the object; if it doesn't, the operation is refused with
  `TPM_RC_POLICY_FAIL`. A real policy session is **consumed by one use** — `tpm-ops` starts a
  fresh one for every `unseal` or policy-bound `sign`.

The critical property: a policy digest is a **one-way hash of a PCR selection and a target
value**. Given only the digest stored in an object, the TPM (or an attacker who reads it) cannot
recover which PCRs it covers or what values they must hold. That's why `sign --policy-pcrs`
requires you to supply the PCR list again at sign time — `tpm-ops` has no way to look it up.

Trial and real policy sessions are TPM resources like any other handle and must be flushed after
use; `tpm-ops` wraps this in a `SessionGuard` (RAII, same pattern as the `KeyGuard` used for
transient key handles).

## Sealing: binding a secret to PCR state

`seal` creates a TPM object that holds arbitrary data (up to the TPM's small sealed-data limit)
instead of a key, with its `authPolicy` field set to a `PolicyPCR` digest computed via a trial
session over the PCRs you name. The object's attributes disable password authorization entirely
(`userWithAuth = false`) and require policy authorization for any use
(`adminWithPolicy = true`) — so there is no back door: the *only* way to unseal is to open a real
policy session over the same PCR selection and prove the current values still produce that
digest.

`unseal` loads the sealed object back under the SRK, opens a real policy session, and asks the
TPM to release the data through that session. If any of the named PCRs has changed since sealing,
`PolicyPCR` rejects it and `unseal` fails — not because `tpm-ops` checked the PCR values itself,
but because the TPM's own authorization check failed.

## Policy-bound signing keys

`key create --policy-pcrs <list>` applies the same idea to a signing key instead of sealed data:
the key's object attributes disable password auth and require policy auth, with the auth policy
set to a PolicyPCR digest computed at creation time. The key is otherwise a normal unrestricted
signing key (RSA-2048/RSA-SSA or ECC P-256/ECDSA) — the private key material never leaves the
TPM either way; what changes is *when* the TPM will use it.

`sign --key <handle> --policy-pcrs <list>` opens a fresh real policy session over the PCR list
you supply and signs through it. As with `unseal`, there is no client-side comparison of "do the
current PCRs match what I expect" — the TPM's authorization check is the only thing standing
between a signature request and a signature.

## Attestation: TPM2_Quote

A quote is a signed statement from the TPM: "at this moment, these PCRs held these values, and
this arbitrary qualifying data (a nonce) was included to prevent replay." `quote` creates an
ephemeral **restricted** signing key (an Attestation Key, or AK) under the SRK — restricted
because only a restricted key can produce the special `TPMS_ATTEST`-and-sign operation `Quote`
performs; an ordinary unrestricted signing key cannot. The AK, the signed attestation structure,
and the raw signature are written to a blob for later verification.

`quote-verify` re-derives the AK's fingerprint from the blob, checks it against a fingerprint the
verifier already trusts (not one read from the blob itself — see
[security-model.md](security-model.md)), verifies the signature over the attestation structure,
and cross-checks the nonce and PCR selection the verifier expected against what was actually
signed.

See also: [docs/commands.md](commands.md) for the full command reference,
[docs/blob-formats.md](blob-formats.md) for the exact on-disk formats mentioned above, and
[docs/security-model.md](security-model.md) for what all of this does and does not protect
against on the reference hardware target.
