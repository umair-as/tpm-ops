# On-disk blob formats

`seal` and `quote` write plain-text `key=value` files. Both formats share the same shape and the
same parsing rules:

- **Magic first line.** The parser rejects the file outright if the first line (trimmed) doesn't
  exactly match the expected magic string.
- **`key = value` lines**, one per field, in any order, blank lines ignored. Values are hex-encoded
  byte strings unless noted otherwise.
- **Every field is required.** A missing field is a parse error naming the missing key, not a
  default or a silently-absent field.
- **No schema versioning beyond the magic line.** If a field is ever added or removed, the magic
  string gains a new version suffix (e.g. `_V2`) so old and new blobs are never silently
  misinterpreted as each other.

Neither format is designed for cross-tool interop — they exist so `tpm-ops` can round-trip its
own output. Treat the field names below as the only stable contract.

## `TPM_OPS_SEALED_V1`

Written by `seal`, read by `unseal`.

```
TPM_OPS_SEALED_V1
pcrs=0,7
policy_digest=02e3642b3e29eeccfffd8031c00a6f0a0febe5ceea2f6ef6b0322fe81598cf31
private=00206e07292eff80d18fbc0a76d01b6aa8ca47d12ed13cc5a8d10639ff345858d1a...
public=0008000b00000492002002e3642b3e29eeccfffd8031c00a6f0a0febe5ceea2f6ef6b...
```

| Field           | Meaning |
|-----------------|---------|
| `pcrs`           | Comma-separated, sorted, deduplicated PCR indices the data was sealed against (SHA-256 bank only), e.g. `0,7`. `unseal` compares this against its own `--pcrs` argument **before** talking to the TPM — a mismatch here is a client-side rejection, distinct from the TPM refusing the policy itself. |
| `policy_digest`  | Hex-encoded `PolicyPCR` digest computed via a trial session over `pcrs` at seal time. Informational — `unseal` recomputes its own digest against current PCR state and asks the TPM to authorize against it; this field is not itself checked against the TPM at unseal time. |
| `private`        | Hex-encoded `TPM2B_PRIVATE` — the encrypted sensitive area, only usable when loaded under the same SRK it was created under. |
| `public`         | Hex-encoded `TPM2B_PUBLIC` — the object's public area, including the `authPolicy` digest that actually gates the TPM's `Unseal` command. |

## `TPM_OPS_QUOTE_V1`

Written by `quote`, read by `quote-verify`.

```
TPM_OPS_QUOTE_V1
algo=rsa
pcrs=0,7
nonce=56b224cae9cfa05d48d59b6e0a84b83cbde2e51a0cb33527b58b5d5a0df657f9
attest=ff54434780180022000b0a89aacf98bfc0779432a6f02e73c235edc65b1f32058a38c2f...
sig=87b7f33963d136a8d74189b2491d74ab89696509fd29852cae91330fc2a70ad7adbda97a...
ak_pub=0001000b00040072000000100014000b0800000000000100...
```

| Field    | Meaning |
|----------|---------|
| `algo`   | `rsa` or `ecc` — which AK algorithm signed the quote. Determines how `sig` is decoded. |
| `pcrs`   | Comma-separated PCR indices the quote was generated over (SHA-256 bank only). |
| `nonce`  | Hex-encoded qualifying data (16–64 bytes) supplied to `TPM2_Quote`, intended to be a verifier-issued challenge. |
| `attest` | Hex-encoded, marshalled `TPMS_ATTEST` structure — the signed statement itself (PCR digest, clock, firmware version, the nonce as `extraData`, etc). |
| `sig`    | Hex-encoded signature over `attest`: raw bytes for RSA-SSA, `R \|\| S` (32 bytes each) for ECDSA. |
| `ak_pub` | Hex-encoded `TPM2B_PUBLIC` of the (ephemeral) Attestation Key that signed the quote. |

**None of `pcrs`, `nonce`, or `ak_pub` in this blob are trusted by `quote-verify` on their own** —
they're cross-checked against independent `--pcrs`, `--nonce`, and `--ak-pub-sha256` arguments the
verifier must supply. See [security-model.md](security-model.md#quote-trust-model) for why.
