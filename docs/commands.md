# Command reference

Every example below was actually run against a software TPM (`swtpm`) — see
[building.md](building.md#testing-with-swtpm) for how to start one. Exit codes follow the usual
Unix convention: `0` on success, non-zero on failure. `tpm-ops` prints human-readable errors as
`Error: ...` and returns `1`.

All commands accept these global flags before or after the subcommand:

| Flag | Meaning |
|---|---|
| `-t`/`--tcti <TCTI>` | Transport (default `device:/dev/tpmrm0`) |
| `--json` | Emit one machine-readable JSON object on stdout instead of human text. Logs/progress always go to stderr, so `tpm-ops --json <cmd> \| jq .` works with no stderr redirect. Every object carries a `schema` field (e.g. `tpm-ops.pcr.v1`) so consumers can detect shape changes. |
| `-v`/`--verbose` (repeatable) | `-v` info, `-vv` debug, `-vvv` trace. Default is warnings/errors only. `RUST_LOG` overrides. |
| `-q`/`--quiet` | Errors only. |
| `--color auto\|always\|never` | Default `auto` (honours `NO_COLOR` and whether stderr is a TTY). Only colors the `Error:` prefix. |
| `-y`/`--yes` | Skip the `key delete` confirmation prompt. Implied automatically when stdin isn't a TTY. |

```
tpm-ops [-t <TCTI>] [--json] [-v...] [-q] [--color <mode>] [-y] <COMMAND>
```

Examples below use `--tcti "swtpm:port=2321"`; drop it (or point it at your resource manager) to
run against real hardware. A hidden `tpm-ops completions <bash|zsh|fish|...>` subcommand prints a
shell completion script.

## `version`

Prints the binary version and embedded git revision. Does not need a TPM — it runs before any
TPM context is created.

```
$ tpm-ops version
tpm-ops 0.2.0
git: 3ac682e
```

## `info`

Manufacturer, firmware version, and spec revision.

```
$ tpm-ops --tcti "swtpm:port=2321" info
Manufacturer: IBM (0x49424D00)
Vendor: SW   TPM
Firmware: 8217.4131
Spec Revision: 1.64

TPM is accessible and responding [OK]
```

## `selftest [--full]`

Runs the TPM's self-test. `--full` is slower but more thorough than the default incremental test.

```
$ tpm-ops --tcti "swtpm:port=2321" selftest
TPM self-test: PASSED
  Mode: incremental
  Result: OK

TPM health check [OK]
```

## `random --bytes <n>`

Hardware TRNG output, 1–48 bytes (`-b`/`--bytes`, default 32).

```
$ tpm-ops --tcti "swtpm:port=2321" random -b 16
Random bytes (16 bytes):
c0a48bfeab894e4288c3ed1e6ad1dfdb
```

## `hash <data> [--algo sha256|sha384|sha1]`

Hashes data using the TPM's own hash engine (not a local library). `<data>` is treated as hex if
it looks like an even-length hex string, otherwise as raw text. `--file <path>` or `-` (either as
the positional argument or `--file -`) reads raw bytes from a file or stdin instead — no hex
auto-detection there, since that only makes sense for a short command-line argument.

```
$ tpm-ops --tcti "swtpm:port=2321" hash "hello world"
SHA256 hash:
b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
```

## `pcr [--index <n>] [--algo sha256|sha1]`

Reads a PCR register. Both flags default (`--index 0`, `--algo sha256`), so bare `pcr` reads
PCR 0. This is the read-only default action of the `pcr` command — see below for its
`extend`/`reset` subcommands.

```
$ tpm-ops --tcti "swtpm:port=2321" pcr -i 0
PCR[0] (SHA256):
0000000000000000000000000000000000000000000000000000000000000000
```

### `pcr extend --index <n> --data <text> [--force]`

Extends a PCR with the SHA-256 hash of `<data>`. Refuses any index outside `{16, 23}` unless
`--force` is passed — see [security-model.md](security-model.md#pcr-extendreset-safety-rule) for
why. Prints both the input digest and the PCR value after extending.

```
$ tpm-ops --tcti "swtpm:port=2321" pcr extend -i 23 -d "boot-stage-1"
Extended PCR 23 (SHA-256)
  Input digest: 95050a102e877420925766d332216dded0fb07d46c20d747803686e3ea3e2708
  New PCR value: 9fa13964b5253198715672904ecb5435a77d3dddc060d1846396a456e3270c26

PCR extend [OK]

$ tpm-ops --tcti "swtpm:port=2321" pcr extend -i 0 -d "x"; echo "exit=$?"
Error: Refusing to extend PCR 0: only PCR 16 (debug) and PCR 23 (application) are extended
without confirmation. Extending a boot-measurement PCR is irreversible until reboot and can
invalidate anything sealed or attested against its current value. Pass --force to proceed anyway.
exit=1
```

### `pcr reset --index <n>`

Resets a PCR to its default value. Refuses any index outside `{16, 23}` **unconditionally** —
there is no `--force` override, because those are the only PCRs resettable from locality 0 on
this platform.

```
$ tpm-ops --tcti "swtpm:port=2321" pcr reset -i 23
Reset PCR 23
  PCR value: 0000000000000000000000000000000000000000000000000000000000000000

PCR reset [OK]

$ tpm-ops --tcti "swtpm:port=2321" pcr reset -i 0; echo "exit=$?"
Error: Refusing to reset PCR 0: only PCR 16 and PCR 23 are resettable from locality 0. PCRs 0-15
cannot be reset without a platform-level action (e.g. reboot).
exit=1
```

## `sign <data> [--algo rsa|ecc] [--key <handle>] [--policy-pcrs <list>]`

Without `--key`: creates an **ephemeral** primary signing key (RSA-2048 by default, `--algo ecc`
for ECC P-256), signs `<data>`, and flushes the key — nothing persists. `--ecc` still works as a
deprecated alias for `--algo ecc`. `<data>` also accepts `--file <path>` or `-` for stdin (must be
valid UTF-8 text — `sign`'s data has always been a string).

With `--key <handle>` (alias `--handle`, matching `key delete`/`key export-pub`'s flag form):
signs using a persistent key created by `key create`. Algorithm is detected from the key itself,
not from `--algo`/`--ecc`.

```
$ tpm-ops --tcti "swtpm:port=2321" sign "hello" --key 0x81000001
Data: hello
Digest (SHA256): 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
Key: 0x81000001 (persistent, RSA)

Signature (RSA-SSA):
Algorithm: RSA-SSA
Signature: 87b7f339...cec4

Data signed with persistent key [OK]
```

`--policy-pcrs <list>` signs through a real `PolicyPCR` session instead of a password session —
required for, and only valid on, a policy-bound key (`key create --policy-pcrs`). See
[concepts.md](concepts.md#policy-bound-signing-keys) and the worked example below.

## `verify <data> --key <handle> (--sig <hex> | --sig-file <path>)`

Verifies a signature produced by `sign --key`. `--sig` is raw signature bytes as hex for RSA, or
`R||S` (64 bytes / 128 hex chars) for ECC. An RSA-2048 signature is a 512-character hex string, so
`--sig-file <path>` (or `--sig-file -` for stdin) is usually more convenient than passing it as a
command-line argument.

```
$ tpm-ops --tcti "swtpm:port=2321" verify "hello" --key 0x81000001 --sig 87b7f339...cec4
Data: hello
Key: 0x81000001 (RSA)

Signature VALID [OK]

$ tpm-ops --tcti "swtpm:port=2321" verify "goodbye" --key 0x81000001 --sig 87b7f339...cec4; echo "exit=$?"
Data: goodbye
Key: 0x81000001 (RSA)

Signature INVALID
Error: Verification failed: the signature is not valid (associated with parameter number 2)
exit=1
```

## `key create --algo rsa|ecc --persist <handle> [--policy-pcrs <list>]`

Creates a persistent signing key as a child of the SRK. Handle must be in the owner persistent
range `0x81000001`–`0x817FFFFF` and not already in use.

```
$ tpm-ops --tcti "swtpm:port=2321" key create --algo rsa --persist 0x81000001
Created RSA signing key at 0x81000001
  Algorithm: RSA-2048 / RSA-SSA / SHA-256
  Parent: SRK (Owner hierarchy)
  Type: persistent, unrestricted signing

Key persisted [OK]
```

With `--policy-pcrs <list>` (comma-separated PCR indices, e.g. `0,7`), the key is bound to the
current value of those PCRs instead of a password — see
[concepts.md](concepts.md#policy-bound-signing-keys):

```
$ tpm-ops --tcti "swtpm:port=2321" key create --algo ecc --persist 0x81000003 --policy-pcrs 23
Created ECC signing key at 0x81000003
  Algorithm: ECC P-256 / ECDSA / SHA-256
  Parent: SRK (Owner hierarchy)
  Type: persistent, unrestricted signing, policy-bound (PCR 23)
  Policy: PCR(SHA256:23)
  Policy digest: 3c87a4b3fb85ebeea58c5fb36ac22d3f280cec27a9f6dd0fa23be9ce560deec8
  NOTE: the policy digest is one-way — the TPM cannot recover this PCR list from the key. Pass
  --policy-pcrs 23 to `sign` for every signature.

Key persisted [OK]
```

**The full policy-bound key lifecycle**, PCR state changing underneath the key:

```
$ tpm-ops --tcti "swtpm:port=2321" sign "attest me" --key 0x81000003 --policy-pcrs 23
[... Signature (ECDSA) ...]
Data signed with persistent key [OK]

$ tpm-ops --tcti "swtpm:port=2321" sign "attest me" --key 0x81000003; echo "exit=$?"
Error: Key 0x81000003 is policy-bound (password auth disabled) — pass --policy-pcrs <list>
matching the PCRs it was created with
exit=1

$ tpm-ops --tcti "swtpm:port=2321" pcr extend -i 23 -d "tamper"
[... PCR extend [OK] ...]

$ tpm-ops --tcti "swtpm:port=2321" sign "attest me" --key 0x81000003 --policy-pcrs 23; echo "exit=$?"
Error: Sign refused by TPM: current PCR state does not satisfy the key's policy
exit=1

$ tpm-ops --tcti "swtpm:port=2321" pcr reset -i 23
[... PCR reset [OK] ...]

$ tpm-ops --tcti "swtpm:port=2321" sign "attest me" --key 0x81000003 --policy-pcrs 23
[... Signature (ECDSA) ...]
Data signed with persistent key [OK]
```

## `key list`

Enumerates all persistent handles in an aligned, headered table, with their algorithm,
restricted/unrestricted status, and usage. Policy-bound keys are marked `policy-bound`; the SRK
and `tpm-ops test`'s reserved handle range (`0x81000FFC`–`0x81000FFF`) are flagged as such under
NOTES so it's obvious which entries are unsafe or pointless to delete.

```
$ tpm-ops --tcti "swtpm:port=2321" key list
  HANDLE       ALGO  RESTRICTED   USAGE     NOTES
  0x81000000   RSA   restricted   decrypt   SRK — do not delete
  0x81000001   RSA   unrestricted signing
  0x81000002   ECC   unrestricted signing
  0x81000003   ECC   unrestricted signing   policy-bound

4 persistent handle(s) found.
```

## `key delete <handle>` (or `--handle <handle>`)

Evicts a persistent key. Refuses to delete the SRK (`0x81000000`). Prompts for confirmation when
stdin is a TTY (`--yes` or a non-TTY/`--json` invocation skips the prompt — this is what lets
`tpm-ops test`, which deletes its 4 reserved-handle test keys per run, never block).

```
$ tpm-ops --tcti "swtpm:port=2321" key delete 0x81000001
Delete persistent key 0x81000001? This cannot be undone. [y/N] y
Deleted persistent key at 0x81000001 [OK]
```

## `key export-pub <handle>` (or `--handle <handle>`)

Exports the public portion of a persistent key as PEM (`RSA PUBLIC KEY` for RSA,
`PUBLIC KEY`/SubjectPublicKeyInfo for ECC).

```
$ tpm-ops --tcti "swtpm:port=2321" key export-pub 0x81000001
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAlx+gc+tVjXN2oGb9UaSSIEZ+frXhGy8ZXLNkhzK45gaz7mzVyL4S
...
-----END RSA PUBLIC KEY-----
```

## `seal <data> --pcrs <list> --out <file>`

Seals `<data>` (small payloads only — a few hundred bytes at most) to the current value of the
named PCRs and writes a [`TPM_OPS_SEALED_V1`](blob-formats.md#tpm_ops_sealed_v1) blob to `<file>`.

```
$ tpm-ops --tcti "swtpm:port=2321" seal "my-secret-value" --pcrs 0,7 --out sealed.blob
Sealed data written to sealed.blob
  Bytes: 15
  Policy: PCR(SHA256:0,7)
  Policy digest: 02e3642b3e29eeccfffd8031c00a6f0a0febe5ceea2f6ef6b0322fe81598cf31

Seal operation [OK]
```

## `unseal --in <file> --pcrs <list>`

Unseals data from a blob written by `seal`, if the current PCR state still satisfies the policy.
`--pcrs` must match the list used at seal time (checked client-side, since it's stored in the
blob) *and* the TPM's policy check must pass (checked by the TPM, not client-side).

```
$ tpm-ops --tcti "swtpm:port=2321" unseal --in sealed.blob --pcrs 0,7
Unsealed 15 bytes
Data (hex): 6d792d7365637265742d76616c7565
Data (utf8): my-secret-value

Unseal operation [OK]

$ tpm-ops --tcti "swtpm:port=2321" unseal --in sealed.blob --pcrs 0; echo "exit=$?"
Error: PCR selection mismatch: blob uses '0,7' but command used '0'
exit=1
```

## `quote --pcrs <list> [--nonce <hex>] [--algo rsa|ecc] [--out <file>]`

Generates a TPM2_Quote over the named PCRs with an ephemeral Attestation Key, printing (and
optionally saving to a [`TPM_OPS_QUOTE_V1`](blob-formats.md#tpm_ops_quote_v1) blob) everything a
verifier needs. If `--nonce` is omitted, 32 random bytes are read from the TPM.

```
$ tpm-ops --tcti "swtpm:port=2321" quote --pcrs 0,7 --nonce <64-hex-chars> --out quote.blob
PCRs:        SHA-256:0,7
Nonce:       56b224ca...657f9
Algo:        RSA
AK SHA-256:  5b84e7f6e2d8b05789626e65fca5281ce507640e01275f06ebbf24d07f96266c
Firmware:    0x54ADD49834D47F73
PCR digest:  f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b

Quote written to quote.blob

Quote [OK]
```

## `quote-verify <file> --nonce <hex> --ak-pub-sha256 <hex> --pcrs <list>`

Verifies a quote blob against three independently supplied expectations — see
[security-model.md](security-model.md#quote-trust-model) for why none of them are read from the
blob's own metadata.

```
$ tpm-ops --tcti "swtpm:port=2321" quote-verify quote.blob \
    --nonce 56b224ca...657f9 \
    --ak-pub-sha256 5b84e7f6...96266c \
    --pcrs 0,7
Signature:   VALID [OK]

--- Attested State ---
PCRs:        SHA-256:0,7 (verified)
Nonce:       56b224ca...657f9 (verified)
AK SHA-256:  5b84e7f6...96266c (trusted)
Clock:       1136900 ms  (resets=3781220454, restarts=3777435736)
Firmware:    0x54ADD49834D47F73
PCR digest:  f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b

Quote verify [OK]

$ tpm-ops --tcti "swtpm:port=2321" quote-verify quote.blob --nonce 00...00 --ak-pub-sha256 5b84e7f6...96266c --pcrs 0,7; echo "exit=$?"
Error: Quote nonce does not match the verifier's expected nonce
exit=1
```

## `quote-fingerprint <file>`

Prints a quote blob's AK fingerprint — useful for enrolling a key's fingerprint the first time,
or for reading it back off a blob you already trust for another reason. This is **not**
verification: it reads blob-internal data with no cryptographic check attached, exactly the kind
of value `quote-verify` deliberately refuses to trust when it comes from inside a blob. Only trust
the fingerprint it prints if you already trust this blob's provenance through some other channel.

```
$ tpm-ops --tcti "swtpm:port=2321" quote-fingerprint quote.blob
AK SHA-256: 5b84e7f6e2d8b05789626e65fca5281ce507640e01275f06ebbf24d07f96266c

This is what the blob claims — it is NOT verified or trusted.
Only trust a fingerprint obtained through a separate, out-of-band channel.
```

## `test`

Runs the full validation suite (12 tests as of this writing) against whatever TPM `--tcti`
points at — every command above, plus negative-path checks (tampered signatures, wrong PCR
policy, PCR state changed after key creation). Reserves persistent handles `0x81000FFC`–
`0x81000FFF` for the duration and refuses to run if any are already occupied. Idempotent: running
it twice in a row leaves the TPM in the same state both times.

```
$ tpm-ops --tcti "swtpm:port=2321" test
=== TPM Test Suite ===

--- Test 1: TPM Self-Test ---
...
--- Test 12: Policy-Bound Key (PCR Policy Session) ---
...
=== All Tests Passed! ===
```
