# tpm-ops documentation

- **[concepts.md](concepts.md)** — the TPM 2.0 ideas this tool exercises (SRK and the key
  hierarchy, transient vs. persistent handles, PCRs, PolicyPCR trial vs. real sessions, sealing,
  attestation), explained as implemented here. Start here if you're new to TPM 2.0.
- **[commands.md](commands.md)** — full command reference with real examples and exit codes.
- **[blob-formats.md](blob-formats.md)** — on-disk spec for the `TPM_OPS_SEALED_V1` and
  `TPM_OPS_QUOTE_V1` blob formats: every field, the magic-line rule, and the versioning policy.
- **[security-model.md](security-model.md)** — what the tool protects against and what it
  doesn't, the quote trust model, the `pcr extend`/`reset` safety rule, and an honest limitations
  section. Read this before relying on any of this for something that matters.
- **[building.md](building.md)** — native build, aarch64 cross-compiling via a sysroot, and
  testing against `swtpm`.
