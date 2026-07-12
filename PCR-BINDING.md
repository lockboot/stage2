# PCR binding for the encrypted data partition

Reference for how the lockboot/containers data partition binds to TPM PCRs, which PCRs
are bound vs. excluded and why, and the reboot-stability analysis (including IMA/PCR10).

## Overview

The data partition (`p3`) is dm-crypt (`aes-xts-plain64`). Its key is **derived from the
TPM and gated by a `TPM2_PolicyPCR` session** — see `crates/tpm-derive` and vaportpm's
`DeriveOps::derive_pcr_bound`. The key is a deterministic function of:

1. the TPM's stable **Storage Primary Seed** (per-instance, persists across reboots), and
2. the live values of a chosen **PCR set**, enforced by the TPM at use time — the TPM
   reads the PCRs itself during `PolicyPCR`, so a caller cannot substitute values, and
3. **PCR15** = a SHA-256 over the entire `container` workload config (image + all
   args/env/mounts), extended by `bootstrap` *before* deriving (see the workload-binding
   section below).

Any change to a bound PCR, the workload config, or the TPM yields a different key. The old
ciphertext then decrypts to garbage, the ext4 superblock fails to validate, and the
partition is re-initialized. **Fail-closed by construction** — there is no stored key blob
or header to attack; the key is recomputed from the TPM each boot.

Guiding principle (per the project owner): **bind broadly by default** — per-instance keys
make binding "free" (the values differ per instance/vendor, which is fine), and any real
change to firmware / boot chain / policy / payload *should* wipe. Exclude a PCR only with a
specific, documented reason.

## Current bound PCR set

`DISK_KEY_PCRS` in `crates/tpm-derive/src/lib.rs`:

> **Every PCR 0–23 except PCR5 and PCR10.**

i.e. `{0,1,2,3,4, 6,7,8,9, 11,12,13,14,15,16,17,18,19,20,21,22,23}`. PCR15 additionally
carries the workload measurement (below). Two PCRs are excluded, each for a reason:

### PCR5 — excluded (GPT / boot-manager config-and-data)

PCR5 measures the **GPT partition table** (UEFI `EV_EFI_GPT_EVENT`). Confirmed against
EDK2 source: `SecurityPkg/Library/DxeTpm2MeasureBootLib/DxeTpm2MeasureBootLib.c`,
`Tcg2MeasureGptTable` sets `PCRIndex = 5` / `EV_EFI_GPT_EVENT` and hashes an `EFI_GPT_DATA`
= the primary GPT header + every *used* partition entry (non-zero type GUID). Boot
variables go to PCR1, boot-attempt `EV_EFI_ACTION` strings go to PCR4 — **not** PCR5. So on
stock OVMF, PCR5 is GPT-only.

`bootstrap` **rewrites the GPT at runtime** on first boot (adds the runtime `p2` + data
`p3` partitions into the grown volume). That changes the measured GPT, so PCR5 differs on
the *next* boot. Binding it would rebind the disk key on every partition create/grow and
wipe the data. → excluded.

Caveat — **Nitro ≠ OVMF here.** AWS's Nitro TPM PCR profile *defines* PCR5 as *"Boot
Manager Code Configuration and Data **and** GPT Partition Table"* (Nitro runs OVMF + AWS
patches). So on real Nitro/GCP, PCR5 may fold in more than the GPT. Confirm with an
event-log dump on a real instance before trusting PCR5's contents there.

### PCR10 — excluded (IMA); settled, redundant for us

PCR10 is the Linux **IMA** (Integrity Measurement Architecture) PCR
(`CONFIG_IMA_MEASURE_PCR_IDX=10`). It changed across a reboot in testing, and the mechanism
is indirect: IMA, at init, extends PCR10 with a **boot aggregate** = a **hash of PCR0–9**
(the pre-OS measured-boot PCRs), unconditionally when `CONFIG_IMA=y`. That range **includes
PCR5**, so our runtime GPT rewrite (which moves PCR5) moves the boot aggregate, and PCR10
with it.

**Excluding PCR10 loses nothing for us** — it is redundant, not a compromise:

- Its boot aggregate = hash(PCR0–9), and we already bind **PCR0–4, 6, 7, 8, 9
  individually**. So PCR10's only unique, non-deterministic input over what we already bind
  is **PCR5** — the very PCR we deliberately excluded.
- Its other contributions are **module measurements** (the x86 secure-boot arch policy adds
  measure rules — see the IMA analysis below). But all our modules ship inside the **UKI's
  initramfs**, which is measured as one unit into **PCR14** (which we bind). So the module
  code identity is already covered there; the PCR10 measurements are duplicative (and
  deterministic, so not even a stability factor).
- We never use IMA **appraisal** (`security.ima` xattr signatures/hashes).
- And it couldn't be suppressed anyway: `CONFIG_IMA=y` is baked into the prebuilt Fedora
  kernel and the boot aggregate is unconditional, so PCR10 is always extended (see "impact
  of disabling IMA").

## Workload binding (PCR15)

`bootstrap` measures the workload into PCR15 **before** deriving the key, so the disk is
locked to *this code in this exact configuration* — not merely the boot chain. Without it,
any container the operator swaps onto the same boot chain would read the data (the key is
held by the supervisor and bind-mounted into the container).

- `tpm_derive::workload_digest(container)` = SHA-256 over the **entire** `container` config
  (compact JSON, sorted keys — image + command + env + mounts + restart).
- `tpm_derive::extend_workload_pcr(digest)` extends **PCR15** with it.
- Then `derive_disk_key()` (PCR15 is in the bound set).

Different config → different PCR15 → different key → a fresh/empty disk. The image digest
in the config is what containerd pulls and verifies, so "what was measured" == "what runs."
(Canonicalization is serde_json sorted-compact today; RFC 8785 / JCS is the interop-portable
form if a remote verifier ever recomputes it.)

## Per-provider PCR map (AWS Nitro)

From AWS's NitroTPM documentation (PCR0/1 are AWS-controlled and held **constant** across
early-boot-code updates):

| PCR | Contents |
|----:|----------|
| 0 | Core System Firmware executable code |
| 1 | Core System Firmware data |
| 2 | Extended or pluggable executable code |
| 3 | Extended or pluggable firmware data |
| 4 | Boot Manager Code |
| 5 | Boot Manager Code Configuration and Data **and GPT Partition Table** |
| 6 | Host Platform Manufacturer specifics |
| 7 | Secure Boot Policy |
| 8–15 | Defined for use by the static OS (lockboot uses **14** for the UKI+payload chain, **15** for the workload) |
| 16 | Debug |
| 23 | Application Support |

Note the EDK2 vs. TCG/Nitro discrepancy for PCR5 (above): EDK2's implementation routes boot
variables to PCR1 and boot actions to PCR4, leaving PCR5 GPT-only; the Nitro profile's
*definition* is broader. This is why the exact bound set must be confirmed empirically on
each provider.

## The reboot-stability finding (2026-07-11)

**Test:** Option 1 in-guest reboot under the QEMU/swtpm harness — a guest `reboot()`
triggers a QEMU system reset (OVMF re-runs, re-reads the GPT, re-measures PCRs, re-netboots
the UKI), while the *same* swtpm process and disk file persist across the reset. So the SPS
and on-disk data survive, faithfully modelling a real reboot. Driven by
`crates/bootstrap/examples/reboot-probe.rs` (self-detecting via a plaintext boot counter on
the runtime partition).

**Result:** with `{5}` excluded, the reboot **failed** — the encrypted sentinel written on
boot 1 did not decrypt on boot 2. Diagnostics showed:

- the p3 **ciphertext persisted** (raw p3 at the sentinel offset was non-zero on boot 2),
- but the **derived key differed** (`key_fp` changed between boots),
- and a full 24-PCR diff showed **only PCR5 and PCR10 changed**; every other PCR was
  identical across the two boots.

With `{5, 10}` excluded, the reboot **passed** — identical `key_fp` on both boots, sentinel
survived. This both (a) proves the end-to-end reboot-persistence path (ESP survives the GPT
rewrite → stage0 re-boots; disk + encrypted data persist; key is stable) and (b) validates
that excluding PCR5 was necessary.

## IMA in depth (why PCR10 moves, and can it be turned off)

IMA is a Linux integrity subsystem with three policy-driven functions:

- **Measurement** — on a matching file access, hash the file, append to the runtime
  measurement log (`/sys/kernel/security/ima/{ascii,binary}_runtime_measurements`), and
  extend the hash into a TPM PCR (default **PCR10**). For attestation.
- **Appraisal** — verify a file against a known-good value in its `security.ima` xattr
  (hash or signature vs. the `.ima` keyring) before access; can enforce. Local access
  control, no TPM.
- **Audit** — log hashes to the audit subsystem.

It pairs with **EVM** (protects file metadata incl. `security.ima` via `security.evm`) and
the integrity keyrings (`.ima`, `.evm`, `.platform`/`.machine` from UEFI db/MOK).

**What's active on the stage1 kernel** (`CONFIG_IMA=y`, `IMA_ARCH_POLICY=y`,
`IMA_SECURE_AND_OR_TRUSTED_BOOT=y`, PCR idx 10, `ima-ng`/sha256), with **no `ima_policy=` on
the cmdline** (only `lockdown=confidentiality`):

- The **boot aggregate** — added unconditionally at IMA init: `PCR10 ← hash(PCR0–9)`. This
  is the *only* per-reboot-variable input to PCR10 in our boot (it folds in PCR5).
- The **x86 secure-boot arch policy** — active because we boot with Secure Boot, and it
  *cannot be replaced* by a custom policy (only appended). It adds appraise rules (kexec;
  modules if `CONFIG_MODULE_SIG` off — Fedora signs modules, so likely a no-op) and
  trusted-boot **measure** rules on x86 UEFI (module loads → PCR10). These are deterministic
  (same modules, same order every boot) → not a stability factor, and covered by PCR14.

**Impact of disabling IMA — effectively not an option, and moot anyway:**

- **Can't disable at runtime.** `CONFIG_IMA=y` is compiled into the prebuilt Fedora kernel
  (we don't rebuild it), and the boot aggregate is extended into PCR10 unconditionally.
  `ima_appraise=off` disables only *enforcement*, not measurement; `ima_policy=` can only
  *add* rules; there is no `ima=off`. Suppressing PCR10 needs `CONFIG_IMA=n` → a custom
  kernel → not viable.
- **Nothing lockboot relies on IMA for.** Appraisal (signed modules/kexec/firmware) is
  redundant with `lockdown=confidentiality` (blocks unsigned modules) + Secure Boot (gates
  stage0) + dm-verity (runtime partition). Attestation lives in PCR10, but our own chain is
  measured into **PCR14** and the workload into **PCR15** — we don't consume PCR10.

## Resolution (2026-07-11)

**Bind every PCR except {5, 10}; both settled.** PCR5 is the runtime-mutated GPT; PCR10 is
redundant for us (its boot aggregate = hash(PCR0–9), whose inputs we bind individually minus
the excluded PCR5; its module measurements are covered by the UKI measurement in PCR14; we
don't use `security.ima` appraisal) *and* it can't be suppressed on this kernel anyway. So
excluding PCR10 is the correct, no-loss choice, not a compromise.

Rejected: **(b) disable IMA** — infeasible (prebuilt `CONFIG_IMA=y`, unconditional boot
aggregate). Separable/optional: **(c) bake the partition layout into the stage0 snapshot** —
that's really about reclaiming *PCR5* (PCR10 would ride along), and PCR5 measures only the
GPT, which isn't security-critical for us (data integrity is the key; runtime integrity is
dm-verity). Revisit only if binding the GPT itself becomes desirable.

*Optional confirmation:* dump `/sys/kernel/security/ima/ascii_runtime_measurements` (mount
securityfs first) on both boots and diff — expected to show the boot aggregate as the only
varying entry, and to enumerate exactly which modules IMA measures.

## How to reproduce / investigate

```bash
# In-guest reboot test (two boots, one QEMU invocation), prints key_fp + all 24 PCRs/boot:
make test-persist-x86_64 PERSIST_PAYLOAD=reboot-probe
# Diff the two boots' pcrNN= lines to see which PCRs move.
```

- `tpm_derive::read_all_pcrs()` — reads all 24 PCRs (SHA-256 bank) for cross-boot diffing.
- `reboot-probe` prints `key_fp`, the raw p3 ciphertext at the sentinel offset, and every
  PCR on each boot.

## References

- TCG PC Client Platform Firmware Profile — PCR usage, `EV_EFI_GPT_EVENT`, `EV_EFI_ACTION`,
  `EV_EFI_VARIABLE_BOOT`.
- EDK2: `SecurityPkg/Library/DxeTpm2MeasureBootLib/DxeTpm2MeasureBootLib.c`
  (`Tcg2MeasureGptTable`, `PCRIndex = 5`).
- AWS NitroTPM PCR documentation (PCR0–15/16/23 assignments; PCR0/1 constant).
- Linux IMA — [concepts](https://ima-doc.readthedocs.io/en/latest/ima-concepts.html),
  [policy](https://ima-doc.readthedocs.io/en/latest/ima-policy.html),
  [arch policies (LWN)](https://lwn.net/Articles/766754/); boot aggregate over PCR0–9,
  `securityfs` measurement lists.
