// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deterministic, PCR-bound disk-key derivation for `bootstrap`.
//!
//! A thin wrapper over vaportpm's `DeriveOps` (where the TPM I/O + packet marshalling
//! already live, and where this logic folds in once the feature settles). No RNG, no
//! sealed blob, no on-disk header: the key is a deterministic function of the TPM's
//! stable hierarchy seed and the current PCR state. Any PCR drift yields a different
//! key, so the encrypted data partition fails to decrypt to a valid filesystem and is
//! re-initialized (fail closed).

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use vaportpm_attest::{DeriveOps, PcrOps, Tpm, TpmAlg};

// The TPM device path (/dev/tpmrm0) lives in vaportpm's `Tpm::open()`.

/// PCR the workload identity is measured into (stage2's PCR, per the stage1 contract:
/// stage1 leaves PCR15 for the payload). Included in [`DISK_KEY_PCRS`], so extending it
/// binds the workload into the disk key.
const WORKLOAD_PCR: u8 = 15;

/// Canonical digest of the container workload: a SHA-256 over the **entire** `container`
/// config dict — image *and* all args/env/mounts/restart — so the disk key locks to
/// *this code in this exact configuration*, not merely to the image. Canonical form is
/// compact JSON with sorted object keys (serde_json's default `Map` is a `BTreeMap`), so
/// formatting differences don't change the identity. (RFC 8785 / JCS is the fully
/// interop-portable form if a remote verifier ever recomputes this — future hardening.)
pub fn workload_digest(container: &serde_json::Value) -> [u8; 32] {
    let canonical = serde_json::to_vec(container).unwrap_or_default();
    Sha256::digest(canonical).into()
}

/// SHA-256 over the **verbatim** stdin config doc. The loader is transparent — it forwards the
/// exact bytes on to `/init` — so binding the raw bytes into PCR15 (via [`extend_workload_pcr`])
/// locks the disk key to *this config*. Byte-stability across boots is required (stage1 delivers
/// the same user-data memfd every boot).
pub fn config_digest(doc: &[u8]) -> [u8; 32] {
    Sha256::digest(doc).into()
}

/// Extend PCR15 with the workload digest. **Must run before [`derive_disk_key`]** so the
/// derived key is bound to this workload — a different config yields a different PCR15,
/// hence a different key, hence a fresh (empty) disk. Also surfaces the workload in any
/// attestation quote.
pub fn extend_workload_pcr(digest: &[u8; 32]) -> Result<()> {
    let mut tpm = Tpm::open().context("open TPM resource manager")?;
    tpm.pcr_extend_bank(WORKLOAD_PCR, TpmAlg::Sha256, digest)
        .context("extend PCR15 with workload digest")
}

/// Namespace for the encrypted data partition's key — separates it from any other
/// PCR-bound derivation on the same TPM.
const DISK_KEY_LABEL: &[u8] = b"lockboot.containers.diskkey.v1";

/// PCRs the disk key is bound to: **every PCR except PCR5 and PCR10** — bind broadly by
/// default (per-instance keys make it free; values differ per instance/vendor), so any
/// real change to firmware/boot/policy/payload wipes. The two exclusions are settled
/// (2026-07-11), each measured elsewhere or otherwise not additive for us — see
/// PCR-BINDING.md for the full analysis:
///
/// - **PCR5 (GPT):** `bootstrap` rewrites the GPT at runtime (adds p2/p3), so it changes
///   across the first reboot. (On Nitro its profile is even broader than the GPT.)
/// - **PCR10 (IMA):** redundant, not a loss. It carries the IMA *boot aggregate* =
///   hash(PCR0-9) — inputs we already bind individually (0-4,6,7,8,9), minus the
///   deliberately-excluded PCR5 — plus module measurements, which are already covered by
///   the UKI measurement in **PCR14** (all modules ship in the measured initramfs). We
///   never use IMA appraisal (`security.ima` xattrs). And `CONFIG_IMA=y` in the prebuilt
///   Fedora kernel extends PCR10 with the boot aggregate unconditionally, so it couldn't
///   be suppressed short of recompiling the kernel anyway.
const DISK_KEY_PCRS: &[u8] = &[
    0, 1, 2, 3, 4, /* 5 excluded (GPT) */ 6, 7, 8, 9, /* 10 excluded (IMA) */ 11, 12, 13,
    14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
];

/// Diagnostic: read all 24 PCRs (SHA-256 bank) for cross-boot comparison.
pub fn read_all_pcrs() -> Result<Vec<(u8, [u8; 32])>> {
    let mut tpm = Tpm::open().context("open TPM")?;
    let mut out = Vec::new();
    for i in 0u8..24 {
        let r = tpm.pcr_read_bank(&[i], TpmAlg::Sha256)?;
        let mut v = [0u8; 32];
        if let Some((_, d)) = r.iter().find(|(idx, _)| *idx == i) {
            if d.len() == 32 {
                v.copy_from_slice(d);
            }
        }
        out.push((i, v));
    }
    Ok(out)
}

/// Derive the 64-byte dm-crypt key (aes-xts-plain64), bound to the boot-chain PCRs and
/// this TPM. (Used by the plain-dm-crypt probes.)
pub fn derive_disk_key() -> Result<[u8; 64]> {
    let mut tpm = Tpm::open().context("open TPM resource manager")?;
    let bytes = tpm
        .derive_pcr_bound(DISK_KEY_PCRS, DISK_KEY_LABEL, 64)
        .context("derive disk key from TPM")?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("expected 64 derived bytes"))
}

/// Namespace for the authenticated `/data` key — separate label from the plain disk key so the
/// two derivations never alias.
const DATA_KEY_LABEL: &[u8] = b"lockboot.containers.datakey.aead.v1";

/// Derive the 32-byte `aes-gcm-random` AEAD key for the authenticated `/data` partition
/// (dm-integrity + dm-crypt), bound to the same PCR set.
pub fn derive_data_key() -> Result<[u8; 32]> {
    let mut tpm = Tpm::open().context("open TPM resource manager")?;
    let bytes = tpm
        .derive_pcr_bound(DISK_KEY_PCRS, DATA_KEY_LABEL, 32)
        .context("derive AEAD data key from TPM")?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("expected 32 derived bytes"))
}
