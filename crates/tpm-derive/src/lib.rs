// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deterministic, PCR-bound key derivation for the loader.
//!
//! A thin wrapper over vaportpm's `DeriveOps`. No RNG, no sealed blob, no on-disk header: the key
//! is a deterministic function of the TPM's stable hierarchy seed and the current PCR state. Any
//! bound-PCR drift (firmware/boot/policy/code/config) yields a different key, so `/data`'s ext4
//! superblock decrypts to garbage and it is re-initialized (fail closed).

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use vaportpm_attest::{DeriveOps, PcrOps, Tpm, TpmAlg};

// The TPM device path (/dev/tpmrm0) lives in vaportpm's `Tpm::open()`.

/// The PCR stage1 leaves for the payload (the stage1 contract). Included in [`DATA_KEY_PCRS`], so
/// extending it with the config digest binds the config into the data key.
const CONFIG_PCR: u8 = 15;

/// SHA-256 over the **verbatim** stdin config doc. The loader is transparent — it forwards the
/// exact bytes on to `/init` — so binding the raw bytes into PCR15 (via [`extend_config_pcr`])
/// locks the disk key to *this config*. Byte-stability across boots is required (stage1 delivers
/// the same user-data memfd every boot).
pub fn config_digest(doc: &[u8]) -> [u8; 32] {
    Sha256::digest(doc).into()
}

/// Extend PCR15 with the config digest. **Must run before [`derive_data_key`]** so the derived key
/// is bound to this config — a different config yields a different PCR15, hence a different key,
/// hence a fresh (empty) `/data`. Also surfaces the config in any attestation quote.
pub fn extend_config_pcr(digest: &[u8; 32]) -> Result<()> {
    let mut tpm = Tpm::open().context("open TPM resource manager")?;
    tpm.pcr_extend_bank(CONFIG_PCR, TpmAlg::Sha256, digest)
        .context("extend PCR15 with config digest")
}

/// PCRs the data key is bound to: **every PCR except PCR5 and PCR10** — bind broadly by default
/// (per-instance keys make it free; values differ per instance/vendor), so any real change to
/// firmware/boot/policy/payload wipes. The two exclusions are settled, each measured elsewhere or
/// otherwise not additive for us — see PCR-BINDING.md for the full analysis:
///
/// - **PCR5 (GPT):** the loader rewrites the GPT at runtime (adds p2/p3), so it changes across the
///   first reboot. (On Nitro its profile is even broader than the GPT.)
/// - **PCR10 (IMA):** redundant, not a loss. It carries the IMA *boot aggregate* = hash(PCR0-9) —
///   inputs we already bind individually (0-4,6,7,8,9), minus the deliberately-excluded PCR5 —
///   plus module measurements, which are already covered by the UKI measurement in **PCR14** (all
///   modules ship in the measured initramfs). We never use IMA appraisal (`security.ima` xattrs).
///   And `CONFIG_IMA=y` in the prebuilt Fedora kernel extends PCR10 with the boot aggregate
///   unconditionally, so it couldn't be suppressed short of recompiling the kernel anyway.
const DATA_KEY_PCRS: &[u8] = &[
    0, 1, 2, 3, 4, /* 5 excluded (GPT) */ 6, 7, 8, 9, /* 10 excluded (IMA) */ 11, 12, 13,
    14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
];

/// Namespace for the `/data` encryption key on this TPM.
const DATA_KEY_LABEL: &[u8] = b"lockboot.stage2.datakey.xts.v1";

/// Derive the 64-byte `aes-xts-plain64` key (AES-256-XTS = two 256-bit subkeys) for the encrypted
/// `/data` partition (dm-crypt), bound to the PCR set + this TPM's stable hierarchy seed.
pub fn derive_data_key() -> Result<[u8; 64]> {
    let mut tpm = Tpm::open().context("open TPM resource manager")?;
    let bytes = tpm
        .derive_pcr_bound(DATA_KEY_PCRS, DATA_KEY_LABEL, 64)
        .context("derive data key from TPM")?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("expected 64 derived bytes"))
}
