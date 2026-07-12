// SPDX-License-Identifier: MIT OR Apache-2.0

//! `bootstrap` — the generic Lock.Boot stage2 **loader** (admitted, PCR-14-measured, PID 1).
//!
//! It carries no payload-specific data. A container image is *appended* to it as a zip
//! ([`payload`]); stage1 measures the whole loader+zip into PCR 14. The loader brings up
//! TPM-sealed persistence, pivots onto the image as an immutable dm-verity'd root under an
//! **ephemeral** tmpfs overlay, and `exec /init` — handing the workload the exact JSON config it
//! received on stdin. "Run this Docker container under lockboot."
//!
//! Boot: read our appended payload → bind the config into PCR15 → derive the disk key →
//! partition → verity-mount the erofs (overlay lower) → overlay(erofs ro + tmpfs upper) as the new
//! root → encrypted `/data` inside it → attestation chain → `switch_root` + `exec /init`.

mod pivot;

use anyhow::{Context, Result};
use std::io::Read;

const LOWER: &str = "/lower"; // verity erofs, overlay lowerdir (ro)
const UPPERFS: &str = "/upperfs"; // tmpfs holding the overlay upper + work dirs
const NEWROOT: &str = "/newroot"; // the assembled overlay root we pivot onto
const DATA: &str = "/newroot/data"; // encrypted persistent store, inside the new root
const RUN: &str = "/newroot/run"; // ephemeral tmpfs in the new root
const ATTEST_DIR: &str = "/newroot/run/lockboot";
const INIT: &str = "/init";
const STAGE1_ATTEST: &str = "/tmp/stage1.attest";

fn main() {
    // PID 1 must never exit: a returning init panics the kernel ("Attempted to kill init"), which on
    // a cloud VM spins a vCPU at 100% forever. Own our failure instead -- log it, then power off.
    if let Err(e) = run() {
        fatal_halt(e);
    }
}

/// The loader body. Returns only on error; on success `switch_root_exec` execs `/init` and never
/// returns.
fn run() -> Result<()> {
    // Our appended payload (rootfs erofs + verity params + ext4 base), read from /proc/self/exe.
    let payload = payload::load_self().context("load appended payload")?;

    // Bind the verbatim stdin config into PCR15, then rewind fd 0 so /init reads it unchanged.
    let mut cfg = Vec::new();
    std::io::stdin()
        .read_to_end(&mut cfg)
        .context("read config from stdin")?;
    tpm_derive::extend_config_pcr(&tpm_derive::config_digest(&cfg))
        .context("bind config into PCR15")?;
    // SAFETY: fd 0 is a seekable memfd (stage1's model); rewind it for the downstream /init.
    unsafe { libc::lseek(0, 0, libc::SEEK_SET) };

    // XTS data key, bound to PCR14 (code+rootfs) + PCR15 (config) + the rest.
    let key = tpm_derive::derive_data_key().context("derive data key")?;

    // Partitions on the boot device.
    let device = blockdev::find_boot_device().context("find boot device")?;
    let (runtime_part, data_part) =
        blockdev::ensure_partitions(&device, runtime_lbas(payload.rootfs_erofs.len()))
            .context("ensure partitions")?;

    // Verity runtime (ro) = the overlay lower; flush-if-mismatch.
    let rt = blockdev::RuntimeImage {
        blob: &payload.rootfs_erofs,
        root_hash: &payload.verity.root_hash,
        salt: &payload.verity.salt,
        data_blocks: payload.verity.data_blocks,
    };
    pivot::mkdir(LOWER);
    let flushed = blockdev::verity_mount(&runtime_part, &rt, LOWER).context("verity runtime")?;

    // Ephemeral writable root: overlay(lower = erofs ro+verity, upper = tmpfs). The merged root is
    // pure verity'd erofs at boot; runtime writes hit RAM and never persist to shadow the code.
    pivot::mkdir(UPPERFS);
    pivot::mount("tmpfs", UPPERFS, "tmpfs", 0, None).context("mount tmpfs upper")?;
    pivot::mkdir(&format!("{UPPERFS}/u"));
    pivot::mkdir(&format!("{UPPERFS}/w"));
    pivot::mkdir(NEWROOT);
    pivot::mount(
        "overlay",
        NEWROOT,
        "overlay",
        0,
        Some(&format!(
            "lowerdir={LOWER},upperdir={UPPERFS}/u,workdir={UPPERFS}/w"
        )),
    )
    .context("mount overlay root")?;

    // Encrypted persistent /data inside the new root — the ONLY thing that survives a reboot.
    pivot::mkdir(DATA);
    let reinit = blockdev::crypt_mount_or_mkfs(&data_part, &key, &payload.data_base, DATA)
        .context("encrypted /data")?;

    // Attestation chain in an ephemeral tmpfs /run/lockboot for /init to read.
    pivot::mkdir(RUN);
    pivot::mount("tmpfs", RUN, "tmpfs", 0, None).context("mount tmpfs /run")?;
    pivot::mkdir(ATTEST_DIR);
    write_attestations(&cfg);

    eprintln!(
        "loader: device={} runtime_flushed={flushed} data_reinit={reinit} -> switch_root {INIT}",
        device.display()
    );

    // Pivot onto the overlay and exec /init (fd 0 = rewound config memfd).
    pivot::switch_root_exec(NEWROOT, INIT)
}

/// Fatal boot error handler for PID 1. Log the error, give a 60 s grace window for console/serial
/// capture, then issue a clean ACPI power-off so a failed instance *stops* rather than spinning a
/// vCPU on a kernel panic (or looping via `panic=`-reboot). Never returns. In the QEMU harness the
/// power-off makes qemu exit, so a failed boot ends the test instead of hanging.
fn fatal_halt(err: anyhow::Error) -> ! {
    const GRACE_SECS: libc::c_uint = 60;
    eprintln!("loader: FATAL: {err:?}");
    eprintln!("loader: powering off in {GRACE_SECS}s");
    // SAFETY: PID 1 shutdown path -- flush, wait out the grace window, power off, never return.
    unsafe {
        libc::sync();
        libc::sleep(GRACE_SECS);
        libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
        // If power-off is somehow refused, park forever rather than exit -> kernel panic.
        loop {
            libc::pause();
        }
    }
}

/// Copy stage1's attestation over and drop our own alongside it. Best-effort: the loader must not
/// fail to boot because attestation evidence couldn't be written.
fn write_attestations(cfg: &[u8]) {
    if let Ok(a) = std::fs::read(STAGE1_ATTEST) {
        let _ = std::fs::write(format!("{ATTEST_DIR}/stage1.attest"), a);
    }
    // TODO: a real TPM quote over PCR14/15. For now, record the config digest we bound so the
    // chain has a stage2 artifact; the quote fills in with the master-service work.
    let d = tpm_derive::config_digest(cfg);
    let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
    let _ = std::fs::write(format!("{ATTEST_DIR}/stage2.attest"), hex);
}

/// p2 size in 512-byte LBAs to hold the runtime image (erofs ++ hash tree), with headroom, so
/// `ensure_partitions` always makes p2 fit without a hand-tuned constant (it re-aligns to 1 MiB).
fn runtime_lbas(img_len: usize) -> u64 {
    const SLACK: u64 = 1 << 20; // 1 MiB
    (img_len as u64 + SLACK).div_ceil(512)
}
