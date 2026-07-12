// SPDX-License-Identifier: MIT OR Apache-2.0

//! Boot-through-harness `/init` for the loader: a comprehensive property-checker baked into the
//! test `rootfs.erofs`. Runs as PID 1 *after* the loader has pivoted, and verifies the essential
//! properties across an in-guest reboot:
//!   boot 1: [config] the JSON arrives on stdin; [attest] the attestation chain is present;
//!           [resize] /data grew far past the tiny baked base; write a persist sentinel + a root
//!           ephemeral probe; reboot.
//!   boot 2: [persist] the /data sentinel survived; [integrity] the overlay-root probe did NOT
//!           (ephemeral). Then PASS.
//! Not production.

use anyhow::{bail, Context, Result};
use std::fs;
use std::io::Read;
use std::path::Path;

const SENTINEL: &[u8] = b"LOCKBOOT-PIVOT-PERSIST-v1";
const EPHEMERAL_PROBE: &str = "/ephemeral-probe"; // written to the overlay root (tmpfs upper)
const COUNTER: &str = "/data/boot-count";
const SENTINEL_FILE: &str = "/data/sentinel";
const BASE_MIB: u64 = 64; // the baked ext4 base; a grown /data must be well past this

fn main() {
    println!("=== pivot-init (PID {}) ===", std::process::id());
    match run() {
        Ok(true) => {
            println!("PIVOT_TEST=PASS all properties verified");
            poweroff();
        }
        Ok(false) => {
            println!("boot 1: properties up, wrote sentinel + ephemeral probe, rebooting");
            reboot();
        }
        Err(e) => {
            println!("PIVOT_TEST=FAIL {e:?}");
            poweroff();
        }
    }
}

fn run() -> Result<bool> {
    let boot: u32 = fs::read_to_string(COUNTER)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    fs::write(COUNTER, (boot + 1).to_string()).context("write boot counter to /data")?;
    println!("boot#{}", boot + 1);

    if boot == 0 {
        check_config()?;
        check_attestations()?;
        check_resized()?;
        fs::write(EPHEMERAL_PROBE, b"x").context("write ephemeral probe to /")?;
        fs::write(SENTINEL_FILE, SENTINEL).context("write sentinel to /data")?;
        unsafe { libc::sync() };
        return Ok(false); // reboot
    }

    // boot 2: persistence + ephemerality.
    let sentinel_ok = fs::read(SENTINEL_FILE)
        .map(|b| b == SENTINEL)
        .unwrap_or(false);
    let ephemeral_gone = !Path::new(EPHEMERAL_PROBE).exists();
    println!("[persist] /data sentinel present = {sentinel_ok}");
    println!("[integrity] overlay-root ephemeral (probe gone) = {ephemeral_gone}");
    if !sentinel_ok {
        bail!("/data sentinel missing after reboot -- persistence broke or key unstable");
    }
    if !ephemeral_gone {
        bail!("/ephemeral-probe survived the reboot -- overlay root is NOT ephemeral (integrity risk)");
    }
    Ok(true)
}

/// [config] the transparent JSON arrives verbatim on stdin.
fn check_config() -> Result<()> {
    let mut cfg = String::new();
    std::io::stdin()
        .read_to_string(&mut cfg)
        .context("read config from stdin")?;
    if cfg.trim().is_empty() {
        bail!("empty config on stdin -- loader did not forward the doc");
    }
    println!(
        "[config] {} bytes on stdin, has_container={}",
        cfg.len(),
        cfg.contains("container")
    );
    Ok(())
}

/// [attest] stage2 attestation is present; stage1's copy is best-effort (tmpfs->tmpfs).
fn check_attestations() -> Result<()> {
    let s1 = Path::new("/run/lockboot/stage1.attest").exists();
    let s2 = Path::new("/run/lockboot/stage2.attest").exists();
    println!("[attest] stage1={} stage2={}", present(s1), present(s2));
    if !s2 {
        bail!("stage2 attestation missing from /run/lockboot");
    }
    Ok(())
}

/// [resize] /data grew online to fill p3 -- its usable size is far past the tiny baked base.
fn check_resized() -> Result<()> {
    let mib = statvfs_total("/data")? / (1 << 20);
    println!("[resize] /data usable = {mib} MiB (baked base was {BASE_MIB} MiB)");
    if mib < BASE_MIB * 2 {
        bail!("/data did not grow past the base ({mib} MiB) -- online resize failed");
    }
    Ok(())
}

// ---- helpers ----

fn statvfs_total(path: &str) -> Result<u64> {
    let c = std::ffi::CString::new(path)?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("statvfs {path}"));
    }
    Ok(st.f_blocks * st.f_frsize)
}

fn present(b: bool) -> &'static str {
    if b {
        "present"
    } else {
        "MISSING"
    }
}

fn reboot() {
    // SAFETY: PID 1 warm reboot; sync then restart.
    unsafe {
        libc::sync();
        libc::reboot(libc::LINUX_REBOOT_CMD_RESTART);
    }
    std::process::exit(0);
}

fn poweroff() {
    // SAFETY: PID 1 power-off; sync then poweroff.
    unsafe {
        libc::sync();
        libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
    }
    std::process::exit(0);
}
