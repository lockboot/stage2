// SPDX-License-Identifier: MIT OR Apache-2.0

//! Boot-through-harness `/init` for the loader: a minimal payload baked into the test
//! `rootfs.erofs`. It runs as PID 1 *after* the loader has pivoted onto the overlay root, and
//! verifies the whole contract across an in-guest reboot:
//!   - the config JSON arrives on stdin (fd 0);
//!   - the stage1 + stage2 attestations are present in `/run/lockboot/`;
//!   - `/data` (encrypted) **persists** across the reboot;
//!   - the overlay root is **ephemeral** — a file written to `/` on boot 1 is gone on boot 2
//!     (proving runtime writes cannot persist to shadow the verity'd code).
//! Boot counter + sentinel live on `/data`. Not production.

use anyhow::{bail, Context, Result};
use std::fs;
use std::io::Read;
use std::path::Path;

const SENTINEL: &[u8] = b"LOCKBOOT-PIVOT-PERSIST-v1";
const EPHEMERAL_PROBE: &str = "/ephemeral-probe"; // written to the overlay root (tmpfs upper)
const COUNTER: &str = "/data/boot-count";
const SENTINEL_FILE: &str = "/data/sentinel";

fn main() {
    println!("=== pivot-init (PID {}) ===", std::process::id());
    match run() {
        Ok(true) => {
            println!("PIVOT_TEST=PASS /data persisted and overlay root was ephemeral");
            poweroff();
        }
        Ok(false) => {
            println!("boot 1: contract up, wrote sentinel + ephemeral probe, rebooting");
            reboot();
        }
        Err(e) => {
            println!("PIVOT_TEST=FAIL {e:?}");
            poweroff();
        }
    }
}

fn run() -> Result<bool> {
    // Config transparently forwarded on stdin.
    let mut cfg = String::new();
    std::io::stdin()
        .read_to_string(&mut cfg)
        .context("read config from stdin")?;
    if cfg.trim().is_empty() {
        bail!("empty config on stdin — loader did not forward the doc");
    }
    println!(
        "config_len={} has_container={}",
        cfg.len(),
        cfg.contains("container")
    );

    // Attestation chain in the ephemeral tmpfs.
    for a in ["/run/lockboot/stage1.attest", "/run/lockboot/stage2.attest"] {
        println!(
            "attest {a}: {}",
            if Path::new(a).exists() {
                "present"
            } else {
                "MISSING"
            }
        );
    }
    if !Path::new("/run/lockboot/stage2.attest").exists() {
        bail!("stage2 attestation missing");
    }

    let boot: u32 = fs::read_to_string(COUNTER)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    fs::write(COUNTER, (boot + 1).to_string()).context("write boot counter to /data")?;

    let ephemeral_present = Path::new(EPHEMERAL_PROBE).exists();
    let sentinel_present = fs::read(SENTINEL_FILE)
        .map(|b| b == SENTINEL)
        .unwrap_or(false);
    println!(
        "boot#{} ephemeral_probe_present={ephemeral_present} data_sentinel_present={sentinel_present}",
        boot + 1
    );

    if boot == 0 {
        // Write to the root (tmpfs upper — must NOT survive) and to /data (encrypted — must survive).
        fs::write(EPHEMERAL_PROBE, b"x").context("write ephemeral probe to /")?;
        fs::write(SENTINEL_FILE, SENTINEL).context("write sentinel to /data")?;
        unsafe { libc::sync() };
        return Ok(false); // reboot
    }

    if !sentinel_present {
        bail!("/data sentinel missing after reboot — persistence broke or key unstable");
    }
    if ephemeral_present {
        bail!(
            "/ephemeral-probe survived the reboot — overlay root is NOT ephemeral (integrity risk)"
        );
    }
    Ok(true)
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
