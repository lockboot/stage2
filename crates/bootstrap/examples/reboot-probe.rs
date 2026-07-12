// SPDX-License-Identifier: MIT OR Apache-2.0

//! Boot-through-harness **reboot** test (Option 1: in-guest reboot within one QEMU
//! invocation — the same swtpm + disk span the reset, so the derived key and the data
//! both persist). Self-detecting and bounded:
//!   boot 1 (counter 0): partition, dm-crypt, write a sentinel, `reboot()`;
//!   boot 2 (counter 1): re-derive the key, dm-crypt, read the sentinel back —
//!                       PASS if it survived (proves stable key + persistence + that the
//!                       ESP survived the GPT rewrite so stage0 re-booted), else FAIL.
//! A plaintext boot counter on the (unencrypted) runtime partition bounds it to two
//! boots and distinguishes "key unstable" from a hang. Not production.

use anyhow::Result;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

const RUNTIME_LBAS: u64 = 65536; // 32 MiB reserved runtime partition
const COUNTER_OFF: u64 = 0; // plaintext boot counter, start of the runtime partition
const SENTINEL_OFF: u64 = 1 << 20; // 1 MiB into the encrypted data device
const SENTINEL: &[u8] = b"LOCKBOOT-REBOOT-PROBE-sentinel-v1";

enum Outcome {
    Pass(u32),
    WroteRebooting,
    Fail(u32),
}

fn main() {
    println!("=== reboot-probe ===");
    match run() {
        Ok(Outcome::Pass(n)) => {
            println!("REBOOT_TEST=PASS sentinel survived reboot (boot #{n})");
        }
        Ok(Outcome::WroteRebooting) => {
            println!("boot 1: wrote sentinel, rebooting");
            reboot_restart();
            return; // unreached
        }
        Ok(Outcome::Fail(n)) => {
            println!("REBOOT_TEST=FAIL sentinel missing after reboot (boot #{n}) — key unstable?");
        }
        Err(e) => println!("reboot-probe error: {e:?}"),
    }
    println!("=== reboot-probe done, powering off ===");
    poweroff();
}

fn run() -> Result<Outcome> {
    let key = tpm_derive::derive_disk_key()?;
    let device = blockdev::find_boot_device()?;
    let (runtime, data) = blockdev::ensure_partitions(&device, RUNTIME_LBAS)?;
    let mapper = blockdev::crypt_open("data", &data, &key)?;

    let boot = read_u32(&runtime, COUNTER_OFF)?; // 0 on the very first boot
    write_u32(&runtime, COUNTER_OFF, boot + 1)?; // survives (runtime part is plaintext)
    println!("boot_device={} boot#{}", device.display(), boot + 1);
    // Diagnostics: is the key stable across the reboot? did the p3 ciphertext persist?
    println!("key_fp={}", hex(&key[..8]));
    println!(
        "p3_raw@sentinel={}",
        hex(&read_raw(&data, SENTINEL_OFF, 16)?)
    );
    for (i, v) in tpm_derive::read_all_pcrs()? {
        println!("pcr{i:02}={}", hex(&v[..8]));
    }

    if sentinel_matches(&mapper)? {
        return Ok(Outcome::Pass(boot + 1));
    }
    if boot == 0 {
        write_sentinel(&mapper)?;
        return Ok(Outcome::WroteRebooting);
    }
    Ok(Outcome::Fail(boot + 1))
}

fn read_raw(dev: &Path, off: u64, len: usize) -> Result<Vec<u8>> {
    let mut f = OpenOptions::new().read(true).open(dev)?;
    f.seek(SeekFrom::Start(off))?;
    let mut b = vec![0u8; len];
    f.read_exact(&mut b)?;
    Ok(b)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn read_u32(dev: &Path, off: u64) -> Result<u32> {
    let mut f = OpenOptions::new().read(true).open(dev)?;
    f.seek(SeekFrom::Start(off))?;
    let mut b = [0u8; 4];
    f.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn write_u32(dev: &Path, off: u64, v: u32) -> Result<()> {
    let mut f = OpenOptions::new().write(true).open(dev)?;
    f.seek(SeekFrom::Start(off))?;
    f.write_all(&v.to_le_bytes())?;
    f.sync_all()?;
    Ok(())
}

fn sentinel_matches(mapper: &Path) -> Result<bool> {
    let mut f = OpenOptions::new().read(true).open(mapper)?;
    f.seek(SeekFrom::Start(SENTINEL_OFF))?;
    let mut b = vec![0u8; SENTINEL.len()];
    f.read_exact(&mut b)?;
    Ok(b == SENTINEL)
}

fn write_sentinel(mapper: &Path) -> Result<()> {
    let mut f = OpenOptions::new().write(true).open(mapper)?;
    f.seek(SeekFrom::Start(SENTINEL_OFF))?;
    f.write_all(SENTINEL)?;
    f.sync_all()?;
    Ok(())
}

fn reboot_restart() {
    if std::process::id() == 1 {
        // SAFETY: PID 1 warm reboot; sync then request restart.
        unsafe {
            libc::sync();
            libc::reboot(libc::LINUX_REBOOT_CMD_RESTART);
        }
    }
    std::process::exit(0);
}

fn poweroff() {
    if std::process::id() == 1 {
        // SAFETY: PID 1 power-off; sync then request poweroff.
        unsafe {
            libc::sync();
            libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
        }
    }
    std::process::exit(0);
}
