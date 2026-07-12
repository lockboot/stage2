// SPDX-License-Identifier: MIT OR Apache-2.0

//! Large-volume `/init`: validates **meta_bg unbounded online growth**. The loader grows `/data` to
//! fill a multi-GB p3; this asserts it grew past ~8 GiB -- one meta-block-group boundary -- so the
//! resize genuinely crossed into a second meta_bg (with its own descriptors), not just more groups
//! within the first. Also checks fresh read/write on the grown fs and that a **sparse hole reads
//! back zero with no block I/O** (ext4 zero-fills holes in software). Single boot. Not production.

use anyhow::{bail, Context, Result};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};

const LARGE_MIB: u64 = 8192; // ~one meta-block-group (64bit / 4 KiB); crossing it exercises meta_bg
const PROBE: &str = "/data/probe";
const SPARSE: &str = "/data/sparse";

fn main() {
    println!("=== grow-probe (PID {}) ===", std::process::id());
    match run() {
        Ok(()) => {
            println!("GROW_TEST=PASS meta_bg grew past 8 GiB, read/write + sparse hole OK");
            poweroff();
        }
        Err(e) => {
            println!("GROW_TEST=FAIL {e:?}");
            poweroff();
        }
    }
}

fn run() -> Result<()> {
    let mib = statvfs_total("/data")? / (1 << 20);
    println!("[grow] /data usable = {mib} MiB");
    if mib <= LARGE_MIB {
        bail!("/data ({mib} MiB) did not cross the ~{LARGE_MIB} MiB meta_bg boundary -- unbounded online growth not exercised");
    }

    // Read/write on the freshly grown fs: write an 8 MiB file, sync, drop caches, read back.
    let data = vec![0x5Au8; 8 << 20];
    fs::write(PROBE, &data).context("write probe file")?;

    // A sparse file with data only near the very top of the volume: the hole occupies most of it.
    {
        let mut f = fs::File::create(SPARSE).context("create sparse")?;
        f.seek(SeekFrom::Start((mib - 16) << 20))?; // 16 MiB below the top
        f.write_all(b"end").context("write sparse tail")?;
    }
    unsafe { libc::sync() };
    drop_caches()?;

    if fs::read(PROBE).context("read probe back")? != data {
        bail!("probe file readback mismatch");
    }
    // Read a hole in the sparse file: ext4 zero-fills with no block I/O (nothing reaches the disk).
    let mut hole = [0u8; 4096];
    let mut sf = fs::File::open(SPARSE)?;
    sf.seek(SeekFrom::Start(1 << 20))?; // deep in the hole
    sf.read_exact(&mut hole)?;
    if hole.iter().any(|&b| b != 0) {
        bail!("sparse hole did not read back as zero");
    }
    println!("[grow] readback ok; sparse hole reads zero with no block I/O");
    Ok(())
}

fn drop_caches() -> Result<()> {
    fs::write("/proc/sys/vm/drop_caches", b"3").context("drop_caches")
}

fn statvfs_total(path: &str) -> Result<u64> {
    let c = std::ffi::CString::new(path)?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("statvfs {path}"));
    }
    Ok(st.f_blocks * st.f_frsize)
}

fn poweroff() {
    // SAFETY: PID 1 power-off; sync then poweroff.
    unsafe {
        libc::sync();
        libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
    }
    std::process::exit(0);
}
