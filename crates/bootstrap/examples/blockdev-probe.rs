// SPDX-License-Identifier: MIT OR Apache-2.0

//! Boot-through-harness probe for `blockdev` against a real (grown) NVMe boot disk:
//! rebuild the GPT to add p2 (runtime) + p3 (data) after the ESP, get the kernel to
//! re-read the table, dm-crypt p3 with the TPM-derived key, and round-trip a sentinel —
//! confirming the plaintext survives the crypt mapping and is *ciphertext* on p3. Then
//! powers off. Not production — a test payload run as stage2 under the QEMU harness.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};

const RUNTIME_LBAS: u64 = 65536; // 32 MiB reserved runtime partition
const OFFSET: u64 = 1 << 20; // 1 MiB into the crypt device
const SENTINEL: &[u8] = b"LOCKBOOT-BLOCKDEV-PROBE-v1-persist";

fn main() {
    println!("=== blockdev-probe ===");
    if let Err(e) = run() {
        println!("blockdev-probe error: {e:?}");
    }
    println!("=== blockdev-probe done, powering off ===");
    poweroff();
}

fn run() -> anyhow::Result<()> {
    let key = tpm_derive::derive_disk_key()?; // PCR-bound; workload binding tested elsewhere

    let device = blockdev::find_boot_device()?;
    println!("boot_device={}", device.display());
    let (runtime, data) = blockdev::ensure_partitions(&device, RUNTIME_LBAS)?;
    println!("runtime={} data={}", runtime.display(), data.display());

    let mapper = blockdev::crypt_open("data", &data, &key)?;
    println!("mapper={}", mapper.display());

    // Write a sentinel through the crypt device, flush, read it back.
    {
        let mut f = OpenOptions::new().read(true).write(true).open(&mapper)?;
        f.seek(SeekFrom::Start(OFFSET))?;
        f.write_all(SENTINEL)?;
        f.sync_all()?;
        let mut buf = vec![0u8; SENTINEL.len()];
        f.seek(SeekFrom::Start(OFFSET))?;
        f.read_exact(&mut buf)?;
        println!("sentinel_roundtrip_ok={}", buf == SENTINEL);
    }

    // The same offset on the raw partition must NOT be the plaintext (i.e. it's encrypted).
    {
        let mut f = OpenOptions::new().read(true).open(&data)?;
        f.seek(SeekFrom::Start(OFFSET))?;
        let mut buf = vec![0u8; SENTINEL.len()];
        f.read_exact(&mut buf)?;
        println!("encrypted_on_disk={}", buf != SENTINEL);
    }
    Ok(())
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
