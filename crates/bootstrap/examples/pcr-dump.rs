// SPDX-License-Identifier: MIT OR Apache-2.0

//! Boot-through-harness `/init` that prints the PCR state the payload starts with: every PCR in
//! every bank as `PCR <bank> <nn> <hex>` (the format workspace tools/pcr-replay `--check` reads),
//! plus the sha256 of the config the loader forwarded on stdin (the digest bound into PCR15).
//! Runs as PID 1 after the loader has pivoted (/sys is moved in). Not production.

use std::fs;
use std::io::Read;

fn main() {
    println!("=== pcr-dump (PID {}) ===", std::process::id());
    let mut cfg = Vec::new();
    match std::io::stdin().read_to_end(&mut cfg) {
        Ok(_) => {
            let d = tpm_derive::config_digest(&cfg);
            let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
            println!("CONFIG bytes={} sha256={hex}", cfg.len());
        }
        Err(e) => println!("CONFIG error: {e}"),
    }
    for bank in ["sha1", "sha256", "sha384", "sha512"] {
        for i in 0..24 {
            if let Ok(v) = fs::read_to_string(format!("/sys/class/tpm/tpm0/pcr-{bank}/{i}")) {
                println!("PCR {bank} {i:02} {}", v.trim().to_lowercase());
            }
        }
    }
    println!("=== PCR-DUMP-END ===");
    // Let the console drain before powering off: a 115200-baud serial console is still sending
    // the last lines when the kernel powers down (GCP lost the tail of the dump without this).
    let _ = std::io::Write::flush(&mut std::io::stdout());
    std::thread::sleep(std::time::Duration::from_secs(3));
    // SAFETY: PID 1 power-off; sync then poweroff.
    unsafe {
        libc::sync();
        libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
    }
}
