// SPDX-License-Identifier: MIT OR Apache-2.0

//! Boot-through-harness probe for `tpm-derive` against the real (swtpm) TPM. Proves:
//! (1) deriving is deterministic within a boot; (2) measuring a workload into PCR15
//! *changes* the key (so the disk is bound to the specific container config). Then
//! powers off. Not production — a test payload run as stage2 under the QEMU harness.

use std::io::Read;

fn main() {
    // Take the container config from stdin's user-data if present, else a fixed sample.
    let mut ud = String::new();
    let _ = std::io::stdin().read_to_string(&mut ud);
    let container = serde_json::from_str::<serde_json::Value>(&ud)
        .ok()
        .and_then(|d| d.get("container").cloned())
        .unwrap_or_else(|| serde_json::json!({"image": "probe@sha256:sample", "env": {"A": "1"}}));

    println!("=== derive-probe ===");
    // Before measuring the workload: PCR15 = 0.
    let k_unbound = tpm_derive::derive_disk_key();

    // Measure the workload, then derive again: PCR15 = H(container config).
    let digest = tpm_derive::workload_digest(&container);
    if let Err(e) = tpm_derive::extend_workload_pcr(&digest) {
        println!("extend PCR15 error: {e:?}");
    }
    let k_bound = tpm_derive::derive_disk_key();
    let k_bound2 = tpm_derive::derive_disk_key();

    match (k_unbound, k_bound, k_bound2) {
        (Ok(u), Ok(b), Ok(b2)) => {
            println!("workload_digest={}", hex(&digest));
            println!("key_unbound={}", hex(&u));
            println!("key_bound={}", hex(&b));
            println!("workload_binding_changes_key={}", u != b);
            println!("deterministic={}", b == b2);
            println!("nonzero={}", b.iter().any(|&x| x != 0));
        }
        _ => println!("derive error"),
    }
    println!("=== derive-probe done, powering off ===");
    poweroff();
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
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
