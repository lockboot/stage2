// SPDX-License-Identifier: MIT OR Apache-2.0

//! Overlay-root assembly + `switch_root` for the loader. We build an **ephemeral** writable root
//! — `overlay(lower = verity erofs ro, upper = tmpfs)` — so the merged `/` is pure verity'd erofs
//! at every boot and runtime writes hit RAM (they cannot persist to shadow the measured code).
//! Then we move the API filesystems into it and `switch_root` (the initramfs can't be
//! `pivot_root`ed, so we use the busybox `mount --move` + `chroot` dance).

use anyhow::{Context, Result};
use std::ffi::CString;

/// `mkdir` a single directory, ignoring EEXIST (a real problem surfaces at the mount that uses it).
pub fn mkdir(path: &str) {
    if let Ok(c) = CString::new(path) {
        // SAFETY: valid NUL-terminated path.
        unsafe { libc::mkdir(c.as_ptr(), 0o755) };
    }
}

/// `mount(2)` `src` at `target`. `data` is the fs options string (e.g. overlay `lowerdir=…`).
pub fn mount(
    src: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<()> {
    let s = CString::new(src)?;
    let t = CString::new(target)?;
    let f = CString::new(fstype)?;
    let d = data.map(CString::new).transpose()?;
    let dptr = d.as_ref().map_or(std::ptr::null(), |x| x.as_ptr().cast());
    // SAFETY: all pointers are valid NUL-terminated strings; data is NULL or a valid options string.
    let rc = unsafe { libc::mount(s.as_ptr(), t.as_ptr(), f.as_ptr(), flags, dptr) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("mount {target} ({fstype})"));
    }
    Ok(())
}

/// `mount --move src target` (relocates a mount subtree; its sub-mounts move with it).
fn move_mount(src: &str, target: &str) -> Result<()> {
    mount(src, target, "", libc::MS_MOVE, None).with_context(|| format!("move {src} -> {target}"))
}

/// `switch_root` onto `newroot` and `exec` `init` as PID 1. Never returns on success; fd 0 (the
/// rewound config memfd) and the environment are inherited across the exec.
pub fn switch_root_exec(newroot: &str, init: &str) -> Result<()> {
    // Move the API filesystems into the new root. Their mountpoints are created in the tmpfs upper,
    // so the rootfs image need not carry them.
    for m in ["proc", "sys", "dev"] {
        let tgt = format!("{newroot}/{m}");
        mkdir(&tgt);
        move_mount(&format!("/{m}"), &tgt)?;
    }

    // Become the new root: chdir into it, MS_MOVE it onto /, chroot.
    let nr = CString::new(newroot)?;
    let dot = CString::new(".")?;
    let slash = CString::new("/")?;
    // SAFETY: valid paths; each call is checked.
    unsafe {
        if libc::chdir(nr.as_ptr()) != 0 {
            return Err(std::io::Error::last_os_error()).context("chdir newroot");
        }
        if libc::mount(
            dot.as_ptr(),
            slash.as_ptr(),
            std::ptr::null(),
            libc::MS_MOVE,
            std::ptr::null(),
        ) != 0
        {
            return Err(std::io::Error::last_os_error()).context("mount --move newroot /");
        }
        if libc::chroot(dot.as_ptr()) != 0 {
            return Err(std::io::Error::last_os_error()).context("chroot");
        }
        if libc::chdir(slash.as_ptr()) != 0 {
            return Err(std::io::Error::last_os_error()).context("chdir /");
        }
    }

    // exec /init.
    let path = CString::new(init)?;
    let argv0 = CString::new(init)?;
    // SAFETY: execv replaces the image; returns only on failure.
    unsafe { libc::execv(path.as_ptr(), [argv0.as_ptr(), std::ptr::null()].as_ptr()) };
    Err(std::io::Error::last_os_error()).with_context(|| format!("execv {init}"))
}
