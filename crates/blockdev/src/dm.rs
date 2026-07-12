// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal device-mapper control via raw ioctls on `/dev/mapper/control`.
//!
//! Enough to create a target (dm-crypt / dm-verity), load its table, resume it, and
//! tear it down — no `libdevmapper`, matching vaportpm's zero-C-dependency approach.
//! The initramfs has no udev, so we create the `/dev/mapper/<name>` node ourselves
//! from the dev_t the kernel returns.

use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::fs::OpenOptions;
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::path::PathBuf;

const DM_CONTROL: &str = "/dev/mapper/control";
const DM_NAME_LEN: usize = 128;
const DM_UUID_LEN: usize = 129;
const DM_VERSION_MAJOR: u32 = 4;

// _IOWR(0xfd, cmd, struct dm_ioctl) with size = size_of::<DmIoctl>() (312).
const DM_IOCTL_TYPE: u32 = 0xfd;
fn dm_iowr(cmd: u32) -> libc::c_ulong {
    let size = size_of::<DmIoctl>() as u32;
    // dir=READ|WRITE (3) << 30 | size << 16 | type << 8 | nr
    ((3u32 << 30) | (size << 16) | (DM_IOCTL_TYPE << 8) | cmd) as libc::c_ulong
}
const CMD_DEV_CREATE: u32 = 3;
const CMD_DEV_REMOVE: u32 = 4;
const CMD_DEV_SUSPEND: u32 = 6; // resume when DM_SUSPEND_FLAG is clear
const CMD_TABLE_LOAD: u32 = 9;

/// `DM_READONLY_FLAG` — mark the mapped device read-only. dm-verity *requires* this.
const DM_READONLY_FLAG: u32 = 1 << 0;

/// `struct dm_ioctl` (linux/dm-ioctl.h), 312 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
struct DmIoctl {
    version: [u32; 3],
    data_size: u32,
    data_start: u32,
    target_count: u32,
    open_count: i32,
    flags: u32,
    event_nr: u32,
    padding: u32,
    dev: u64,
    name: [u8; DM_NAME_LEN],
    uuid: [u8; DM_UUID_LEN],
    data: [u8; 7],
}

impl DmIoctl {
    fn new(name: &str) -> Result<Self> {
        let mut hdr = DmIoctl {
            version: [DM_VERSION_MAJOR, 0, 0],
            data_size: size_of::<DmIoctl>() as u32,
            data_start: size_of::<DmIoctl>() as u32,
            target_count: 0,
            open_count: 0,
            flags: 0,
            event_nr: 0,
            padding: 0,
            dev: 0,
            name: [0; DM_NAME_LEN],
            uuid: [0; DM_UUID_LEN],
            data: [0; 7],
        };
        let n = name.as_bytes();
        if n.len() >= DM_NAME_LEN {
            bail!("dm device name too long: {name}");
        }
        hdr.name[..n.len()].copy_from_slice(n);
        Ok(hdr)
    }
}

/// `struct dm_target_spec`, 40-byte header followed by the null-terminated params.
#[repr(C)]
#[derive(Clone, Copy)]
struct DmTargetSpec {
    sector_start: u64,
    length: u64,
    status: i32,
    next: u32,
    target_type: [u8; 16],
}

fn control() -> Result<std::fs::File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(DM_CONTROL)
        .context("open /dev/mapper/control")
}

fn ioctl(f: &std::fs::File, cmd: u32, buf: &mut [u8]) -> Result<()> {
    // SAFETY: buf holds a valid dm_ioctl (+ payload); the kernel reads/writes within data_size.
    let rc = unsafe { libc::ioctl(f.as_raw_fd(), dm_iowr(cmd) as _, buf.as_mut_ptr()) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("dm ioctl cmd={cmd}"));
    }
    Ok(())
}

fn as_bytes<T: Copy>(v: &T) -> &[u8] {
    // SAFETY: T is repr(C) POD; we read size_of::<T> bytes.
    unsafe { core::slice::from_raw_parts((v as *const T).cast::<u8>(), size_of::<T>()) }
}

/// Create the device, load a single-target table, and resume it. Returns the created
/// `/dev/mapper/<name>` node path. `target` is e.g. "crypt" / "verity"; `params` is the
/// target's parameter string; `length` is the mapped size in 512-byte sectors; `read_only`
/// marks the mapped device read-only (required by dm-verity).
pub fn create_and_load(
    name: &str,
    target: &str,
    params: &str,
    length: u64,
    read_only: bool,
) -> Result<PathBuf> {
    let f = control()?;
    let ro = if read_only { DM_READONLY_FLAG } else { 0 };

    // DM_DEV_CREATE
    let mut hdr = DmIoctl::new(name)?;
    hdr.flags = ro;
    let mut buf = as_bytes(&hdr).to_vec();
    ioctl(&f, CMD_DEV_CREATE, &mut buf).context("DM_DEV_CREATE")?;
    // Read back the assigned dev_t.
    let created: DmIoctl = read_hdr(&buf);
    let node = make_node(name, created.dev)?;

    // DM_TABLE_LOAD: header + one dm_target_spec + params(NUL, padded to 8).
    let mut spec = DmTargetSpec {
        sector_start: 0,
        length,
        status: 0,
        next: 0,
        target_type: [0; 16],
    };
    let t = target.as_bytes();
    if t.len() >= 16 {
        bail!("target type too long: {target}");
    }
    spec.target_type[..t.len()].copy_from_slice(t);

    let mut params_bytes = params.as_bytes().to_vec();
    params_bytes.push(0); // NUL
    while !(size_of::<DmTargetSpec>() + params_bytes.len()).is_multiple_of(8) {
        params_bytes.push(0); // pad to 8-byte alignment
    }
    let spec_total = size_of::<DmTargetSpec>() + params_bytes.len();
    spec.next = spec_total as u32;

    hdr.target_count = 1;
    hdr.data_size = (size_of::<DmIoctl>() + spec_total) as u32;
    let mut load = Vec::with_capacity(hdr.data_size as usize);
    load.extend_from_slice(as_bytes(&hdr));
    load.extend_from_slice(as_bytes(&spec));
    load.extend_from_slice(&params_bytes);
    ioctl(&f, CMD_TABLE_LOAD, &mut load).context("DM_TABLE_LOAD")?;

    // DM_DEV_SUSPEND without DM_SUSPEND_FLAG -> resume (activate) the table; keep read-only.
    let mut resume = DmIoctl::new(name)?;
    resume.flags = ro;
    let mut rbuf = as_bytes(&resume).to_vec();
    ioctl(&f, CMD_DEV_SUSPEND, &mut rbuf).context("DM_DEV_SUSPEND(resume)")?;

    Ok(node)
}

/// Remove a device-mapper device.
pub fn remove(name: &str) -> Result<()> {
    let f = control()?;
    let hdr = DmIoctl::new(name)?;
    let mut buf = as_bytes(&hdr).to_vec();
    ioctl(&f, CMD_DEV_REMOVE, &mut buf).context("DM_DEV_REMOVE")
}

fn read_hdr(buf: &[u8]) -> DmIoctl {
    let mut hdr = DmIoctl::new("").unwrap();
    // SAFETY: buf is at least size_of::<DmIoctl> (it was built from one).
    unsafe {
        core::ptr::copy_nonoverlapping(
            buf.as_ptr(),
            (&mut hdr as *mut DmIoctl).cast::<u8>(),
            size_of::<DmIoctl>(),
        );
    }
    hdr
}

/// Create `/dev/mapper/<name>` from the kernel dev_t (no udev in the initramfs).
fn make_node(name: &str, dev: u64) -> Result<PathBuf> {
    // new_encode_dev layout returned by dm.
    let major = ((dev >> 8) & 0xfff) as u32;
    let minor = ((dev & 0xff) | ((dev >> 12) & 0xfff00)) as u32;
    std::fs::create_dir_all("/dev/mapper").ok();
    let path = PathBuf::from(format!("/dev/mapper/{name}"));
    let cpath = CString::new(path.to_str().unwrap())?;
    let devt = libc::makedev(major, minor);
    // SAFETY: valid path + dev_t; S_IFBLK block node.
    let rc = unsafe { libc::mknod(cpath.as_ptr(), libc::S_IFBLK | 0o600, devt) };
    if rc < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EEXIST) {
            return Err(e).context(format!("mknod {}", path.display()));
        }
    }
    Ok(path)
}
