// SPDX-License-Identifier: MIT OR Apache-2.0

//! Block-device setup for the two persistence partitions on the NVMe boot volume.
//!
//! Layout after the ESP (p1): **p2** = runtime (read-only erofs image + dm-verity,
//! plaintext, integrity anchored to a build-time root hash measured into PCR 14);
//! **p3** = data (dm-crypt `aes-xts-plain64`, TPM-derived key, grows to fill the
//! volume). Device-mapper is driven by raw ioctls ([`dm`]) — no cryptsetup/veritysetup.

mod dm;

use anyhow::{bail, Context, Result};
use gpt::partition::Partition;
use gpt::partition_types::{OperatingSystem, Type};
use gpt::GptConfig;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Locate the lockboot boot disk among all attached whole disks, **failing loud on any
/// ambiguity** rather than guessing which volume to partition/encrypt. Identification,
/// in order of confidence:
///   1. a disk already carrying our **data** partition (definitive — a prior boot
///      stamped it; survives extra disks and reboots);
///   2. otherwise a disk with an **EFI System Partition** (first boot, before we've
///      partitioned). Exactly one must match; zero or several is a hard error.
///
/// TODO: once stage0 hardcodes a fixed lockboot disk GUID (today it's derived from the
/// stage0.efi hash, so it changes per release), prefer matching that — unambiguous even
/// with multiple bootable disks, and it stabilizes the GPT/PCR5.
pub fn find_boot_device() -> Result<PathBuf> {
    let mut data_disks = Vec::new();
    let mut esp_disks = Vec::new();
    for dev in enumerate_whole_disks()? {
        match disk_role(&dev) {
            Role::Data => data_disks.push(dev),
            Role::Esp => esp_disks.push(dev),
            Role::None => {}
        }
    }
    match data_disks.len() {
        1 => return Ok(data_disks.remove(0)),
        0 => {}
        n => bail!("{n} disks carry the lockboot data partition — refusing to guess"),
    }
    match esp_disks.len() {
        1 => Ok(esp_disks.remove(0)),
        0 => bail!("no lockboot boot disk found (no data partition, no ESP)"),
        n => bail!("{n} disks have an ESP — cannot identify the boot disk (fail closed)"),
    }
}

enum Role {
    Data,
    Esp,
    None,
}

/// Classify a disk by reading its GPT: does it hold our data partition, or an ESP?
fn disk_role(dev: &Path) -> Role {
    let Ok(disk) = GptConfig::new().writable(false).open(dev) else {
        return Role::None;
    };
    let data = Uuid::parse_str(DATA_TYPE_GUID).unwrap();
    let esp = Uuid::parse_str(ESP_TYPE_GUID).unwrap();
    let mut has_esp = false;
    for p in disk.partitions().values() {
        if p.part_type_guid.guid == data {
            return Role::Data;
        }
        if p.part_type_guid.guid == esp {
            has_esp = true;
        }
    }
    if has_esp {
        Role::Esp
    } else {
        Role::None
    }
}

/// Whole block devices from `/sys/block` (skipping partitions, loop/ram/dm/md/sr).
fn enumerate_whole_disks() -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir("/sys/block").context("read /sys/block")? {
        let name = entry?.file_name();
        let n = name.to_string_lossy();
        if ["loop", "ram", "sr", "dm-", "md", "zram", "fd", "nbd"]
            .iter()
            .any(|p| n.starts_with(p))
        {
            continue;
        }
        out.push(PathBuf::from(format!("/dev/{n}")));
    }
    Ok(out)
}

/// GPT partition type GUIDs. The ESP is the standard EFI System Partition type; the two
/// we own are fixed application-specific GUIDs so bootstrap finds them by type.
const ESP_TYPE_GUID: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
const RUNTIME_TYPE_GUID: &str = "0b7e5a1c-9f4d-4c2a-8b3e-1a2b3c4d5e6f";
const DATA_TYPE_GUID: &str = "1c8f6b2d-af5e-4d3b-9c4f-2b3c4d5e6f70";

/// Deterministic *unique* partition GUIDs, matching stage0's LOCKBOOT role scheme
/// (disk=0, ESP=1) — runtime=2, data=3. Fixed so the rebuilt GPT is byte-stable across
/// instances of a given disk size (hence a stable firmware PCR5 measurement).
const RUNTIME_PART_GUID: &str = "4c4f434b-424f-4f54-0000-000000000002";
const DATA_PART_GUID: &str = "4c4f434b-424f-4f54-0000-000000000003";

/// 1 MiB alignment, in 512-byte LBAs.
const ALIGN_LBA: u64 = 2048;

fn ptype(guid: &str, label: &str) -> Type {
    Type {
        guid: Uuid::parse_str(guid).expect("valid type GUID"),
        os: OperatingSystem::Custom(label.into()),
    }
}

/// Size of a block device in 512-byte sectors (via `BLKGETSIZE64`).
fn block_device_sectors(device: &Path) -> Result<u64> {
    use std::os::fd::AsRawFd;
    let f = std::fs::File::open(device).with_context(|| format!("open {}", device.display()))?;
    // BLKGETSIZE64 = _IOR(0x12, 114, size_t) -> bytes.
    const BLKGETSIZE64: libc::c_ulong = 0x80081272;
    let mut bytes: u64 = 0;
    // SAFETY: valid fd; kernel writes a u64.
    let rc = unsafe { libc::ioctl(f.as_raw_fd(), BLKGETSIZE64 as _, &mut bytes) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("BLKGETSIZE64 {}", device.display()));
    }
    Ok(bytes / 512)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---- Not yet implemented (next blockdev increments) ----

/// Ensure the runtime (p2, fixed `runtime_lbas`) and data (p3, fills the rest)
/// partitions exist on `device`, after the existing ESP (p1). Idempotent and
/// **grow-only**: p3 is always sized to fill the current device, so this both *creates*
/// the partitions on first boot and *grows* p3 into a larger volume later — p3's start
/// never moves (p2 is fixed), so extending only its end preserves the encrypted data.
/// Refuses to shrink. Rebuilds the GPT preserving the ESP at its exact extent (a table
/// rewrite doesn't touch partition contents). Returns `(runtime_path, data_path)`.
pub fn ensure_partitions(device: &Path, runtime_lbas: u64) -> Result<(PathBuf, PathBuf)> {
    let runtime_lbas = align_up(runtime_lbas, ALIGN_LBA);
    let esp_type = Uuid::parse_str(ESP_TYPE_GUID).unwrap();
    let data_type = Uuid::parse_str(DATA_TYPE_GUID).unwrap();

    // Inspect the current GPT: capture the disk GUID and the *whole* ESP entry so we can
    // preserve them byte-for-byte, plus any existing data-partition end.
    let (disk_guid, esp, data_last) = {
        let disk = GptConfig::new()
            .writable(false)
            .open(device)
            .with_context(|| format!("open GPT on {}", device.display()))?;
        let mut esp = None;
        let mut data_last = None;
        for p in disk.partitions().values() {
            if p.part_type_guid.guid == esp_type {
                esp = Some(p.clone());
            }
            if p.part_type_guid.guid == data_type {
                data_last = Some(p.last_lba);
            }
        }
        (
            disk.header().disk_guid,
            esp.context("no EFI System Partition on the boot disk")?,
            data_last,
        )
    };

    // Fresh GPT sized to the (possibly grown) device, PRESERVING the disk GUID. Nothing
    // is written to disk until `write()` below, so an early no-op return leaves the
    // on-disk table untouched.
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(device)
        .with_context(|| format!("open {} for GPT rewrite", device.display()))?;
    let mut disk = GptConfig::new()
        .writable(true)
        .change_partition_count(true)
        .create_from_device(file, Some(disk_guid))
        .with_context(|| format!("recreate GPT on {}", device.display()))?;
    let last_usable = disk.header().last_usable;

    let p2_first = align_up(esp.last_lba + 1, ALIGN_LBA);
    let p3_first = align_up(p2_first + runtime_lbas, ALIGN_LBA);
    if p3_first > last_usable {
        bail!("disk too small for runtime ({runtime_lbas} LBAs) + data partitions");
    }
    if let Some(dl) = data_last {
        if dl > last_usable {
            bail!("refusing to shrink data partition ({dl} > {last_usable})");
        }
        if dl == last_usable {
            // Already fills the device — leave the GPT untouched (kernel already has it).
            return Ok((part_path(device, 2), part_path(device, 3)));
        }
        // dl < last_usable → grow p3 (fall through to rebuild).
    }

    // Exact partition table: ESP preserved verbatim; runtime + data with deterministic
    // lockboot GUIDs. Only p3's end LBA and the backup GPT location move on a grow.
    let mut parts: BTreeMap<u32, Partition> = BTreeMap::new();
    parts.insert(1, esp);
    parts.insert(
        2,
        Partition {
            part_type_guid: ptype(RUNTIME_TYPE_GUID, "lockboot-runtime"),
            part_guid: Uuid::parse_str(RUNTIME_PART_GUID).unwrap(),
            first_lba: p2_first,
            last_lba: p2_first + runtime_lbas - 1,
            flags: 0,
            name: "lockboot-runtime".into(),
        },
    );
    parts.insert(
        3,
        Partition {
            part_type_guid: ptype(DATA_TYPE_GUID, "lockboot-data"),
            part_guid: Uuid::parse_str(DATA_PART_GUID).unwrap(),
            first_lba: p3_first,
            last_lba: last_usable,
            flags: 0,
            name: "lockboot-data".into(),
        },
    );
    disk.update_partitions(parts)
        .context("install partition table")?;
    let dev = disk.write().context("write rebuilt GPT")?;
    dev.sync_all().context("flush GPT to disk")?;

    reread_partition_table(device)?;
    Ok((part_path(device, 2), part_path(device, 3)))
}

/// Force the kernel to re-read the partition table (`BLKRRPART`) so new partitions
/// appear via devtmpfs. The whole-disk device must not have partitions in use.
fn reread_partition_table(device: &Path) -> Result<()> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(device)
        .with_context(|| format!("open {} for BLKRRPART", device.display()))?;
    const BLKRRPART: libc::c_ulong = 0x125F; // _IO(0x12, 95)
                                             // SAFETY: valid fd; BLKRRPART takes no argument.
    let rc = unsafe { libc::ioctl(f.as_raw_fd(), BLKRRPART as _, 0) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error()).context("BLKRRPART");
    }
    Ok(())
}

/// `/dev/nvme0n1` + partition N → `/dev/nvme0n1p2`; `/dev/sda` → `/dev/sda2`.
fn part_path(device: &Path, n: u32) -> PathBuf {
    let s = device.to_string_lossy();
    let sep = if s.chars().last().is_some_and(|c| c.is_ascii_digit()) {
        "p"
    } else {
        ""
    };
    PathBuf::from(format!("{s}{sep}{n}"))
}

fn align_up(x: u64, a: u64) -> u64 {
    x.div_ceil(a) * a
}

// ---- Runtime partition (p2): erofs + dm-verity ----

/// The build-time-forged runtime image and the dm-verity parameters that pin it, all
/// embedded in `bootstrap` (so the root hash rides into PCR 14 as bytes of the binary).
/// `blob` is the erofs image immediately followed by its dm-verity hash tree, flushed to
/// p2 verbatim; the hash tree therefore starts at block `data_blocks` (offset = image size).
pub struct RuntimeImage<'a> {
    pub blob: &'a [u8],
    /// hex SHA-256 dm-verity root hash.
    pub root_hash: &'a str,
    /// hex dm-verity salt (fixed at build so the root hash is deterministic).
    pub salt: &'a str,
    /// number of 4096-byte erofs data blocks (also the hash-tree start block).
    pub data_blocks: u64,
}

const VERITY_NAME: &str = "runtime";
const VERITY_BLOCK: u64 = 4096;
const SECTORS_PER_BLOCK: u64 = VERITY_BLOCK / 512; // 8
/// erofs superblock: little-endian magic 0xE0F5E1E2 at byte offset 1024.
const EROFS_MAGIC: u32 = 0xE0F5_E1E2;
const EROFS_SB_OFFSET: u64 = 1024;

/// Bring the runtime partition up read-only at `mountpoint`, flushing the embedded image
/// to p2 only if what's already there doesn't verify. dm-verity is its own comparator:
/// creating the mapping always succeeds (verity validates lazily, on read), so we probe by
/// reading the erofs superblock through the mapper — a clean read means p2 already holds
/// exactly this image (warm, no write); an EIO (empty/stale/torn) triggers a flush and
/// retry. Self-healing and idempotent. Returns `true` if it (re)flushed the image.
pub fn verity_mount(part: &Path, img: &RuntimeImage, mountpoint: &str) -> Result<bool> {
    if verity_try_mount(part, img, mountpoint)? {
        return Ok(false); // warm: p2 already holds this image
    }
    // Empty/stale/torn -> lay down the embedded blob and try once more.
    flush_image(part, img.blob)?;
    if !verity_try_mount(part, img, mountpoint)? {
        bail!("runtime image fails dm-verity even after flushing (corrupt embed or short p2?)");
    }
    Ok(true) // cold / upgrade
}

/// Map dm-verity over `part` and, if block 0 verifies as erofs, mount it read-only.
/// On a verity mismatch the probe read returns EIO; we tear the mapping down and report
/// `false` so the caller can flush.
fn verity_try_mount(part: &Path, img: &RuntimeImage, mountpoint: &str) -> Result<bool> {
    let mapper = verity_open(VERITY_NAME, part, img)?;
    if probe_erofs(&mapper)? {
        mount_fs(&mapper, mountpoint, "erofs", libc::MS_RDONLY, None)?;
        Ok(true)
    } else {
        dm::remove(VERITY_NAME)?;
        Ok(false)
    }
}

/// Create a dm-verity mapping named `name` over `part` (data blocks and hash tree share the
/// one device) and return its `/dev/mapper/<name>` node. Creation never validates content;
/// a wrong/empty hash tree only surfaces as EIO on the first data read.
fn verity_open(name: &str, part: &Path, img: &RuntimeImage) -> Result<PathBuf> {
    let dev = part.to_str().context("device path not UTF-8")?;
    // <version> <data_dev> <hash_dev> <data_bs> <hash_bs> <data_blocks> <hash_start> <alg> <root> <salt>
    let params = format!(
        "1 {dev} {dev} {VERITY_BLOCK} {VERITY_BLOCK} {blocks} {blocks} sha256 {root} {salt}",
        blocks = img.data_blocks,
        root = img.root_hash,
        salt = img.salt,
    );
    dm::create_and_load(
        name,
        "verity",
        &params,
        img.data_blocks * SECTORS_PER_BLOCK,
        true,
    )
}

/// Read the erofs magic through `dev`; a dm-verity failure on the underlying block reads as
/// EIO, which we translate to "does not verify" (⇒ flush) rather than a hard error.
fn probe_erofs(dev: &Path) -> Result<bool> {
    let mut f = File::open(dev).with_context(|| format!("open {}", dev.display()))?;
    f.seek(SeekFrom::Start(EROFS_SB_OFFSET))?;
    let mut b = [0u8; 4];
    match f.read_exact(&mut b) {
        Ok(()) => Ok(u32::from_le_bytes(b) == EROFS_MAGIC),
        Err(e) if e.raw_os_error() == Some(libc::EIO) => Ok(false),
        Err(e) => Err(e).with_context(|| format!("probe erofs superblock on {}", dev.display())),
    }
}

/// Write raw `blob` to the start of block device `dev` (+ fsync). Used for the erofs runtime
/// image (p2), which is embedded raw (already erofs-compressed).
fn flush_image(dev: &Path, blob: &[u8]) -> Result<()> {
    let capacity = block_device_sectors(dev)? * 512;
    if blob.len() as u64 > capacity {
        bail!(
            "image ({} bytes) exceeds device {} ({capacity} bytes)",
            blob.len(),
            dev.display()
        );
    }
    let mut f = OpenOptions::new()
        .write(true)
        .open(dev)
        .with_context(|| format!("open {} to flush image", dev.display()))?;
    f.write_all(blob)
        .with_context(|| format!("write image to {}", dev.display()))?;
    f.sync_all()
        .with_context(|| format!("flush image to {}", dev.display()))?;
    Ok(())
}

// ---- Data partition (p3): dm-crypt (aes-xts-plain64) + ext4 ----

const CRYPT_NAME: &str = "data"; // /dev/mapper/data (the encrypted device ext4 lives on)
const EXT4_BLOCK: u64 = 4096;
/// ext4 superblock: little-endian magic 0xEF53 at byte offset 0x438.
const EXT4_MAGIC: u16 = 0xEF53;
const EXT4_MAGIC_OFFSET: u64 = 0x438;
/// `EXT4_IOC_RESIZE_FS` = `_IOW('f', 16, __u64)` — in-kernel online grow (no `resize2fs` ships).
const EXT4_IOC_RESIZE_FS: libc::c_ulong = 0x4008_6610;

/// Bring up the encrypted data partition (dm-crypt `aes-xts-plain64`, confidentiality-only) at
/// `mountpoint` and mount its ext4, grown to fill p3. **Cold** (fresh device, or the key drifted so
/// the ext4 superblock decrypts to garbage): flush the baked ext4 base, then mount. **Warm:** the
/// superblock decrypts cleanly → mount + grow. Returns whether it reinitialized.
///
/// XTS is confidentiality-only: there is no per-sector authentication tag, so a never-written sector
/// decrypts to (deterministic) garbage rather than erroring — which is why online resize needs **no
/// wipe** (ext4's read-modify-write of new-group metadata reads that garbage and overwrites it, as on
/// any plain dm-crypt volume; cold-boot cost is independent of volume size). Tamper at rest is
/// *garbled*, not *detected*: the storage layer (EBS et al.) provides media integrity beneath us, and
/// an adversary with raw-disk write access is out of scope. Key drift still fails closed: bad
/// plaintext ⇒ no ext4 magic ⇒ reinit.
pub fn crypt_mount_or_mkfs(
    part: &Path,
    key: &[u8; 64],
    base_image: &[u8],
    mountpoint: &str,
) -> Result<bool> {
    let mapper = crypt_xts_open(part, key)?;

    // Cold if the ext4 superblock doesn't decrypt to a valid magic (fresh device or drifted key).
    let reinit = !probe_ext4(&mapper)?;
    if reinit {
        flush_image(&mapper, base_image)?; // lay down the baked ext4 base
    }
    // errors=remount-ro: contain damage; the next boot re-derives and decides mount-vs-reinit.
    mount_fs(&mapper, mountpoint, "ext4", 0, Some("errors=remount-ro"))?;
    grow_ext4(mountpoint, &mapper)?;
    Ok(reinit)
}

/// Activate dm-crypt `aes-xts-plain64` over the whole of p3. A 64-byte key = AES-256-XTS (two 256-bit
/// subkeys); 4096-byte crypto sectors align with ext4's block size.
fn crypt_xts_open(part: &Path, key: &[u8; 64]) -> Result<PathBuf> {
    // With sector_size:4096 the mapped length (in 512-byte sectors) must be a multiple of 8; p3 is
    // not necessarily 4 KiB-aligned, so round down (drops at most 7 tail sectors ~= 3.5 KiB).
    let sectors = block_device_sectors(part)? & !7;
    let params = format!(
        "aes-xts-plain64 {} 0 {} 0 1 sector_size:4096",
        hex(key),
        dev_str(part)?
    );
    dm::create_and_load(CRYPT_NAME, "crypt", &params, sectors, false)
}

fn dev_str(dev: &Path) -> Result<&str> {
    dev.to_str().context("device path not UTF-8")
}

/// Is there an ext4 superblock readable *through* `dev` (magic 0xEF53 at 0x438)? Under XTS a drifted
/// key decrypts the superblock to garbage, so the magic simply won't match ⇒ reinit (fail closed).
fn probe_ext4(dev: &Path) -> Result<bool> {
    let mut f = File::open(dev).with_context(|| format!("open {}", dev.display()))?;
    f.seek(SeekFrom::Start(EXT4_MAGIC_OFFSET))?;
    let mut b = [0u8; 2];
    match f.read_exact(&mut b) {
        Ok(()) => Ok(u16::from_le_bytes(b) == EXT4_MAGIC),
        Err(e) if e.raw_os_error() == Some(libc::EIO) => Ok(false),
        Err(e) => Err(e).with_context(|| format!("read ext4 magic on {}", dev.display())),
    }
}

/// Online-grow the ext4 at `mountpoint` to fill `mapper` (its backing dm-crypt device) via the
/// kernel `EXT4_IOC_RESIZE_FS` ioctl. No-op if the fs already spans the device (the common warm
/// path); ext4 forbids online shrink, so `target <= current` is left alone.
fn grow_ext4(mountpoint: &str, mapper: &Path) -> Result<()> {
    let target = block_device_sectors(mapper)? * 512 / EXT4_BLOCK;
    let mp = CString::new(mountpoint)?;
    // SAFETY: valid path; kernel fills the statvfs.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(mp.as_ptr(), &mut st) } < 0 {
        return Err(std::io::Error::last_os_error()).context("statvfs data mount");
    }
    // f_blocks / f_frsize are c_ulong (= u64 on our LP64 musl targets).
    let current = st.f_blocks * st.f_frsize / EXT4_BLOCK;
    if target <= current {
        return Ok(());
    }
    let dir = File::open(mountpoint).with_context(|| format!("open {mountpoint} for resize"))?;
    // SAFETY: valid fd on the mounted fs; kernel reads one __u64 (the new block count).
    let rc = unsafe { libc::ioctl(dir.as_raw_fd(), EXT4_IOC_RESIZE_FS as _, &target) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("EXT4_IOC_RESIZE_FS to {target} blocks"));
    }
    Ok(())
}

// ---- shared mount helper ----

/// `mkdir -p`-ish the mountpoint (ignoring EEXIST) then `mount(2)` `src` there. `data` is the
/// fs-specific options string (e.g. `errors=remount-ro`), or `None`.
fn mount_fs(
    src: &Path,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<()> {
    let c = CString::new(target)?;
    // Ignore EEXIST; a real problem surfaces at the mount below.
    unsafe { libc::mkdir(c.as_ptr(), 0o755) };
    let s = CString::new(src.to_str().context("device path not UTF-8")?)?;
    let f = CString::new(fstype)?;
    let d = data.map(CString::new).transpose()?;
    let dptr = d.as_ref().map_or(std::ptr::null(), |x| x.as_ptr().cast());
    // SAFETY: valid NUL-terminated strings; data is NULL or a valid options string.
    let rc = unsafe { libc::mount(s.as_ptr(), c.as_ptr(), f.as_ptr(), flags, dptr) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("mount {target} ({fstype})"));
    }
    Ok(())
}
