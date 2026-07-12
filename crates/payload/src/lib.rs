// SPDX-License-Identifier: MIT OR Apache-2.0

//! The loader's self-contained payload: a ZIP **appended** to the loader ELF (self-extracting
//! layout — the ELF loader ignores trailing bytes; zip readers find the End-Of-Central-Directory
//! by scanning back from EOF). stage1 sha256s the whole loader+zip into PCR 14, so the payload is
//! measured for free and the loader itself carries no payload-specific data.
//!
//! We read our own image via `/proc/self/exe` (a memfd under stage1's execveat model, readable)
//! and pull three entries out of the archive:
//!   - `rootfs.erofs`   — erofs image ++ dm-verity hash tree (flushed to p2);
//!   - `data-base.img`  — the empty journaled ext4 base (flushed to p3 on reinit);
//!   - `verity.json`    — `{ root_hash, salt, data_blocks }`.
//!
//! A deliberately-minimal zip reader (no ZIP64, no encryption, store + raw-deflate only) keeps the
//! trust surface small; our own `make pack` produces exactly this shape. The central-directory
//! offset is self-located (`archive_start = eocd_pos - cd_size - cd_offset`), so it works whether
//! or not `zip -A` rewrote the SFX prefix.

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::io::Read;

pub const ROOTFS_EROFS: &str = "rootfs.erofs";
pub const DATA_BASE: &str = "data-base.img";
pub const VERITY_JSON: &str = "verity.json";

/// dm-verity parameters for the runtime image, carried in `verity.json` (measured into PCR 14).
#[derive(Debug, Clone, Deserialize)]
pub struct Verity {
    pub root_hash: String,
    pub salt: String,
    pub data_blocks: u64,
}

/// The extracted payload.
pub struct Payload {
    pub rootfs_erofs: Vec<u8>,
    pub data_base: Vec<u8>,
    pub verity: Verity,
}

/// Read this executable's appended zip (`/proc/self/exe`) and extract the payload.
pub fn load_self() -> Result<Payload> {
    let image = std::fs::read("/proc/self/exe").context("read /proc/self/exe")?;
    from_image(&image)
}

/// Parse the payload from a full loader+zip image (split out from [`load_self`] so it is testable
/// without a real `/proc/self/exe`).
pub fn from_image(image: &[u8]) -> Result<Payload> {
    let zip = Zip::open(image)?;
    let verity: Verity =
        serde_json::from_slice(&zip.read(VERITY_JSON)?).context("parse verity.json")?;
    Ok(Payload {
        rootfs_erofs: zip.read(ROOTFS_EROFS)?,
        data_base: zip.read(DATA_BASE)?,
        verity,
    })
}

// ---- minimal zip reader ----

const EOCD_SIG: u32 = 0x0605_4b50;
const CDH_SIG: u32 = 0x0201_4b50;
const LFH_SIG: u32 = 0x0403_4b50;
const EOCD_MIN: usize = 22;

struct Entry {
    method: u16,
    comp_size: u64,
    local_offset: u64,
}

struct Zip<'a> {
    image: &'a [u8],
    archive_start: u64,
    entries: std::collections::BTreeMap<String, Entry>,
}

impl<'a> Zip<'a> {
    fn open(image: &'a [u8]) -> Result<Self> {
        let eocd = find_eocd(image).ok_or_else(|| anyhow!("no zip EOCD found in image"))?;
        let cd_size = le_u32(image, eocd + 12)? as u64;
        let cd_offset = le_u32(image, eocd + 16)? as u64;
        let n_entries = le_u16(image, eocd + 10)? as usize;

        // The central directory ends right before the EOCD; its offset in the record is relative
        // to the archive start, so the SFX prefix length falls out directly.
        let cd_end = eocd as u64;
        let cd_start = cd_end
            .checked_sub(cd_size)
            .ok_or_else(|| anyhow!("central directory size overflows image"))?;
        let archive_start = cd_start
            .checked_sub(cd_offset)
            .ok_or_else(|| anyhow!("central directory offset overflows image"))?;

        let mut entries = std::collections::BTreeMap::new();
        let mut pos = cd_start as usize;
        for _ in 0..n_entries {
            if le_u32(image, pos)? != CDH_SIG {
                bail!("bad central directory header at {pos}");
            }
            let method = le_u16(image, pos + 10)?;
            let comp_size = le_u32(image, pos + 20)? as u64;
            let name_len = le_u16(image, pos + 28)? as usize;
            let extra_len = le_u16(image, pos + 30)? as usize;
            let comment_len = le_u16(image, pos + 32)? as usize;
            let local_offset = le_u32(image, pos + 42)? as u64;
            let name = std::str::from_utf8(slice(image, pos + 46, name_len)?)
                .context("central header name not UTF-8")?
                .to_string();
            entries.insert(
                name,
                Entry {
                    method,
                    comp_size,
                    local_offset,
                },
            );
            pos += 46 + name_len + extra_len + comment_len;
        }
        Ok(Zip {
            image,
            archive_start,
            entries,
        })
    }

    /// Extract (and decompress if deflated) the named entry.
    fn read(&self, name: &str) -> Result<Vec<u8>> {
        let e = self
            .entries
            .get(name)
            .ok_or_else(|| anyhow!("payload entry {name:?} not found"))?;
        let lfh = (self.archive_start + e.local_offset) as usize;
        if le_u32(self.image, lfh)? != LFH_SIG {
            bail!("bad local file header for {name:?}");
        }
        // The local header carries its own name/extra lengths (may differ from the central one).
        let name_len = le_u16(self.image, lfh + 26)? as usize;
        let extra_len = le_u16(self.image, lfh + 28)? as usize;
        let data = slice(
            self.image,
            lfh + 30 + name_len + extra_len,
            e.comp_size as usize,
        )?;
        match e.method {
            0 => Ok(data.to_vec()), // stored
            8 => {
                let mut out = Vec::new();
                flate2::read::DeflateDecoder::new(data)
                    .read_to_end(&mut out)
                    .with_context(|| format!("inflate {name:?}"))?;
                Ok(out)
            }
            m => bail!("unsupported zip compression method {m} for {name:?}"),
        }
    }
}

/// Scan back from EOF for the EOCD signature (no-comment archives put it in the last 22 bytes; we
/// tolerate a trailing comment up to the spec max). Returns the EOCD record offset.
fn find_eocd(image: &[u8]) -> Option<usize> {
    if image.len() < EOCD_MIN {
        return None;
    }
    let max_back = image.len().min(EOCD_MIN + 0xffff);
    let start = image.len() - max_back;
    for pos in (start..=image.len() - EOCD_MIN).rev() {
        if le_u32(image, pos).ok()? == EOCD_SIG {
            return Some(pos);
        }
    }
    None
}

fn slice(b: &[u8], off: usize, len: usize) -> Result<&[u8]> {
    b.get(off..off + len)
        .ok_or_else(|| anyhow!("zip: read {len} at {off} past end ({}))", b.len()))
}

fn le_u16(b: &[u8], off: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(slice(b, off, 2)?.try_into().unwrap()))
}

fn le_u32(b: &[u8], off: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(slice(b, off, 4)?.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build a minimal zip (one entry per name) with an arbitrary ELF-like prefix, to exercise the
    /// SFX-prefix self-location, central-directory parsing, and both store + deflate paths.
    fn build_zip(prefix: &[u8], files: &[(&str, &[u8], bool)]) -> Vec<u8> {
        let mut out = prefix.to_vec();
        let start = out.len() as u32; // archive start = prefix length
        let mut central = Vec::new();
        let mut offsets = Vec::new();

        for (name, data, deflate) in files {
            let (method, stored): (u16, Vec<u8>) = if *deflate {
                let mut e =
                    flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
                e.write_all(data).unwrap();
                (8, e.finish().unwrap())
            } else {
                (0, data.to_vec())
            };
            let local_off = out.len() as u32 - start;
            offsets.push((
                *name,
                method,
                stored.len() as u32,
                data.len() as u32,
                local_off,
            ));
            // local file header
            out.extend_from_slice(&LFH_SIG.to_le_bytes());
            out.extend_from_slice(&[0u8; 4]); // ver, flags
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&[0u8; 8]); // mtime,mdate,crc
            out.extend_from_slice(&(stored.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra len
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&stored);
        }

        let cd_start = out.len() as u32 - start;
        for (name, method, comp, uncomp, local_off) in &offsets {
            central.extend_from_slice(&CDH_SIG.to_le_bytes());
            central.extend_from_slice(&[0u8; 6]); // ver made, ver need, flags
            central.extend_from_slice(&method.to_le_bytes());
            central.extend_from_slice(&[0u8; 8]); // mtime,mdate,crc
            central.extend_from_slice(&comp.to_le_bytes());
            central.extend_from_slice(&uncomp.to_le_bytes());
            central.extend_from_slice(&(name.len() as u16).to_le_bytes());
            central.extend_from_slice(&[0u8; 8]); // extra,comment,disk,intattr (2+2+2+2)
            central.extend_from_slice(&[0u8; 4]); // ext attr
            central.extend_from_slice(&local_off.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_size = central.len() as u32;
        out.extend_from_slice(&central);

        // EOCD
        out.extend_from_slice(&EOCD_SIG.to_le_bytes());
        out.extend_from_slice(&[0u8; 6]); // disks + counts-this-disk
        out.extend_from_slice(&(offsets.len() as u16).to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_start.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // comment len
        out
    }

    #[test]
    fn extracts_store_and_deflate_behind_a_prefix() {
        let erofs = vec![0xE2, 0xE1, 0xF5, 0xE0, 42, 42, 42]; // pretend erofs bytes
        let base = vec![0u8; 4096]; // compressible zeros
        let vj = br#"{"root_hash":"abcd","salt":"beef","data_blocks":116}"#;
        let img = build_zip(
            b"\x7fELF fake loader prefix",
            &[
                (ROOTFS_EROFS, &erofs, false), // stored
                (DATA_BASE, &base, true),      // deflated
                (VERITY_JSON, vj, false),
            ],
        );
        let p = from_image(&img).expect("parse");
        assert_eq!(p.rootfs_erofs, erofs);
        assert_eq!(p.data_base, base);
        assert_eq!(p.verity.root_hash, "abcd");
        assert_eq!(p.verity.salt, "beef");
        assert_eq!(p.verity.data_blocks, 116);
    }

    #[test]
    fn missing_entry_is_an_error() {
        let img = build_zip(b"prefix", &[(VERITY_JSON, b"{}", false)]);
        assert!(from_image(&img).is_err());
    }
}
