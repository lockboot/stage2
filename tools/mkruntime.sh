#!/bin/sh
# Forge the deterministic payload INSIDE lockboot:erofs-builder (build-time only; none of these
# tools ship to the instance). Emits a single self-describing ZIP at $2/payload.zip, which
# `make pack` appends to the loader ELF. Entries:
#   rootfs.erofs   erofs image ++ dm-verity hash tree, data + hash on ONE device with
#                  --no-superblock so the tree starts exactly at the data end -> the runtime
#                  dm-verity table's hash_start_block == DATA_BLOCKS (see blockdev::verity_open).
#   data-base.img  empty journaled ext4 base for p3 (flushed on reinit, grown online via ioctl).
#   verity.json    { root_hash, salt, data_blocks } for the loader (payload::Verity).
#
# Reproducible: fixed UUID + salt, SOURCE_DATE_EPOCH, no lazy init, fixed mtimes + `zip -X`.
# Byte-verified CI==local.
set -eu

SRC_ROOTFS="${1:?usage: mkruntime.sh <rootfs-binary-or-dir> <out-dir>}"
OUT="${2:?usage: mkruntime.sh <rootfs-binary-or-dir> <out-dir>}"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

# Fixed so the payload (hence the packed stage2, hence PCR14) is deterministic across builds.
FIXED_UUID="4c4f434b-0000-0000-0000-000000000002"
FIXED_SALT="6c6f636b626f6f742d72756e74696d652d766572697479732d73616c742d3031"
# Base ext4 size. Small: grown online to fill p3 at runtime (EXT4_IOC_RESIZE_FS), and the smaller
# the base the less we write on first boot / reinit. resize_inode reserves ~1024x growth headroom
# (64 MiB -> ~64 GiB); larger volumes need meta_bg (a documented follow-up).
DATA_EXT4_SIZE_MB=64

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/root" "$OUT"

# Rootfs source: a single binary becomes a flat erofs root with that binary as /init (the loader
# execs /init); a directory is taken as a full container rootfs verbatim (docker->erofs front end).
if [ -d "$SRC_ROOTFS" ]; then
    cp -a "$SRC_ROOTFS/." "$work/root/"
else
    install -m 0755 "$SRC_ROOTFS" "$work/root/init"
fi

# 1) erofs (deterministic): 4096-byte blocks, fixed UUID + timestamp.
mkfs.erofs -b 4096 -U "$FIXED_UUID" -T "$SOURCE_DATE_EPOCH" \
    "$work/rootfs.erofs" "$work/root" >/dev/null

E="$(stat -c %s "$work/rootfs.erofs")"
[ $((E % 4096)) -eq 0 ] || { echo "erofs size $E is not 4096-aligned" >&2; exit 1; }
DATA_BLOCKS=$((E / 4096))

# 2) dm-verity hash tree appended at offset E. --no-superblock => the tree starts exactly at E,
#    so no offset fixup is needed when the runtime loads the table manually.
ROOT_HASH="$(veritysetup format "$work/rootfs.erofs" "$work/rootfs.erofs" \
    --no-superblock --hash-offset="$E" \
    --data-block-size=4096 --hash-block-size=4096 --data-blocks="$DATA_BLOCKS" \
    --hash=sha256 --salt="$FIXED_SALT" --format=1 \
    | awk '/Root hash/ {print $NF}')"
[ -n "$ROOT_HASH" ] || { echo "veritysetup produced no root hash" >&2; exit 1; }

# 3) Empty journaled ext4 base for p3. Grown online to the partition at runtime via
#    EXT4_IOC_RESIZE_FS, so a modest base with resize_inode headroom is enough. Fully written
#    (no lazy init) + fixed UUID/hash_seed for determinism. Modern mke2fs disables periodic
#    fsck by default (max-mount-count -1, interval 0), which we rely on (no fsck ships).
mkfs.ext4 -q -F -b 4096 -m 0 \
    -O has_journal,extents,metadata_csum,64bit,resize_inode \
    -U "$FIXED_UUID" \
    -E "hash_seed=$FIXED_UUID,lazy_itable_init=0,lazy_journal_init=0,root_owner=0:0" \
    "$work/data-base.img" "$((DATA_EXT4_SIZE_MB * 256))"

printf '{"root_hash":"%s","salt":"%s","data_blocks":%s}\n' \
    "$ROOT_HASH" "$FIXED_SALT" "$DATA_BLOCKS" > "$work/verity.json"

# 4) Deterministic zip: fixed mtimes + `zip -X` (drop uid/gid/atime extra fields), fixed order.
#    The zip deflates each entry (erofs a little, the mostly-zero ext4 base to ~nothing).
touch -d "@$SOURCE_DATE_EPOCH" "$work/rootfs.erofs" "$work/data-base.img" "$work/verity.json"
rm -f "$OUT/payload.zip"
( cd "$work" && TZ=UTC zip -q -X -9 payload.zip rootfs.erofs data-base.img verity.json )
mv "$work/payload.zip" "$OUT/payload.zip"

echo "payload.zip=$(stat -c %s "$OUT/payload.zip")B (rootfs.erofs=${E}B data_blocks=$DATA_BLOCKS) root=$ROOT_HASH"
