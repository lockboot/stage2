#!/bin/sh
# Forge the deterministic stage2 payload INSIDE lockboot:erofs-builder (build-time only; none of
# these tools ship to the instance). The payload is a single self-describing ZIP with entries:
#   rootfs.erofs   erofs image ++ dm-verity hash tree, data + hash on ONE device with
#                  --no-superblock so the tree starts exactly at the data end -> the runtime
#                  dm-verity table's hash_start_block == DATA_BLOCKS (see blockdev::verity_open).
#   data-base.img  empty journaled ext4 base for p3 (flushed on reinit, grown online via ioctl to
#                  fill the disk; meta_bg => unbounded growth).
#   verity.json    { root_hash, salt, data_blocks } for the loader (payload::Verity).
# With --bootstrap, the loader ELF is prepended and the zip self-adjusted, so the output is a
# ready-to-run packed stage2 (what `make pack` produces) instead of a bare zip. The released image
# bakes in the release's loaders for both arches; --arch <x86_64|aarch64> selects one of those.
#
# Reproducible: with default knobs the output is byte-identical across builds (fixed UUID + salt,
# SOURCE_DATE_EPOCH, no lazy init, fixed mtimes + `zip -X`). Byte-verified CI==local.
set -eu

usage() {
    cat <<'EOF'
mkruntime.sh -- forge the deterministic stage2 payload (runs in lockboot:erofs-builder).

Usage: mkruntime.sh [--arch <x86_64|aarch64> | --bootstrap <elf>] <rootfs> <out>

  --arch <arch>       prepend the loader for <arch> baked into this image (the released
                      stage2-loader-<arch>), so <out> is a ready-to-run packed stage2.
  --bootstrap <elf>   prepend this loader ELF instead (e.g. a local build), same result.
  <rootfs>   one of:
               -            read a tar stream on stdin (a container rootfs)
               <file.tar>   a tar archive of a container rootfs
               <dir>        a directory, used as the rootfs verbatim
               <binary>     a single executable, installed as /init
  <out>      output file path, or `-` to write to stdout

Environment knobs (optional; the defaults keep the build reproducible / PCR14-stable):
  SOURCE_DATE_EPOCH   epoch for mtimes + erofs timestamp        (default 0)
  DATA_SIZE_MB        ext4 /data base size, MiB                 (default 64)
  ROOTFS_UUID         erofs + ext4 UUID                         (default lockboot)
  VERITY_SALT         dm-verity salt, hex                       (default lockboot)

Examples:
  # bare payload.zip from a single static PID-1 binary:
  mkruntime.sh ./myinit payload.zip

  # a ready-to-run aarch64 stage2 from a Docker image, using the baked-in loader:
  docker export "$(docker create --rm myimage)" | \
      mkruntime.sh --arch aarch64 - stage2
EOF
}

LOADER_DIR=/usr/local/share/lockboot
BOOTSTRAP=""
ARCH=""
while [ $# -gt 0 ]; do
    case "$1" in
        --bootstrap) BOOTSTRAP="${2:?--bootstrap needs an <elf> path}"; shift 2 ;;
        --bootstrap=*) BOOTSTRAP="${1#*=}"; shift ;;
        --arch) ARCH="${2:?--arch needs x86_64 or aarch64}"; shift 2 ;;
        --arch=*) ARCH="${1#*=}"; shift ;;
        -h|--help) usage; exit 0 ;;
        --) shift; break ;;
        --*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
        *) break ;;                 # positional (rootfs); includes "-" for stdin
    esac
done

if [ -n "$ARCH" ]; then
    [ -z "$BOOTSTRAP" ] || { echo "--arch and --bootstrap are mutually exclusive" >&2; exit 2; }
    case "$ARCH" in
        x86_64|aarch64) BOOTSTRAP="$LOADER_DIR/stage2-loader-$ARCH" ;;
        *) echo "--arch: expected x86_64 or aarch64, got: $ARCH" >&2; exit 2 ;;
    esac
    [ -f "$BOOTSTRAP" ] || { echo "--arch: no baked loader at $BOOTSTRAP (dev image? use --bootstrap)" >&2; exit 1; }
fi

SRC_ROOTFS="${1:?missing <rootfs>; see 'mkruntime.sh --help'}"
OUT="${2:?missing <out>; see 'mkruntime.sh --help'}"

# Knobs (env-overridable; the defaults preserve the reproducible, PCR14-stable payload).
: "${SOURCE_DATE_EPOCH:=0}"; export SOURCE_DATE_EPOCH
: "${DATA_SIZE_MB:=64}"
: "${ROOTFS_UUID:=4c4f434b-0000-0000-0000-000000000002}"
: "${VERITY_SALT:=6c6f636b626f6f742d72756e74696d652d766572697479732d73616c742d3031}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/root"

# Rootfs source -> $work/root. Four shapes; the tar-on-stdin form keeps docker out of this script
# (see the `docker export` example in --help). The loader execs /init, so a bare binary lands there.
if [ "$SRC_ROOTFS" = "-" ]; then
    tar -x -C "$work/root"                              # tar stream on stdin
elif [ -d "$SRC_ROOTFS" ]; then
    cp -a "$SRC_ROOTFS/." "$work/root/"                 # directory, verbatim
elif tar -tf "$SRC_ROOTFS" >/dev/null 2>&1; then
    tar -x -C "$work/root" -f "$SRC_ROOTFS"             # a tar archive file
else
    install -m 0755 "$SRC_ROOTFS" "$work/root/init"     # single executable -> /init
fi

# 1) erofs (deterministic): 4096-byte blocks (matches the runtime verity block size), UUID + epoch.
mkfs.erofs -b 4096 -U "$ROOTFS_UUID" -T "$SOURCE_DATE_EPOCH" \
    "$work/rootfs.erofs" "$work/root" >/dev/null

E="$(stat -c %s "$work/rootfs.erofs")"
[ $((E % 4096)) -eq 0 ] || { echo "erofs size $E is not 4096-aligned" >&2; exit 1; }
DATA_BLOCKS=$((E / 4096))

# 2) dm-verity hash tree appended at offset E. --no-superblock => the tree starts exactly at E,
#    so no offset fixup is needed when the runtime loads the table manually.
ROOT_HASH="$(veritysetup format "$work/rootfs.erofs" "$work/rootfs.erofs" \
    --no-superblock --hash-offset="$E" \
    --data-block-size=4096 --hash-block-size=4096 --data-blocks="$DATA_BLOCKS" \
    --hash=sha256 --salt="$VERITY_SALT" --format=1 \
    | awk '/Root hash/ {print $NF}')"
[ -n "$ROOT_HASH" ] || { echo "veritysetup produced no root hash" >&2; exit 1; }

# 3) Empty journaled ext4 base for p3. Grown online at runtime via EXT4_IOC_RESIZE_FS to fill p3.
#    meta_bg: each ~8 GiB meta-block-group carries its own group descriptors (no central reserved
#    GDT), so online growth is unbounded -- volume sizes are unknown. Fully written (no lazy init) +
#    fixed UUID/hash_seed for determinism. Modern mke2fs disables periodic fsck by default (relied
#    on; no fsck ships).
mkfs.ext4 -q -F -b 4096 -m 0 \
    -O has_journal,extents,metadata_csum,64bit,meta_bg,^resize_inode \
    -U "$ROOTFS_UUID" \
    -E "hash_seed=$ROOTFS_UUID,lazy_itable_init=0,lazy_journal_init=0,root_owner=0:0" \
    "$work/data-base.img" "$((DATA_SIZE_MB * 256))"

printf '{"root_hash":"%s","salt":"%s","data_blocks":%s}\n' \
    "$ROOT_HASH" "$VERITY_SALT" "$DATA_BLOCKS" > "$work/verity.json"

# 4) Deterministic zip: fixed mtimes + `zip -X` (drop uid/gid/atime extra fields), fixed order.
#    The zip deflates each entry (erofs a little, the mostly-zero ext4 base to ~nothing).
touch -d "@$SOURCE_DATE_EPOCH" "$work/rootfs.erofs" "$work/data-base.img" "$work/verity.json"
( cd "$work" && TZ=UTC zip -q -X -9 payload.zip rootfs.erofs data-base.img verity.json )

# 5) Assemble the artifact: bare zip, or (with --bootstrap) loader ELF ++ zip, self-adjusted so the
#    appended central directory offsets account for the ELF prefix (self-extracting).
if [ -n "$BOOTSTRAP" ]; then
    [ -f "$BOOTSTRAP" ] || { echo "--bootstrap: no such ELF: $BOOTSTRAP" >&2; exit 1; }
    cat "$BOOTSTRAP" "$work/payload.zip" > "$work/out"
    zip -qA "$work/out"
else
    mv "$work/payload.zip" "$work/out"
fi

# 6) Emit to <out> (a file, whose parent dir we create) or stdout (`-`). The summary goes to stderr
#    so stdout stays clean when piping.
if [ "$OUT" = "-" ]; then
    cat "$work/out"
else
    mkdir -p "$(dirname "$OUT")"
    cp "$work/out" "$OUT"
    [ -n "$BOOTSTRAP" ] && chmod 0755 "$OUT" || :
fi

SIZE="$(stat -c %s "$work/out")"
if [ -n "$BOOTSTRAP" ]; then
    echo "stage2=${SIZE}B (loader+payload; rootfs.erofs=${E}B data_blocks=$DATA_BLOCKS) root=$ROOT_HASH" >&2
else
    echo "payload.zip=${SIZE}B (rootfs.erofs=${E}B data_blocks=$DATA_BLOCKS) root=$ROOT_HASH" >&2
fi
