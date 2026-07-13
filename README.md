# 🐚 stage2 — the Lock.Boot loader

Part of [Lock.Boot](https://github.com/lockboot). The **preferred stage2 layering** in the chain
(stage0 → stage1 → **stage2**) — replaceable, like any lockboot stage, with your own. It is a
**payload-agnostic loader**, not a container runtime: it takes any container image, seals it into a
measured, TPM-bound, integrity-checked form, and boots it. "Run this Docker container under
Lock.Boot."

By the time this runs, the layers below have admitted and verified it (sha256/ed25519, PCR 14).
**Trust and verification are not this layer's concern** — it consumes an already-trusted payload.

## The idea

A small, low-churn **loader** binary (`bootstrap`, static-musl, PID 1) with a container image
**appended to it as a self-extracting zip**. The workload never touches the loader — you swap the
appended image freely without recompiling the (audited, reproducible) loader. stage1 measures the
whole loader+image into **PCR 14**, so the image identity is attested for free. Deployment is just
packaging: `docker export → mkfs.erofs → veritysetup → zip → append to the loader ELF`.

## Using it

Build the loader and the packaging image once:

```bash
make build-x86_64 docker-build-erofs
#   build-x86_64        -> target/x86_64-unknown-linux-musl/release/bootstrap   (the loader ELF)
#   docker-build-erofs  -> lockboot:erofs-builder  (a one-shot CLI; mkruntime.sh is its entrypoint)
```

The image *is* the tool. Mount just the loader ELF, pipe any container rootfs in on stdin, and the
bootable `stage2` comes out on stdout — no repo bind-mount, no host filesystem tools:

```bash
docker export "$(docker create --rm myimage)" \
  | docker run --rm -i \
      -v "$PWD/target/x86_64-unknown-linux-musl/release/bootstrap:/bootstrap:ro" \
      lockboot:erofs-builder --bootstrap /bootstrap - - > stage2
```

The rootfs argument (`-` above) can instead be a `.tar`, a directory, or a single binary (installed
as `/init`); the output (`-`) can be a path. `docker run --rm lockboot:erofs-builder --help` lists
the env knobs (`DATA_SIZE_MB`, `ROOTFS_UUID`, `VERITY_SALT`, `SOURCE_DATE_EPOCH`), all reproducible
by default. Serve the resulting `stage2` as your payload; stage0/stage1 admit it by `sha256`/`ed25519`.

## Technical details

### How it boots (loader = PID 1)

1. **Read its own payload** from `/proc/self/exe` (a memfd) — the appended zip carries
   `rootfs.erofs` (+ its dm-verity hash tree), a deterministic empty `data-base.img`, and
   `verity.json`.
2. **Bind the config**: hash the verbatim stdin JSON into **PCR 15**, then rewind fd 0 so the
   workload reads the exact same bytes.
3. **Derive keys** from the TPM, bound to the boot-chain PCRs (see below).
4. **Runtime (p2)** — flush the erofs to the partition only if it doesn't already verify, then
   **dm-verity**-mount it read-only.
5. **Root** — assemble an **overlay**: the verity'd erofs as the immutable lower, a **tmpfs**
   upper. The merged `/` is therefore *pure verity'd erofs at every boot* — runtime writes hit RAM
   and can never persist to shadow the measured code.
6. **Data (p3)** — bring up `/data`: **dm-crypt** `aes-xts-plain64` (AES-256-XTS), grown online to
   fill the disk. Confidential; the TPM-derived key binds it to the boot chain.
7. **Attest** — copy stage1's attestation and drop stage2's alongside it in an ephemeral
   `/run/lockboot/`.
8. **`switch_root`** onto the overlay and **`exec /init`** — the image's own entrypoint, handed the
   verbatim config on stdin. Transparent: stage2 imposes no config schema of its own.

### Security model

| Layer | Mechanism | Guarantee |
|---|---|---|
| **Code / rootfs** | erofs + dm-verity, measured into PCR 14, under an **ephemeral** overlay | Immutable, integrity-verified, re-attestable each boot — no persistent code modification |
| **Config** | verbatim stdin JSON → hashed → PCR 15 | Disk key bound to config; any change ⇒ fresh disk (fail-closed) |
| **Data** | `/data`: dm-crypt `aes-xts-plain64` (AES-256-XTS) | Confidential (confidentiality-only): at-rest tamper garbles rather than being cryptographically detected — media integrity is left to the storage layer (EBS et al.) |
| **Keys** | TPM-derived under a `PolicyPCR` session over a curated PCR set | No LUKS/header; drift in bound PCRs (code/config/firmware) ⇒ superblock decrypts to garbage ⇒ re-initialized (fail-closed) |

See [`PCR-BINDING.md`](PCR-BINDING.md) for the bound PCR set, the {5,10} exclusions, and the IMA
analysis.

### Building & testing

Everything builds inside the shared `lockboot:build` image (no host toolchain); the runtime image is
forged in the build-time-only `lockboot:erofs-builder` — none of those tools ship to the instance.
Reproducible: the loader ELF and the payload zip are each byte-deterministic.

```bash
make lock                 # generate Cargo.lock (first time)
make check test           # cargo check + test the workspace
make ci                   # fmt + clippy + test (the CI gate)
make pack-x86_64          # pack the bundled example -> build/x86_64/pack/stage2
make test-pivot-x86_64    # boot a packed stage2 under the QEMU/swtpm harness
```

`unzip -l build/<arch>/pack/stage2` inspects a packed payload.

### Crates

- **`bootstrap`** — the loader: read the appended payload, bring up persistence, pivot onto the
  overlay root, `exec /init`.
- **`payload`** — the minimal appended-zip reader (self-extracting; reads `/proc/self/exe`).
- **`blockdev`** — raw device-mapper ioctls (no `libdevmapper`): dm-verity, dm-crypt (XTS),
  byte-stable GPT grow/discovery, ext4 online grow.
- **`tpm-derive`** — deterministic PCR-bound key derivation (pure-Rust TPM2).

## License

Apache-2.0 OR MIT, at your option.
