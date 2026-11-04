# lockboot stage2 loader - the payload-agnostic shim that pivots onto an appended erofs image.
# Builds through the shared lockboot:build image only (never host cargo/docker directly).
#
#   make check                cargo check the whole workspace
#   make test                 cargo test the whole workspace
#   make build-x86_64          build the loader (bootstrap, static musl)
#   make pack-x86_64           loader + appended payload.zip -> build/<arch>/pack/stage2
#   make test-pivot-x86_64     boot the packed stage2 under the harness (overlay + /data)
#   make fmt / make clippy
#
# The container image travels as a self-extracting zip appended to the loader (make pack);
# tests borrow the stage0 harness + existing swtpm, exactly as stage1's chain test does.

.PHONY: all lock check test fmt fmt-fix clippy ci build build-amd64 build-x86_64 build-arm64 build-aarch64 clean docker-build-base docker-build-erofs docker-shell-base pack pack-amd64 pack-arm64

ARCHS = x86_64 aarch64
all: build

# ---- Docker images (shared lockboot family; built locally, never published) ----
BUILD_IMAGE   = lockboot:build
HARNESS_IMAGE = lockboot:harness
EROFS_IMAGE   = lockboot:erofs-builder

docker-build-base:
	docker build -f Dockerfile.build -t $(BUILD_IMAGE) .

# Build-time-only forge for the runtime-image artifacts (mkfs.erofs + veritysetup + mkfs.ext4);
# nothing it produces ships to the instance. See Dockerfile.erofs-builder + tools/mkruntime.sh.
docker-build-erofs:
	docker build -f Dockerfile.erofs-builder --target tools -t $(EROFS_IMAGE) .

# ---- Docker run plumbing (keep identical across repos; mirrors stage0/stage1) ----
USER_ID  := $(shell stat -c %u .)
GROUP_ID := $(shell stat -c %g .)

KVM_GID   := $(shell stat -c %g /dev/kvm 2>/dev/null || echo "")
KVM_MOUNT := $(shell test -e /dev/kvm && echo "-v /dev/kvm:/dev/kvm")
DOCKER_OPT_KVM := $(if $(KVM_GID),--group-add $(KVM_GID)) $(KVM_MOUNT)

DOCKER_SOCK_GID   := $(shell stat -c %g /var/run/docker.sock 2>/dev/null || echo "")
DOCKER_SOCK_MOUNT := $(shell test -e /var/run/docker.sock && echo "-v /var/run/docker.sock:/var/run/docker.sock")
DOCKER_OPT_DOCKER := $(DOCKER_SOCK_MOUNT) $(if $(DOCKER_SOCK_GID),--group-add $(DOCKER_SOCK_GID))

DOCKER_SAMEUSER := -u $(USER_ID):$(GROUP_ID)

# Host-path translation for docker-in-devcontainer (see stage1/Makefile for the why).
HOST_DIR := $(CURDIR)
ifneq ($(filter /src/%,$(CURDIR)),)
  SRC_BIND := $(shell findmnt -fnro SOURCE --target /src 2>/dev/null | sed -n 's/.*\[\(.*\)\]$$/\1/p')
  ifneq ($(SRC_BIND),)
    HOST_DIR := $(SRC_BIND)$(CURDIR:/src%=%)
  endif
endif

REPO_NAME := $(notdir $(HOST_DIR))
HOST_WS   := $(patsubst %/,%,$(dir $(HOST_DIR)))
CACHE_ENV := $(if $(CI),-e CARGO_HOME=/tmp/.cargo -e RUSTUP_HOME=/tmp/.rustup)

DOCKER_RUN = docker run --rm \
	--privileged \
	-v $(HOST_WS):/src \
	-h lockboot \
	--add-host lockboot:127.0.0.1 \
	-e OWNER_UID=$(USER_ID) \
	-e OWNER_GID=$(GROUP_ID) \
	$(CACHE_ENV) \
	-w /src/$(REPO_NAME)

docker-shell-base: docker-build-base
	$(DOCKER_RUN) -ti $(DOCKER_SAMEUSER) $(DOCKER_OPT_DOCKER) $(DOCKER_OPT_KVM) $(BUILD_IMAGE) bash

# ---- Workspace build / check / test ----
CARGO = cargo

lock:
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) $(CARGO) generate-lockfile

check:
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) $(CARGO) check --workspace --all-targets --locked

test:
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) $(CARGO) test --workspace --locked

fmt:
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) $(CARGO) fmt --all --check

fmt-fix:
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) $(CARGO) fmt --all

clippy:
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) $(CARGO) clippy --workspace --locked -- -D warnings

# One-shot CI gate (fmt-check + check + clippy + test) in a single container, mirroring the sibling
# repos. `docker-build-base` builds lockboot:build on demand (fresh CI runners have no local image).
ci: docker-build-base
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) bash -c "\
		$(CARGO) fmt --all --check && \
		$(CARGO) check --workspace --all-targets --locked && \
		$(CARGO) clippy --workspace --locked -- -D warnings && \
		$(CARGO) test --workspace --locked"

# ---- Build the loader (payload-agnostic; the image is appended separately by `pack`) ----
build: build-x86_64
build-amd64: build-x86_64
build-arm64: build-aarch64
build-x86_64 build-aarch64: build-%:
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) bash -c "\
		rustup target add $*-unknown-linux-musl && \
		$(CARGO) build --release --locked --target $*-unknown-linux-musl -p bootstrap"

# ---- Pack: loader ELF + appended payload.zip = the stage2 artifact ----
# The loader carries no payload; a rootfs image (with /init) travels as an appended, self-extracting
# zip. INIT_PAYLOAD names the /init binary baked into the test rootfs.erofs (a docker->erofs rootfs
# dir plugs in here for real deploys). Builds loader + /init, forges payload.zip in the erofs-builder
# (mkfs.erofs + veritysetup + mkfs.ext4), then `cat`s + `zip -A`s them into build/<arch>/pack/stage2.
INIT_PAYLOAD ?= pivot-init

pack:
	@echo "needs an arch suffix, e.g. 'make pack-x86_64'." >&2; exit 2

pack-amd64: pack-x86_64
pack-arm64: pack-aarch64
pack-%: docker-build-base docker-build-erofs
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) bash -c "\
		rustup target add $*-unknown-linux-musl && \
		$(CARGO) build --release --locked --target $*-unknown-linux-musl -p bootstrap && \
		$(CARGO) build --release --locked --target $*-unknown-linux-musl -p bootstrap --example $(INIT_PAYLOAD)"
	@mkdir -p build/$*/pack
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) \
		-e SOURCE_DATE_EPOCH -e DATA_SIZE_MB -e ROOTFS_UUID -e VERITY_SALT \
		$(EROFS_IMAGE) \
			--bootstrap "target/$*-unknown-linux-musl/release/bootstrap" \
			"target/$*-unknown-linux-musl/release/examples/$(INIT_PAYLOAD)" \
			"build/$*/pack/stage2"
	@echo "packed stage2 ($(INIT_PAYLOAD)): $$(stat -c%s build/$*/pack/stage2) bytes"

clean:
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) $(CARGO) clean

# ---- Boot-through-harness test (borrows the sibling stage0 boot.disk + stage1 UKI) ----
# Boots stage0 -> stage1 UKI -> our packed stage2 under QEMU/KVM + swtpm, exactly as stage1's
# chain test does. sha256 admission; no signing needed for a local boot test.
STAGE0_DIR       ?= ../stage0
STAGE0_BOOT_DISK ?= $(STAGE0_DIR)/build/$*/boot.disk
STAGE1_DIR       ?= ../stage1
STAGE1_UKI       ?= $(STAGE1_DIR)/tools/build-uki/$*/linux.efi
SERVE_HOST       ?= 10.0.2.1:8000
PERSIST_GROW     ?= 268435456   # bytes to grow the boot.disk copy (room for p2 + p3)

# ---- Full loader test: verity erofs root under an ephemeral overlay + encrypted /data + pivot ----
# `pack`s the loader + a pivot-init /init into a stage2 (loader ELF + appended payload.zip), then
# boots it on a GROWN disk. pivot-init verifies config passthrough + attestations + /data
# persistence + overlay-root ephemerality across an in-guest reboot.
.PHONY: test-pivot
test-pivot:
	@echo "needs an arch suffix, e.g. 'make test-pivot-x86_64'." >&2; exit 2

test-pivot-%: pack-%
	@[ -f "$(STAGE0_BOOT_DISK)" ] || { echo "missing stage0 boot.disk: $(STAGE0_BOOT_DISK)" >&2; exit 1; }
	@[ -f "$(STAGE1_UKI)" ] || { echo "missing stage1 UKI: $(STAGE1_UKI)" >&2; exit 1; }
	@D="build/$*/pivot"; rm -rf "$$D"; mkdir -p "$$D"; H="http://$(SERVE_HOST)"; \
	cp "$(STAGE1_UKI)" "$$D/linux.efi"; \
	cp "build/$*/pack/stage2" "$$D/stage2"; \
	cp "$(STAGE0_BOOT_DISK)" "$$D/boot.disk"; \
	cp "$$(dirname "$(STAGE0_BOOT_DISK)")/efi-vars.ovmf" "$$D/efi-vars.ovmf"; \
	truncate -s +$(PERSIST_GROW) "$$D/boot.disk"; \
	echo "grown boot.disk -> $$(stat -c%s "$$D/boot.disk") bytes"; \
	UKI_SHA=$$(sha256sum "$$D/linux.efi" | cut -d' ' -f1); \
	S2_SHA=$$(sha256sum "$$D/stage2" | cut -d' ' -f1); \
	printf '{\n  "container": { "image": "docker.io/library/busybox@sha256:%064d" },\n  "_stage1": { "%s": { "payload": { "url": "%s/linux.efi", "sha256": "%s" } } },\n  "_stage2": { "%s": { "payload": { "url": "%s/stage2", "sha256": "%s" } } }\n}\n' \
		0 "$*" "$$H" "$$UKI_SHA" "$*" "$$H" "$$S2_SHA" > "$$D/user-data.json"; \
	echo "user-data: UKI $$UKI_SHA  stage2(loader+$(INIT_PAYLOAD)) $$S2_SHA"; \
	$(DOCKER_RUN) $(DOCKER_OPT_KVM) \
		-e YES_INSIDE_DOCKER_DO_DANGEROUS_IPTABLES=1 --cap-add=NET_ADMIN --device=/dev/net/tun \
		$(HARNESS_IMAGE) --kind stage0 --arch $* \
			--boot-disk "$$D/boot.disk" \
			--serve-dir "$$D" --user-data "$$D/user-data.json" \
			$(if $(HARNESS_TIMEOUT),--timeout $(HARNESS_TIMEOUT))

# ---- Self-test: stage2's part of the workspace `make selftest` (PASS/FAIL, non-zero on FAIL) ----
# Two full-chain boots through test-pivot:
#   pivot  pivot-init on the default grown disk: config + attestation + /data resize + persistence
#          + overlay-root ephemerality across an in-guest reboot (PIVOT_TEST=PASS).
#   grow   grow-probe on a 10 GiB sparse grow: /data grows past one ext4 meta_bg (~8 GiB), fresh
#          read/write, sparse hole reads zero (GROW_TEST=PASS). The sparse file costs no host disk;
#          the time is guest-side resize + I/O (~30 s measured on both arches).
# Every boot is time-bounded (HARNESS_TIMEOUT -> qemu-test.sh --timeout). Needs the sibling stage0
# boot.disk + stage1 UKI and the lockboot:harness image (workspace `make selftest-<arch>`).
SELFTEST_TIMEOUT_x86_64  ?= 300
SELFTEST_TIMEOUT_aarch64 ?= 300
.PHONY: selftest
selftest:
	@echo "needs an arch suffix, e.g. 'make selftest-x86_64'." >&2; exit 2
selftest-%:
	@fail=0; T=$(SELFTEST_TIMEOUT_$*); sum="build/$*/selftest.summary"; mkdir -p build/$*; : > "$$sum"; \
	for m in "pivot:PIVOT_TEST=PASS:INIT_PAYLOAD=pivot-init" "grow:GROW_TEST=PASS:INIT_PAYLOAD=grow-probe PERSIST_GROW=10G"; do \
		name="$${m%%:*}"; rest="$${m#*:}"; marker="$${rest%%:*}"; vars="$${rest#*:}"; \
		log="build/$*/selftest-$$name.log"; \
		echo "==================== stage2 test [$$name] $$vars -> $$log"; \
		$(MAKE) --no-print-directory test-pivot-$* $$vars HARNESS_TIMEOUT=$$T > "$$log" 2>&1 || true; \
		if grep -q "$$marker" "$$log"; then \
			echo "PASS [$$name]" | tee -a "$$sum"; \
		else \
			echo "FAIL [$$name] (see $$log)" | tee -a "$$sum"; fail=1; \
		fi; \
	done; \
	echo "==================== stage2 self-test summary ($*)"; cat "$$sum"; \
	if [ "$$fail" = 0 ]; then echo "ALL STAGE2 SELF-TESTS PASSED ($*)"; else echo "SOME STAGE2 SELF-TESTS FAILED ($*)"; exit 1; fi
