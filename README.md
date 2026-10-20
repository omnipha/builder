# omnipha/builder

Omnipha build tool. Fork of [pmbootstrap](https://gitlab.postmarketos.org/postmarketOS/pmbootstrap) (GPL-3.0), extended for the Omnipha goals:

- **Server profiles**: minimal headless target (sshd, no lockscreen, no UI required, optional console UI on the phone display)
- **Agent host profile**: adds container runtime, Node/Python toolchains, ready for Claude Code / Codex / OpenClaw / Hermes
- **SSH key injection at build time**: images boot reachable per SSH key, no password entry on the device ever
- **Headless CI mode**: non-interactive builds driven by GitHub Actions (see omnipha/images)

Upstream is tracked; we rebase our additions on upstream releases.

## Status
Imported at pmbootstrap 3.12.1. The experimental `image` action accepts pinned, clean pmaports and omnipha/ports checkouts, builds an isolated image without prompts, and copies image bytes with a `SHA256SUMS` manifest only when every requested partition is supported. It refuses unsupported image definitions before creating a work directory. CI needs PyYAML, git, OpenSSH's `ssh-keygen`, and the usual pmbootstrap host/chroot dependencies.

A headless CI invocation (with `PMAPORTS_REV` set to the exact checked-out commit) is:

```sh
pmbootstrap -c "$RUNNER_TEMP/pmbootstrap.cfg" -w "$RUNNER_TEMP/pmbootstrap-work" \
  -p "$RUNNER_TEMP/pmaports" image devices/nothing-asteroids/image.yaml \
  --non-interactive --profile server --ssh-pubkey "$RUNNER_TEMP/ci-key.pub" \
  --ports "$RUNNER_TEMP/ports" \
  --ports-revision 0633617cd90dfdc12fb8a8941c4ad0dddad36d3b \
  --aports-revision "$PMAPORTS_REV" --output "$RUNNER_TEMP/image-output"
```

The current Nothing Phone (3a) Pro full `image` recipe deliberately **fails** before any image build: metadata-encrypted userdata remains blocked on builder #4. No devices are accessed by `image`.

The separate `boot_chain` action builds only the slot-A boot chain, never userdata or slot B. It requires a host-only, version-1 JSON `--layout-manifest` and `--input-dir` outside this repository and a new external `--output` directory. It does not fetch inputs or contact a device:

```sh
pmbootstrap boot_chain /external/images/devices/nothing-asteroids/image.yaml \
  --layout-manifest /external/boot-layout.json --input-dir /external/inputs \
  --output /external/boot-output
```

The manifest must contain `version: 1`, `device: "nothing-asteroids"`, `slot: "a"`, `recipe_sha256` (the byte-level SHA-256 of the exact image.yaml), `dtb_index: 9`, `dtbo_index: 65`, `partition_sizes` (byte bounds for `boot`, `init_boot`, `vendor_boot`, `dtbo`, `vbmeta`), and ordered 20-element `dtb_sha256` and 76-element `dtbo_sha256` arrays. `headers` must specify `boot_cmdline`, `init_boot_cmdline`, `vendor_cmdline`, and the verified stock `kernel_offset: 32768`, `ramdisk_offset: 16777216`, `tags_offset: 256`, `dtb_offset: 32505856`, `os_version: 0`. `inputs` must map each of `kernel`, `generic_ramdisk`, `vendor_ramdisk`, `dtbs`, `dtbo`, `bootconfig`, `stock_boot`, `stock_init_boot`, `stock_vendor_boot`, `stock_dtbo`, and `stock_vbmeta` to `{ "file": "basename", "sha256": "64 lower-case hex digits", "provenance": "source/revision and origin", "verification": "independent verification method" }`. Inputs must be external, regular and hash-matched; do not put their bytes or sensitive contents in Git. The stock references must match the five slot-A SHA-256 identifiers pinned by the linux-sm7635 #10 verifier. Supply independently evidenced kernel, init and vendor ramdisks and compatible ordered DTB/DTBO inputs; neither debug artifacts nor unverified stock copies are release inputs.

The gate compares the separate header-v4 generic ramdisk, all ordered DTBs against the stock reference, all DTBO entries, stock AVB hash descriptors/footers, stock bootconfig and DTBO 65 overlay application to DTB 9 using `fdtoverlay`. It generates unsigned AVB0 flags=2 with no key or descriptors; stock vbmeta hashes will not authenticate the new chain and bootloader acceptance is unknown. Successful output is five `.img` files, a slot-A-only `partition-map.json`, and SHA256SUMS computed from the actual image bytes. No compatible per-input manifest or reproducible vendor input set is available from the pinned public ports/image recipe today, so there are **no Nothing boot-chain image SHA-256s** and no boot claim. This path does not approve flashing or relax the metadata-encryption requirement.

Read-only diagnosis before an image can be delivered: obtain externally authorized, SHA-256-checked host-only slot-A references and independent source-built inputs; compare header geometry, generic versus vendor ramdisk roles, every DTB and DTBO entry hash, index-9/entry-65 overlay application, stock AVB relationships and measured partition bounds. In particular the linux-sm7635 #10 verifier rejects the earlier #8 vendor DTB at index 9 (32 missing symbols across 82 fixups) and accepts the stock-compatible corrected set; do not infer that this caused the earlier fastboot return. Record only the hashes, sizes, offsets, structural differences and provenance, then rerun the CLI; leave all raw inputs and resulting images outside Git. If any input cannot be independently verified, stop without generating an image.

## License
GPL-3.0-only (inherited from pmbootstrap).
