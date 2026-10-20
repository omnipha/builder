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

The current Nothing Phone (3a) Pro definition deliberately **fails** before any image build: Android metadata encryption, `dtbo`/`vbmeta`, and header-v4 `init_boot` are not implemented by pmbootstrap. Do not treat a definition hash or a header-v4 `boot.img` alone as a flashable server image. No devices are accessed by `image`.

### nothing-asteroids userdata encryption gate (#4)

`flash.userdata.filesystem: f2fs` only selects the filesystem inside the image; pmbootstrap formats and populates it as plaintext. `--fde` is passphrase-based LUKS, not Android metadata encryption. Neither produces the requested wrapped-key metadata-encrypted `userdata`, and no device secrets may be baked into a release artifact. The recipe is rejected before staging/building, even if a `metadata` partition name is added.

[Android metadata encryption](https://source.android.com/docs/security/features/encryption/metadata) uses a separate, formattable `/metadata` filesystem for the persistent key (typically ext4 on a dedicated partition), a device-specific boot path to generate/retrieve and protect the key via KeyMint/Keystore, and `dm-default-key` beneath `/data`. Its F2FS `/data` example requires `keydirectory=/metadata/vold/metadata_encryption` and file-based encryption configuration; `metadata_encryption=...:wrappedkey_v0` is relevant to the wrapped-key variant. `vold` must start and KeyMint must be ready before mounting `/data`, with compatible fstab/init and kernel support (`CONFIG_DM_DEFAULT_KEY`, `CONFIG_BLK_INLINE_ENCRYPTION`, `CONFIG_FS_ENCRYPTION_INLINE_CRYPT`, plus compatible inline-crypto hardware or fallback). [AOSP vold's implementation](https://android.googlesource.com/platform/system/vold/+/refs/heads/main/MetadataCrypt.cpp) generates/loads a key and formats through the encrypted mapping when instructed, or conditionally attempts in-place encryption; it cannot make the existing plaintext image encrypted simply by naming the partition. The public ports kernel config enables those three kernel options, but this does not establish working device-specific key management, fstab, init order, wrapped-key support, or safe conversion on nothing-asteroids.

First-boot initialization is plausible only with a verified device boot path and partition/key lifecycle, normally with an empty, formattable userdata partition; it is **not** a reproducibly provisioned, prepopulated server image and may erase any staged contents. Do not rely on unverified in-place conversion or preserve stock `/metadata` keys without an explicit migration plan. A product owner must explicitly choose and authorize a corrected image definition (and its encryption/boot-time implementation), or provide verifiable public partition layout, key-management and early-boot prerequisites for a separate supported provisioning flow. Until then builder#1 and images#1 remain blocked; do not change `encryption: metadata` to `none` or claim an image hash/flashable result for this recipe. No physical-device validation is claimed.

## License
GPL-3.0-only (inherited from pmbootstrap).
