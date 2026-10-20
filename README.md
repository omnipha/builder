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

## License
GPL-3.0-only (inherited from pmbootstrap).
