# omnipha/builder

Omnipha build tool. Fork of [pmbootstrap](https://gitlab.postmarketos.org/postmarketOS/pmbootstrap) (GPL-3.0), extended for the Omnipha goals:

- **Server profiles**: minimal headless target (sshd, no lockscreen, no UI required, optional console UI on the phone display)
- **Agent host profile**: adds container runtime, Node/Python toolchains, ready for Claude Code / Codex / OpenClaw / Hermes
- **SSH key injection at build time**: images boot reachable per SSH key, no password entry on the device ever
- **Headless CI mode**: non-interactive builds driven by GitHub Actions (see omnipha/images)

Upstream is tracked; we rebase our additions on upstream releases.

## Status
Imported at pmbootstrap 3.12.1. Omnipha extensions: planned (see issues).

## License
GPL-3.0-only (inherited from pmbootstrap).
