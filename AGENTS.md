# AGENTS.md — omnipha/builder

Python CLI tool (fork of pmbootstrap). Entry point: pmbootstrap.py / pmb/.

## Layout
- pmb/ — package code (config, install, flasher, parse, build)
- pmb/config/ — defaults, device/UI selection
- Tests: pmb/test/ (pytest)

## Omnipha extensions (planned; open issues before implementing)
1. `--profile server|agent-host|console-ui` selecting package sets and services
2. `--ssh-pubkey <file|url>` injected into the image at install time
3. `--non-interactive` full CI mode (no prompts, fail-fast)

## Conventions
- Keep diff to upstream minimal; upstreamable changes go upstream first when sensible.
- Run `pytest pmb/test` before committing (needs pmaports checkout).
- One feature per PR. Sign commits.
