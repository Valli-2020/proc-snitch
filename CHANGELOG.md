# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `c` key clears ALL active ProcSnitch block rules at once (with confirmation).
- Logo (shield + cut bar) as `proc-snitch.ico` and `proc-snitch.png`.
- GitHub Actions workflow to build `proc-snitch.exe` on Windows runners.
- Pre-built `.exe` attached to every release.

## [1.0.0] - 2026-08-20

Initial release.

### Added

- Live process list with arrow-key navigation, paging, and scrolling for long lists.
- Global hotkey (`Ctrl+Shift+B`, rebindable with `h`) that toggles an outbound
  Windows Firewall block rule for the guarded program.
- Automatic UAC elevation on start.
- Hotkey persisted to `proc-snitch.json`.
- Block state read back from the firewall on every rescan, so rules left over
  from a previous run show up as active.
- Exit prompt to remove any block rules still in effect.

[1.0.0]: https://github.com/Valli-2020/proc-snitch/releases/tag/v1.0.0
