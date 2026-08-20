# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Auto-detect related processes** — guarding a program also picks up its
  parent, its children, sibling `.exe` files under the same install directory,
  and processes spawned by the same launcher. All are blocked together, and the
  flash message shows the count: `Guarding chrome (12 processes)`.
- Pre-built `proc-snitch.exe` now lives in the repo root, so it can be
  downloaded without going through the releases page.

### Fixed

- Config path when running as a frozen `.exe`: `proc-snitch.json` was written
  into PyInstaller's temporary extraction directory and lost on exit. It is now
  saved next to the executable.
- UAC re-launch from the frozen `.exe` passed the `.py` path as an argument to
  itself and never elevated.
- The overlay never left its "no guard active" state, because it unpacked the
  selection tuple with the pre-1.2.0 shape.
- Rescanning could crash with a `TypeError` when two processes shared a display
  name — `psutil.Process` handles ended up in the sort key and are not
  orderable.
- Related-process detection compared bound methods instead of parent PIDs, so
  the "same launcher" heuristic never matched anything.
- Related-process detection no longer sweeps sibling binaries in shared
  locations (`System32`, `Program Files`, `%LOCALAPPDATA%`, …), where guarding
  one process could pull in unrelated programs.
- Clear-all and the exit prompt now work off the firewall's own rule list, so
  rules whose program has since exited are removed instead of reported as
  leftovers.
- The hotkey toggle reports how many rules failed to apply instead of silently
  counting them as successful.

### Changed

- Scanned processes are a flat `(exe, name, handle)` tuple throughout, removing
  the mismatched unpacking left over from the multi-process refactor.
- `make_logo.py` is importable (no work at module import) and its ICO dump no
  longer misreports frame offsets and sizes.
- Dropped the SSH cross-build instructions from the README now that the `.exe`
  ships in the repo.

## [1.2.0] - 2026-08-20

### Added

- Persistent top-left overlay status window (tkinter, always-on-top) showing
  the guarded program and its block state.

### Changed

- Blocking now writes an **inbound rule as well as an outbound one**; both are
  added and removed together, and the block covers every port and protocol.

## [1.1.0] - 2026-08-20

### Added

- `c` clears every active ProcSnitch block rule at once, with confirmation.
- Logo (shield + cut bar) as `proc-snitch.ico` and `proc-snitch.png`, generated
  by `make_logo.py`.
- Release instructions and a pre-built `.exe` attached to releases.

## [1.0.0] - 2026-08-20

Initial release.

### Added

- Live process list with arrow-key navigation, paging, and scrolling for long
  lists.
- Global hotkey (`Ctrl+Shift+B`, rebindable with `h`) that toggles an outbound
  Windows Firewall block rule for the guarded program.
- Automatic UAC elevation on start.
- Hotkey persisted to `proc-snitch.json`.
- Block state read back from the firewall on every rescan, so rules left over
  from a previous run show up as active.
- Exit prompt to remove any block rules still in effect.

[Unreleased]: https://github.com/Valli-2020/proc-snitch/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/Valli-2020/proc-snitch/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Valli-2020/proc-snitch/releases/tag/v1.1.0
[1.0.0]: https://github.com/Valli-2020/proc-snitch/commit/6cedbc4
