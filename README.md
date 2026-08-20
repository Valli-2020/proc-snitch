# proc-snitch

![logo](proc-snitch.png)

**Windows per-process inbound + outbound firewall kill switch.**

Pick a program from a live process list, then cut all its network access
with a global hotkey — from anywhere, without alt-tabbing out of whatever
you're doing.

## What it does

proc-snitch is a small terminal UI over Windows Firewall. It enumerates every
running executable, lets you "guard" one, and binds a global hotkey
(`Ctrl+Shift+B` by default) that toggles inbound AND outbound **block**
rules for that executable's path.

Blocking adds two firewall rules (inbound + outbound) named
`ProcSnitch_<exe>_<in|out>_<hash>`; unblocking deletes both. Nothing is patched,
injected, or killed — the process keeps running, it just stops reaching the
network.

Useful for cutting a game's telemetry mid-session, freezing an updater, or
pulling the plug on something chatty without hunting through `wf.msc`.

## Features

- **Global hotkey toggle** — works from inside a fullscreen game or any other
  window, no alt-tabbing.
- **Inbound *and* outbound blocking** — every port, every protocol, all
  firewall profiles.
- **Multi-process group detection** — guarding one program also picks up its
  parent, its children, sibling `.exe` files from the same install directory,
  and processes spawned by the same launcher, so a browser's renderers or a
  game's launcher/anti-cheat helpers get blocked together. Shared locations
  like `System32` and `Program Files` are excluded from the directory sweep,
  so guarding a system process never sweeps in the whole OS.
- **Always-on-top overlay** — a small top-left status window shows the guarded
  program and whether it is currently blocked, without stealing focus.
- **Clear-all** — one keypress removes every rule proc-snitch ever wrote,
  including rules left over from a previous run whose program has since exited.
- **State read back from the firewall** — rules that survived a crash or a
  previous session show up as active on the next scan.
- **Exit prompt** — quitting with blocks still live tells you so and offers to
  remove them.

## Install

A pre-built `proc-snitch.exe` sits in the repo root — download it and run it,
no Python needed. It is also attached to every
[release](https://github.com/Valli-2020/proc-snitch/releases).

To run from source instead:

```powershell
pip install psutil keyboard
python proc-snitch.py
```

## Usage

Launch the `.exe` (or the script). proc-snitch requests Administrator rights
via UAC and relaunches itself — firewall rules and global hotkeys both require
elevation.

Your hotkey choice is saved to `proc-snitch.json`, next to the executable.

```
  Proc-Snitch   hotkey: [ctrl+shift+b]   [h]hotkey [r]rescan [c]clear-all [q]quit

    [  1] chrome.exe
 ▸ ■ [  2] Discord.exe
    [  3] explorer.exe
    [  4] steam.exe
      ... 1-4 of 187

  ── ■ BLOCKED: Discord.exe (7 processes) ──

  Guarding: Discord.exe — press [ctrl+shift+b] to toggle  [b]ack
```

Meanwhile, in the top-left corner of the screen:

```
  ┌────────────────────────────────┐
  │ proc-snitch                    │
  │ ■ BLOCKED                      │
  │ CTRL+SHIFT+B toggles · Discord │
  └────────────────────────────────┘
```

## Controls

| Key | Action |
| --- | --- |
| `↑` / `↓` | Move through the process list |
| `PgUp` / `PgDn` | Jump a page |
| `Home` / `End` | Jump to first / last entry |
| `Enter` | Guard the selected program (and its related processes) |
| `Ctrl+Shift+B` | **Toggle block** for the guarded group (global — works in any window) |
| `b` / `Esc` | Back to the list |
| `h` | Change the global hotkey |
| `r` | Rescan running processes |
| `c` | **Clear all** ProcSnitch block rules (with confirmation) |
| `q` | Quit |

A `■` next to an entry means block rules are currently active for it. The
overlay in the top-left shows the guarded program's block state too.

## Scope of the block

proc-snitch blocks **all network traffic** for each executable in the guarded
group — inbound and outbound, every port and protocol, on every firewall
profile.

To limit it to HTTP/HTTPS instead, add `protocol=tcp` and `remoteport=80,443`
to both `add rule` calls in `set_block()`:

```python
ok_out, msg_out = _netsh(["advfirewall", "firewall", "add", "rule",
                          f"name={rn_out}", "dir=out", "action=block",
                          f"program={exe_path}", "profile=any", "enable=yes",
                          "protocol=tcp", "remoteport=80,443"])
ok_in, msg_in = _netsh(["advfirewall", "firewall", "add", "rule",
                        f"name={rn_in}", "dir=in", "action=block",
                        f"program={exe_path}", "profile=any", "enable=yes",
                        "protocol=tcp", "remoteport=80,443"])
```

**Firewall rules outlive the process.** If you quit while blocks are active,
proc-snitch lists them and offers to remove them all. Decline and they stay in
effect until you re-run proc-snitch (`c` clears everything) or delete them in
Windows Defender Firewall.

## Requirements

- Windows (uses `netsh advfirewall`; on any other platform the script exits
  with a clear message)
- Administrator rights
- Python 3.8+ — source only, the `.exe` bundles its own
- `psutil`, `keyboard` — source only

`tkinter` is optional: without it the overlay is silently skipped and
everything else works as normal.

## Build

```powershell
pip install psutil keyboard pyinstaller
pyinstaller --onefile --console --icon proc-snitch.ico --name proc-snitch proc-snitch.py
# .exe lands in dist/proc-snitch.exe — copy it to the repo root to replace the shipped one
```

The logo is generated, not hand-drawn:

```powershell
pip install pillow
python make_logo.py    # rewrites proc-snitch.ico and proc-snitch.png
```

## License

MIT — see [LICENSE](LICENSE).
