# proc-snitch

![logo](proc-snitch.png)

**Windows per-process outbound firewall kill switch.**

Pick a program from a live process list, then cut its internet access with a
global hotkey — from anywhere, without alt-tabbing out of whatever you're doing.

## What it does

proc-snitch is a small terminal UI over Windows Firewall. It enumerates every
running executable, lets you "guard" one, and binds a global hotkey
(`Ctrl+Shift+B` by default) that toggles an outbound **block** rule for that
executable's path.

Blocking adds a firewall rule named `ProcSnitch_<exe>_<hash>`; unblocking
deletes it. Nothing is patched, injected, or killed — the process keeps running,
it just stops reaching the network.

Useful for cutting a game's telemetry mid-session, freezing an updater, or
pulling the plug on something chatty without hunting through `wf.msc`.

## Install

Pre-built `.exe` attached to every [release](https://github.com/Valli-2020/proc-snitch/releases).

Or build locally:

```powershell
pip install psutil keyboard pyinstaller
pyinstaller --onefile --console --icon proc-snitch.ico --name proc-snitch proc-snitch.py
# .exe lands in dist/proc-snitch.exe
```

## Usage

```
python proc-snitch.py
```

The script requests Administrator rights via UAC and relaunches itself —
firewall rules and global hotkeys both require elevation.

Your hotkey choice is saved to `proc-snitch.json` next to the script.

## Controls

| Key | Action |
| --- | --- |
| `↑` / `↓` | Move through the process list |
| `PgUp` / `PgDn` | Jump a page |
| `Home` / `End` | Jump to first / last entry |
| `Enter` | Guard the selected program |
| `Ctrl+Shift+B` | **Toggle block** for the guarded program (global — works in any window) |
| `b` / `Esc` | Back to the list |
| `h` | Change the global hotkey |
| `r` | Rescan running processes |
| `c` | **Clear all** ProcSnitch block rules (with confirmation) |
| `q` | Quit |

A `■` next to an entry means an outbound block rule is currently active for it.

## Scope of the block

proc-snitch blocks **all outbound traffic** for the executable — every port and
protocol, on every firewall profile — not just web traffic. A blocked program
also can't reach DNS, update servers, or LAN peers.

To limit it to HTTP/HTTPS instead, add `protocol=tcp` and `remoteport=80,443`
to the `add rule` call in `set_block()`:

```python
ok, out = _netsh(["advfirewall", "firewall", "add", "rule",
                  f"name={rn}", "dir=out", "action=block",
                  f"program={exe_path}", "profile=any", "enable=yes",
                  "protocol=tcp", "remoteport=80,443"])
```

**Firewall rules outlive the process.** If you quit while blocks are active,
proc-snitch lists them and offers to remove them all. Decline and they stay in
effect until you re-run proc-snitch or delete them in Windows Defender Firewall.

## Requirements

- Windows (uses `netsh advfirewall` — the script exits with a clear message elsewhere)
- Administrator rights
- Python 3.8+
- `psutil`, `keyboard`

## License

MIT — see [LICENSE](LICENSE).
