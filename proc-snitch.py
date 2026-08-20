#!/usr/bin/env python3
"""
proc-snitch.py — Windows per-process outbound firewall kill switch.

Lists running programs, lets you pick one with arrow keys, and a global
hotkey toggles blocking ALL its outbound traffic via Windows Firewall.

NOTE: blocks ALL outbound traffic for the process (not just web ports).
      To restrict to HTTP/HTTPS only, add 'remoteport=80,443' and
      'protocol=tcp' to the netsh add-rule call in set_block().

Deps:  pip install psutil keyboard
Run:  As Administrator (required for firewall rules + global hotkey).
"""

import os
import sys
import json
import time
import shutil
import hashlib
import threading
import subprocess

IS_WINDOWS = os.name == "nt"

if IS_WINDOWS:
    import ctypes
    import msvcrt
else:
    ctypes = None
    msvcrt = None

try:
    import psutil
except ImportError:
    psutil = None

try:
    import keyboard
except ImportError:
    keyboard = None

# ── paths / config ──────────────────────────────────────────────────
HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG = os.path.join(HERE, "proc-snitch.json")
RULE_TAG = "ProcSnitch"
RULE_PREFIX = RULE_TAG + "_"
DEFAULT_HOTKEY = "ctrl+shift+b"
NETSH_TIMEOUT = 20

# Absolute path to netsh: we run elevated, so resolving it via PATH would
# let anything that can write to a PATH directory run code as Administrator.
NETSH = os.path.join(
    os.environ.get("SystemRoot", r"C:\Windows"), "System32", "netsh.exe"
)
if not os.path.isfile(NETSH):
    NETSH = "netsh"

# Keep netsh from flashing a console window on every call.
_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


def load_cfg():
    base = {"hotkey": DEFAULT_HOTKEY}
    if os.path.exists(CONFIG):
        try:
            with open(CONFIG, encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                base.update(loaded)
            if not isinstance(base.get("hotkey"), str) or not base["hotkey"]:
                base["hotkey"] = DEFAULT_HOTKEY
        except Exception:
            pass
    return base


def save_cfg(cfg):
    try:
        with open(CONFIG, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        return True
    except OSError:
        return False


# ── admin ───────────────────────────────────────────────────────────
def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_elevated():
    """Re-run this script through UAC. Returns True if the prompt was accepted."""
    script = os.path.abspath(__file__)
    params = subprocess.list2cmdline([script] + sys.argv[1:])
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, HERE, 1
        )
    except Exception as e:
        print(f"  Could not elevate: {e}")
        return False
    if rc <= 32:                       # ShellExecuteW error codes are <= 32
        if rc == 5:                    # SE_ERR_ACCESSDENIED — UAC declined
            print("  Elevation declined. proc-snitch needs Administrator rights.")
        else:
            print(f"  Could not elevate (ShellExecuteW returned {rc}).")
        return False
    return True


# ── console encoding ────────────────────────────────────────────────
def _console_encoding():
    if IS_WINDOWS:
        try:
            return "cp" + str(ctypes.windll.kernel32.GetConsoleOutputCP())
        except Exception:
            pass
    return sys.getdefaultencoding()


def _decode(raw):
    """Decode netsh output without ever raising on odd code pages."""
    if isinstance(raw, str):
        return raw
    if not raw:
        return ""
    for enc in (_console_encoding(), "utf-8"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1", "replace")


def _init_stdout():
    """Never let a unicode process name or a box-drawing glyph crash the UI."""
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass
    enc = getattr(sys.stdout, "encoding", None) or "ascii"
    fancy = {"cur": "\u25b8", "on": "\u25a0", "off": "\u25a1",
             "bar": "\u2500", "nav": "\u2191\u2193"}
    try:
        "".join(fancy.values()).encode(enc)
        return fancy
    except (UnicodeEncodeError, LookupError):
        return {"cur": ">", "on": "#", "off": "-", "bar": "-", "nav": "up/dn"}


GLYPH = _init_stdout()


# ── firewall ────────────────────────────────────────────────────────
def _rule_name(exe_path):
    """Unique, stable rule name. The hash is over the full path, so two
    different binaries with the same basename never collide."""
    h = hashlib.md5(exe_path.encode("utf-8", "replace")).hexdigest()[:12]
    base = exe_path.replace("/", "\\").rsplit("\\", 1)[-1] or "exe"
    base = "".join(c for c in base if c.isalnum() or c in "._-")[:48]
    return f"{RULE_PREFIX}{base}_{h}"


def _netsh(args):
    """Run netsh, returning (ok, output). Never raises."""
    try:
        r = subprocess.run(
            [NETSH] + args, capture_output=True, timeout=NETSH_TIMEOUT,
            creationflags=_NO_WINDOW,
        )
    except FileNotFoundError:
        return False, "netsh.exe not found"
    except subprocess.TimeoutExpired:
        return False, "netsh timed out"
    except OSError as e:
        return False, str(e)
    out = (_decode(r.stdout) + _decode(r.stderr)).strip()
    return r.returncode == 0, out


def list_blocked():
    """All exe paths currently blocked by a ProcSnitch rule.

    One netsh call for the whole rule set — probing each executable
    separately took a subprocess per process and made a rescan take
    tens of seconds.  Field labels are localised, so match on values.
    """
    ok, out = _netsh(["advfirewall", "firewall", "show", "rule",
                      "name=all", "dir=out", "verbose"])
    if not ok:
        return None, out
    blocked, current = set(), None
    for line in out.splitlines():
        if ":" not in line:
            continue
        value = line.split(":", 1)[1].strip()
        if value.startswith(RULE_PREFIX):
            current = value
        elif current and (os.path.isabs(value) or value[1:3] == ":\\"):
            # first absolute path after a ProcSnitch rule name is its program
            blocked.add(os.path.normcase(value))
            current = None
    return blocked, ""


def set_block(exe_path, on):
    """Add or remove the outbound block rule. Returns (ok, message)."""
    rn = _rule_name(exe_path)
    if on:
        ok, out = _netsh(["advfirewall", "firewall", "add", "rule",
                          f"name={rn}", "dir=out", "action=block",
                          f"program={exe_path}", "profile=any", "enable=yes"])
    else:
        ok, out = _netsh(["advfirewall", "firewall", "delete", "rule",
                          f"name={rn}"])
    return ok, out


# ── process scan ────────────────────────────────────────────────────
def scan_processes():
    """Sorted list of (exe_path, name) for unique executables."""
    seen = {}
    for p in psutil.process_iter(["name", "exe"]):
        try:
            exe = p.info["exe"]
            name = p.info["name"] or os.path.basename(exe or "")
            if not exe or exe in seen:
                continue
            if os.path.isfile(exe):
                seen[exe] = name
        except (psutil.Error, OSError, ValueError):
            continue
    return sorted(seen.items(), key=lambda kv: (kv[1].lower(), kv[0].lower()))


# ── terminal io ─────────────────────────────────────────────────────
def cls():
    # ANSI is handled by the Windows 10+ console; avoids spawning cmd.exe
    # ~25x/second the way os.system("cls") did.
    sys.stdout.write("\x1b[2J\x1b[H")


def _enable_ansi():
    try:
        h = ctypes.windll.kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if ctypes.windll.kernel32.GetConsoleMode(h, ctypes.byref(mode)):
            ctypes.windll.kernel32.SetConsoleMode(h, mode.value | 0x0004)
    except Exception:
        pass


_KEYMAP = {72: "up", 80: "down", 75: "left", 77: "right",
           73: "pgup", 81: "pgdn", 71: "home", 79: "end"}


def read_key():
    """Non-blocking key read. Returns 'up'/'down'/'enter'/'esc'/char or None."""
    if not msvcrt.kbhit():
        return None
    ch = msvcrt.getch()
    if ch in (b"\x00", b"\xe0"):                          # extended prefix
        return _KEYMAP.get(msvcrt.getch()[0])
    if ch == b"\r":
        return "enter"
    if ch == b"\x1b":
        return "esc"
    if ch == b"\x03":
        return "q"                                        # ctrl+c
    try:
        return ch.decode("ascii").lower()
    except UnicodeDecodeError:
        return None


# ── app ─────────────────────────────────────────────────────────────
class App:
    FLASH_SECS = 4.0

    def __init__(self, cfg):
        self.cfg = cfg
        self.hotkey = cfg["hotkey"]
        self.hook = None
        self.lock = threading.Lock()      # guards blocked_set + netsh writes
        self.blocked_set = set()
        self.items = []
        self.sel = 0
        self.top = 0
        self.selected = None              # (exe, name)
        self.mode = "select"              # "select" | "guard"
        self.flash_msg = ""
        self.flash_at = 0.0
        self.dirty = True
        self.running = True

    # ── state ────────────────────────────────────────────────────────
    def flash(self, msg):
        self.flash_msg = msg
        self.flash_at = time.monotonic()
        self.dirty = True

    def refresh_blocked(self):
        found, err = list_blocked()
        if found is None:
            self.flash(f"Could not read firewall rules: {err.splitlines()[0] if err else '?'}")
            return
        with self.lock:
            self.blocked_set = found

    def is_blocked(self, exe):
        return os.path.normcase(exe) in self.blocked_set

    def rescan(self):
        self.items = scan_processes()
        self.refresh_blocked()
        self.sel = min(self.sel, max(0, len(self.items) - 1))
        self.flash(f"Rescanned — {len(self.items)} programs")

    def toggle(self):
        """Global hotkey callback — runs in the keyboard library's thread."""
        sel = self.selected
        if sel is None:
            return
        exe, name = sel
        with self.lock:
            turn_on = os.path.normcase(exe) not in self.blocked_set
            ok, out = set_block(exe, turn_on)
            if ok:
                if turn_on:
                    self.blocked_set.add(os.path.normcase(exe))
                else:
                    self.blocked_set.discard(os.path.normcase(exe))
        if ok:
            verb = f"{GLYPH['on']} BLOCKED" if turn_on else f"{GLYPH['off']} unblocked"
            self.flash(f"{verb}: {name}")
        else:
            first = out.splitlines()[0] if out else "netsh failed"
            self.flash(f"! firewall error: {first}")

    def install_hotkey(self, hk):
        """Bind hk. Raises on an invalid combination, leaving the old one live."""
        new = keyboard.add_hotkey(hk, self.toggle)
        if self.hook is not None:
            try:
                keyboard.remove_hotkey(self.hook)
            except (KeyError, ValueError):
                pass
        self.hook = new

    def remove_hotkey(self):
        if self.hook is not None:
            try:
                keyboard.remove_hotkey(self.hook)
            except (KeyError, ValueError):
                pass
            self.hook = None

    # ── drawing ──────────────────────────────────────────────────────
    def _viewport(self, rows):
        """Scroll window so the selection stays visible on long process lists."""
        if len(self.items) <= rows:
            self.top = 0
        else:
            self.top = max(0, min(self.top, len(self.items) - rows))
            if self.sel < self.top:
                self.top = self.sel
            elif self.sel >= self.top + rows:
                self.top = self.sel - rows + 1
        return self.top, min(len(self.items), self.top + rows)

    def draw(self):
        cols, lines = shutil.get_terminal_size((80, 25))
        rows = max(3, lines - 7)
        start, end = self._viewport(rows)
        buf = [f"  Proc-Snitch   hotkey: [{self.hotkey}]   "
               f"[h]hotkey [r]rescan [q]quit", ""]
        for i in range(start, end):
            exe, name = self.items[i]
            cur = GLYPH["cur"] if (self.mode == "select" and i == self.sel) else " "
            st = " " + (GLYPH["on"] if self.is_blocked(exe) else " ")
            buf.append(f" {cur}{st} [{i + 1:>3}] {name}"[:cols - 1])
        if end < len(self.items) or start > 0:
            buf.append(f"      ... {start + 1}-{end} of {len(self.items)}")
        if not self.items:
            buf.append("      (no processes — press [r] to rescan)")
        if self.flash_msg:
            buf.append(f"\n  {GLYPH['bar'] * 2} {self.flash_msg} {GLYPH['bar'] * 2}"[:cols - 1])
        if self.mode == "guard":
            name = self.selected[1] if self.selected else "?"
            buf.append(f"\n  Guarding: {name} — press [{self.hotkey}] to toggle  [b]ack")
        else:
            buf.append(f"\n  {GLYPH['nav']} navigate   Enter select")
        cls()
        sys.stdout.write("\n".join(buf) + "\n")
        sys.stdout.flush()
        self.dirty = False

    def prompt_hotkey(self):
        cls()
        sys.stdout.flush()
        try:
            new = input(f"  Hotkey now: {self.hotkey}\n"
                        f"  New (e.g. ctrl+shift+x), blank to keep: ").strip()
        except (EOFError, KeyboardInterrupt):
            new = ""
        if new:
            try:
                self.install_hotkey(new)
            except Exception as e:
                self.flash(f"Invalid hotkey ({e}) — keeping {self.hotkey}")
            else:
                self.hotkey = new
                self.cfg["hotkey"] = new
                if save_cfg(self.cfg):
                    self.flash(f"Hotkey -> {new}")
                else:
                    self.flash(f"Hotkey -> {new} (could not save config)")
        self.dirty = True

    # ── input ────────────────────────────────────────────────────────
    def handle(self, k):
        self.dirty = True
        if k == "q":
            self.running = False
        elif k == "r":
            self.rescan()
        elif k == "h":
            self.prompt_hotkey()
        elif self.mode == "select":
            rows = max(3, shutil.get_terminal_size((80, 25)).lines - 7)
            last = len(self.items) - 1
            if k == "up":
                self.sel = max(0, self.sel - 1)
            elif k == "down":
                self.sel = min(last, self.sel + 1)
            elif k == "pgup":
                self.sel = max(0, self.sel - rows)
            elif k == "pgdn":
                self.sel = min(last, self.sel + rows)
            elif k == "home":
                self.sel = 0
            elif k == "end":
                self.sel = max(0, last)
            elif k == "enter" and self.items:
                self.selected = self.items[self.sel]
                self.mode = "guard"
                self.flash(f"Guarding {self.selected[1]}")
        elif self.mode == "guard":
            if k in ("b", "esc"):
                self.mode = "select"

    # ── shutdown ─────────────────────────────────────────────────────
    def cleanup_prompt(self):
        """Firewall rules outlive the process — say so, and offer to drop them."""
        with self.lock:
            active = sorted(self.blocked_set)
        if not active:
            return
        cls()
        print(f"\n  {len(active)} ProcSnitch block rule(s) are still active:\n")
        for exe in active[:20]:
            print(f"    {GLYPH['on']} {exe}")
        if len(active) > 20:
            print(f"    ... and {len(active) - 20} more")
        print("\n  These survive exit and keep blocking until removed.")
        try:
            answer = input("  Remove them all now? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer != "y":
            print("  Left in place. Re-run proc-snitch to toggle them off.")
            return
        removed = 0
        for exe, _ in self.items:
            if os.path.normcase(exe) in self.blocked_set:
                ok, _out = set_block(exe, False)
                removed += bool(ok)
        # Rules whose executable is no longer running are matched by name only.
        leftover, _err = list_blocked()
        if leftover is None:
            print(f"  Removed {removed} rule(s); could not re-check the firewall.")
        elif leftover:
            print(f"  Removed {removed}; {len(leftover)} rule(s) remain "
                  f"(their programs are no longer running).")
            print("  Clear manually: netsh advfirewall firewall delete rule "
                  f'name=all program="<path>"')
        else:
            print(f"  Removed {removed} rule(s).")

    # ── loop ─────────────────────────────────────────────────────────
    def run(self):
        try:
            self.install_hotkey(self.hotkey)
        except Exception as e:
            self.flash(f"Could not bind hotkey [{self.hotkey}]: {e}")
        self.rescan()
        try:
            while self.running:
                if self.flash_msg and time.monotonic() - self.flash_at > self.FLASH_SECS:
                    self.flash_msg = ""
                    self.dirty = True
                if self.dirty:
                    self.draw()
                k = read_key()
                if k is None:
                    time.sleep(0.04)
                    continue
                self.handle(k)
        except KeyboardInterrupt:
            pass
        finally:
            self.remove_hotkey()
            try:
                self.cleanup_prompt()
            except Exception:
                pass


# ── main ────────────────────────────────────────────────────────────
def preflight():
    """Return a list of fatal problems, phrased for a human."""
    problems = []
    if not IS_WINDOWS:
        problems.append(
            f"proc-snitch only runs on Windows (Windows Firewall + netsh); "
            f"this is {sys.platform}."
        )
        return problems
    if sys.version_info < (3, 8):
        problems.append(f"Python 3.8+ required (running {sys.version.split()[0]}).")
    missing = [n for n, m in (("psutil", psutil), ("keyboard", keyboard)) if m is None]
    if missing:
        problems.append(f"Missing dependencies: {', '.join(missing)}. "
                        f"Install with: pip install {' '.join(missing)}")
    return problems


def main():
    problems = preflight()
    if problems:
        for p in problems:
            print(f"  ! {p}", file=sys.stderr)
        return 1

    if not is_admin():
        print("  proc-snitch needs Administrator rights — requesting elevation...")
        return 0 if relaunch_elevated() else 1

    _enable_ansi()
    app = App(load_cfg())
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
