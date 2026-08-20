#!/usr/bin/env python3
"""
proc-snitch.py — Windows per-process firewall kill switch.

Lists running programs, lets you pick one with arrow keys, and a global
hotkey toggles blocking ALL of its network traffic (inbound and outbound)
via Windows Firewall.

NOTE: blocks every port and protocol for the program. To restrict to
      HTTP/HTTPS only, add 'protocol=tcp' and 'remoteport=80,443' to the
      netsh add-rule calls in set_block().

Deps:  pip install psutil keyboard
Run:   As Administrator (required for firewall rules + global hotkey).
"""

import os
import sys
import json
import time
import shutil
import hashlib
import threading
import subprocess
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

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

try:
    import tkinter as tk
    HAS_TK = True
except ImportError:
    tk = None
    HAS_TK = False

# ── paths / config ──────────────────────────────────────────────────
# When frozen by PyInstaller, __file__ points into the temporary extraction
# directory, so the config would be written somewhere that vanishes on exit.
# Anchor everything to the .exe instead.
FROZEN = bool(getattr(sys, "frozen", False))
APP_DIR = os.path.dirname(os.path.abspath(sys.executable if FROZEN else __file__))
CONFIG = os.path.join(APP_DIR, "proc-snitch.json")

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

# One scanned process: (exe path, display name, psutil handle or None).
# The handle is None for entries discovered by walking the process tree
# rather than by the top-level scan.
Item = Tuple[str, str, Optional["psutil.Process"]]


def load_cfg() -> Dict[str, object]:
    """Read proc-snitch.json, falling back to defaults on anything unusable."""
    base: Dict[str, object] = {"hotkey": DEFAULT_HOTKEY}
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


def save_cfg(cfg: Dict[str, object]) -> bool:
    """Persist the config. Returns False if it could not be written."""
    try:
        with open(CONFIG, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        return True
    except OSError:
        return False


# ── admin ───────────────────────────────────────────────────────────
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_elevated() -> bool:
    """Re-run proc-snitch through UAC. Returns True if the prompt was accepted."""
    if FROZEN:
        target = sys.executable
        params = subprocess.list2cmdline(sys.argv[1:])
    else:
        target = sys.executable
        params = subprocess.list2cmdline([os.path.abspath(__file__)] + sys.argv[1:])
    try:
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", target, params, APP_DIR, 1
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
def _console_encoding() -> str:
    if IS_WINDOWS:
        try:
            return "cp" + str(ctypes.windll.kernel32.GetConsoleOutputCP())
        except Exception:
            pass
    return sys.getdefaultencoding()


def _decode(raw) -> str:
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


def _init_stdout() -> Dict[str, str]:
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
def _short_hash(text: str) -> str:
    """Short, stable id for a path. Not security-relevant — md5 is used only
    so rule names stay identical across versions; keep it that way or rules
    written by an older build become unreachable by name."""
    data = text.encode("utf-8", "replace")
    try:
        return hashlib.md5(data, usedforsecurity=False).hexdigest()[:12]
    except TypeError:                  # usedforsecurity is Python 3.9+
        return hashlib.md5(data).hexdigest()[:12]


def _rule_name(exe_path: str, direction: str) -> str:
    """Unique, stable rule name. The hash is over the full path, so two
    different binaries with the same basename never collide."""
    base = exe_path.replace("/", "\\").rsplit("\\", 1)[-1] or "exe"
    base = "".join(c for c in base if c.isalnum() or c in "._-")[:48]
    return f"{RULE_PREFIX}{base}_{direction}_{_short_hash(exe_path)}"


def _netsh(args: Sequence[str]) -> Tuple[bool, str]:
    """Run netsh, returning (ok, output). Never raises."""
    try:
        r = subprocess.run(
            [NETSH] + list(args), capture_output=True, timeout=NETSH_TIMEOUT,
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


def list_blocked() -> Tuple[Optional[Set[str]], str]:
    """All exe paths currently blocked by a ProcSnitch rule, normcased.

    Returns (paths, "") on success and (None, error) on failure.

    One netsh call for the whole rule set — probing each executable
    separately took a subprocess per process and made a rescan take
    tens of seconds. Field labels are localised, so match on values.
    Only outbound rules are enumerated; set_block() always writes and
    deletes the inbound/outbound pair together, so they stay in sync.
    """
    ok, out = _netsh(["advfirewall", "firewall", "show", "rule",
                      "name=all", "dir=out", "verbose"])
    if not ok:
        return None, out
    blocked: Set[str] = set()
    current: Optional[str] = None
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


def set_block(exe_path: str, on: bool) -> Tuple[bool, str]:
    """Add or remove the inbound AND outbound block rules for one program.

    Returns (ok, message); ok is True only if both directions succeeded.
    """
    rn_out = _rule_name(exe_path, "out")
    rn_in = _rule_name(exe_path, "in")
    if on:
        ok_out, msg_out = _netsh(["advfirewall", "firewall", "add", "rule",
                                  f"name={rn_out}", "dir=out", "action=block",
                                  f"program={exe_path}", "profile=any",
                                  "enable=yes"])
        ok_in, msg_in = _netsh(["advfirewall", "firewall", "add", "rule",
                                f"name={rn_in}", "dir=in", "action=block",
                                f"program={exe_path}", "profile=any",
                                "enable=yes"])
    else:
        ok_out, msg_out = _netsh(["advfirewall", "firewall", "delete", "rule",
                                  f"name={rn_out}"])
        ok_in, msg_in = _netsh(["advfirewall", "firewall", "delete", "rule",
                                f"name={rn_in}"])
    return ok_out and ok_in, (msg_out + "\n" + msg_in).strip()


# ── overlay ─────────────────────────────────────────────────────────
class Overlay:
    """Persistent top-left status window (always-on-top).

    Shows the currently guarded program and its block state. Runs in a
    background daemon thread so the console UI keeps working. If tkinter
    is unavailable (HAS_TK is False) every method is a no-op and the rest
    of the app is unaffected.
    """

    BG = "#1a1b26"
    FG = "#c0caf5"
    ACCENT = "#7aa2f7"
    RED = "#f7768e"
    DIM = "#565f89"
    GEOM = "+5+5"
    REFRESH_MS = 250

    def __init__(self, app: "App"):
        self.app = app
        self.root = None
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if not HAS_TK or not IS_WINDOWS:
            return
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        """Ask the Tk thread to exit its mainloop. Safe to call more than once."""
        root, self.root = self.root, None
        if root is None:
            return
        try:
            # Tk is not thread-safe: hand the quit to its own event loop.
            root.after(0, root.quit)
        except Exception:
            pass

    def _run(self) -> None:
        try:
            self.root = tk.Tk()
            self.root.overrideredirect(True)
            self.root.attributes("-topmost", True)
            self.root.attributes("-alpha", 0.92)
            self.root.configure(bg=self.BG)
            self.root.geometry(self.GEOM)

            frame = tk.Frame(self.root, bg=self.BG, padx=8, pady=4)
            frame.pack()

            self.title_label = tk.Label(
                frame, text="proc-snitch", bg=self.BG, fg=self.ACCENT,
                font=("Consolas", 9, "bold"),
            )
            self.title_label.pack(anchor="w")

            self.status_label = tk.Label(
                frame, text="— no guard active —", bg=self.BG, fg=self.DIM,
                font=("Consolas", 8),
            )
            self.status_label.pack(anchor="w")

            self.detail_label = tk.Label(
                frame, text="", bg=self.BG, fg=self.DIM,
                font=("Consolas", 7),
            )
            self.detail_label.pack(anchor="w")

            self._tick()
            self.root.mainloop()
        except Exception:
            # A missing display or a broken Tk install must not take the
            # console UI down with it.
            self.root = None

    def _tick(self) -> None:
        if self.root is None:
            return
        try:
            app = self.app
            if app.selected is None:
                self.status_label.config(text="— no guard active —", fg=self.DIM)
                self.detail_label.config(text="")
            else:
                exe, name, related = app.selected
                blocked = app.is_blocked(exe)
                state = "■ BLOCKED" if blocked else "□ ACTIVE"
                self.status_label.config(
                    text=state, fg=self.RED if blocked else self.ACCENT)
                hint = f"{app.hotkey.upper()} toggles · {name} ({len(related)})"
                self.detail_label.config(text=hint[:50], fg=self.FG)
        except Exception:
            pass
        self.root.after(self.REFRESH_MS, self._tick)


# ── process scan ────────────────────────────────────────────────────
def _shared_dirs() -> Set[str]:
    """Directories that hold unrelated binaries from many vendors.

    Sibling matching in find_related() is skipped for these — otherwise
    guarding one process in C:\\Windows\\System32 would block the whole OS.
    """
    root = os.environ.get("SystemRoot", r"C:\Windows")
    candidates = [root, os.path.join(root, "System32"),
                  os.path.join(root, "SysWOW64")]
    for var in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432",
                "ProgramData", "LOCALAPPDATA", "APPDATA", "TEMP"):
        value = os.environ.get(var)
        if value:
            candidates.append(value)
    return {os.path.normcase(c).rstrip("\\") for c in candidates}


SHARED_DIRS = _shared_dirs()


def _ppid_of(proc: Optional["psutil.Process"]) -> Optional[int]:
    """Parent pid of a scanned process, preferring the value cached by
    process_iter() so a dead process does not raise mid-scan."""
    if proc is None:
        return None
    info = getattr(proc, "info", None)
    if isinstance(info, dict) and info.get("ppid") is not None:
        return info["ppid"]
    try:
        return proc.ppid()
    except (psutil.Error, OSError):
        return None


def _exe_of(proc: "psutil.Process") -> Optional[str]:
    """Normcased executable path of a process, or None if it is gone."""
    try:
        exe = proc.exe()
    except (psutil.Error, OSError):
        return None
    return os.path.normcase(exe) if exe else None


def scan_processes() -> List[Item]:
    """Sorted list of (exe_path, name, psutil handle) for unique executables.

    The handle lets callers walk the process tree to find related
    siblings / children / services.
    """
    seen: Dict[str, Item] = {}
    for p in psutil.process_iter(["name", "exe", "pid", "ppid"]):
        try:
            exe = p.info["exe"]
            if not exe or exe in seen:
                continue
            name = p.info["name"] or os.path.basename(exe)
            if os.path.isfile(exe):
                seen[exe] = (exe, name, p)
        except (psutil.Error, OSError, ValueError):
            continue
    # Sort by display name, then path — psutil.Process is not orderable, so
    # the handle must never end up in the sort key.
    return sorted(seen.values(), key=lambda it: (it[1].lower(), it[0].lower()))


def find_related(exe_path: str, proc: Optional["psutil.Process"],
                 all_items: Iterable[Item]) -> Set[str]:
    """Normcased exe paths belonging to the same program group as `exe_path`.

    Three heuristics, unioned:

      1. The parent of `proc` and every descendant of that parent — this is
         what catches a browser's renderer children or a launcher's helpers.
      2. Scanned processes living under the same install directory (sibling
         .exe files shipped side by side, plus anything in bin/ or similar
         subfolders). Skipped for shared locations like System32, where
         "same directory" says nothing about who ships the binary.
      3. Scanned processes sharing `proc`'s parent pid, i.e. spawned by the
         same launcher but not reachable through the walk in (1).

    `exe_path` itself is always included, so the result is never empty.
    """
    related = {os.path.normcase(exe_path)}

    # 1. parent + everything under it
    if proc is not None:
        try:
            parent = proc.parent()
        except (psutil.Error, OSError):
            parent = None
        if parent is not None:
            for candidate in [parent] + _children_of(parent):
                exe = _exe_of(candidate)
                if exe:
                    related.add(exe)

    # 2. same install directory
    directory = os.path.normcase(os.path.dirname(exe_path)).rstrip("\\")
    sweep_dir = bool(directory) and directory not in SHARED_DIRS

    # 3. same immediate parent
    ppid = _ppid_of(proc)

    for ex, _name, pr in all_items:
        ex_norm = os.path.normcase(ex)
        if ex_norm in related:
            continue
        if sweep_dir and ex_norm.startswith(directory + "\\"):
            related.add(ex_norm)
        elif ppid is not None and _ppid_of(pr) == ppid:
            related.add(ex_norm)
    return related


def _children_of(proc: "psutil.Process") -> List["psutil.Process"]:
    try:
        return proc.children(recursive=True)
    except (psutil.Error, OSError):
        return []


# ── terminal io ─────────────────────────────────────────────────────
def cls() -> None:
    # ANSI is handled by the Windows 10+ console; avoids spawning cmd.exe
    # ~25x/second the way os.system("cls") did.
    sys.stdout.write("\x1b[2J\x1b[H")


def _enable_ansi() -> None:
    try:
        h = ctypes.windll.kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if ctypes.windll.kernel32.GetConsoleMode(h, ctypes.byref(mode)):
            ctypes.windll.kernel32.SetConsoleMode(h, mode.value | 0x0004)
    except Exception:
        pass


_KEYMAP = {72: "up", 80: "down", 75: "left", 77: "right",
           73: "pgup", 81: "pgdn", 71: "home", 79: "end"}


def read_key() -> Optional[str]:
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


def _ask(question: str) -> str:
    """Full-screen yes/no style prompt. Returns the lowercased answer."""
    cls()
    sys.stdout.flush()
    try:
        return input(question).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return ""


# ── app ─────────────────────────────────────────────────────────────
class App:
    """Console UI + hotkey loop."""

    FLASH_SECS = 4.0

    def __init__(self, cfg: Dict[str, object]):
        self.cfg = cfg
        self.hotkey: str = cfg["hotkey"]
        self.hook = None
        self.lock = threading.Lock()      # guards blocked_set + netsh writes
        self.blocked_set: Set[str] = set()
        self.items: List[Item] = []
        self.sel = 0
        self.top = 0
        self.selected: Optional[Tuple[str, str, Set[str]]] = None
        self.mode = "select"              # "select" | "guard"
        self.flash_msg = ""
        self.flash_at = 0.0
        self.dirty = True
        self.running = True
        self.overlay = Overlay(self)

    def flash(self, msg: str) -> None:
        self.flash_msg = msg
        self.flash_at = time.monotonic()
        self.dirty = True

    # ── firewall state ───────────────────────────────────────────────
    def refresh_blocked(self) -> bool:
        """Re-read the ProcSnitch rules from the firewall."""
        found, err = list_blocked()
        if found is None:
            detail = err.splitlines()[0] if err else "?"
            self.flash(f"Could not read firewall rules: {detail}")
            return False
        with self.lock:
            self.blocked_set = found
        return True

    def is_blocked(self, exe: str) -> bool:
        return os.path.normcase(exe) in self.blocked_set

    def _delete_rules(self, exe_paths: Iterable[str]) -> int:
        """Drop the rule pair for each path. Caller must hold self.lock."""
        removed = 0
        for exe in exe_paths:
            ok, _out = set_block(exe, False)
            if ok:
                self.blocked_set.discard(os.path.normcase(exe))
                removed += 1
        return removed

    def rescan(self) -> None:
        self.items = scan_processes()
        self.refresh_blocked()
        self.sel = min(self.sel, max(0, len(self.items) - 1))
        self.flash(f"Rescanned — {len(self.items)} programs")

    def toggle(self) -> None:
        """Global hotkey callback — runs in the keyboard library's thread."""
        sel = self.selected
        if sel is None:
            return
        exe, name, related = sel
        with self.lock:
            turn_on = os.path.normcase(exe) not in self.blocked_set
            failed = 0
            for path in sorted(related):
                ok, _out = set_block(path, turn_on)
                if not ok:
                    failed += 1
                    continue
                if turn_on:
                    self.blocked_set.add(os.path.normcase(path))
                else:
                    self.blocked_set.discard(os.path.normcase(path))
        verb = f"{GLYPH['on']} BLOCKED" if turn_on else f"{GLYPH['off']} unblocked"
        msg = f"{verb}: {name} ({len(related)} processes)"
        if failed:
            msg += f" — {failed} failed"
        self.flash(msg)

    # ── hotkey ───────────────────────────────────────────────────────
    def install_hotkey(self, hk: str) -> None:
        """Bind hk. Raises on an invalid combination, leaving the old one live."""
        new = keyboard.add_hotkey(hk, self.toggle)
        self.remove_hotkey()
        self.hook = new

    def remove_hotkey(self) -> None:
        if self.hook is not None:
            try:
                keyboard.remove_hotkey(self.hook)
            except (KeyError, ValueError):
                pass
            self.hook = None

    def prompt_hotkey(self) -> None:
        new = _ask(f"  Hotkey now: {self.hotkey}\n"
                   f"  New (e.g. ctrl+shift+x), blank to keep: ")
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

    # ── drawing ──────────────────────────────────────────────────────
    def _viewport(self, rows: int) -> Tuple[int, int]:
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

    def draw(self) -> None:
        cols, lines = shutil.get_terminal_size((80, 25))
        rows = max(3, lines - 7)
        start, end = self._viewport(rows)
        buf = [f"  Proc-Snitch   hotkey: [{self.hotkey}]   "
               f"[h]hotkey [r]rescan [c]clear-all [q]quit", ""]
        for i in range(start, end):
            exe, name, _proc = self.items[i]
            cur = GLYPH["cur"] if (self.mode == "select" and i == self.sel) else " "
            st = " " + (GLYPH["on"] if self.is_blocked(exe) else " ")
            buf.append(f" {cur}{st} [{i + 1:>3}] {name}"[:cols - 1])
        if end < len(self.items) or start > 0:
            buf.append(f"      ... {start + 1}-{end} of {len(self.items)}")
        if not self.items:
            buf.append("      (no processes — press [r] to rescan)")
        if self.flash_msg:
            bar = GLYPH["bar"] * 2
            buf.append(f"\n  {bar} {self.flash_msg} {bar}"[:cols - 1])
        if self.mode == "guard":
            name = self.selected[1] if self.selected else "?"
            buf.append(f"\n  Guarding: {name} — press [{self.hotkey}] to toggle  [b]ack")
        else:
            buf.append(f"\n  {GLYPH['nav']} navigate   Enter select")
        cls()
        sys.stdout.write("\n".join(buf) + "\n")
        sys.stdout.flush()
        self.dirty = False

    # ── actions ──────────────────────────────────────────────────────
    def clear_all_blocks(self) -> None:
        """Remove every ProcSnitch block rule. Bound to 'c' in select mode.

        Works off the firewall's own rule list, so rules whose program is no
        longer running are cleared too.
        """
        if not self.refresh_blocked():
            return
        with self.lock:
            targets = sorted(self.blocked_set)
        if not targets:
            self.flash("No active block rules to clear")
            return
        answer = _ask(f"  Remove ALL {len(targets)} ProcSnitch block rule(s)? [y/N]: ")
        self.dirty = True
        if answer != "y":
            self.flash("Cancelled — rules kept")
            return
        with self.lock:
            removed = self._delete_rules(targets)
        self.flash(f"Cleared {removed} of {len(targets)} block rule(s)")

    def guard_selected(self) -> None:
        """Guard the highlighted program together with its related processes."""
        exe, name, proc = self.items[self.sel]
        related = find_related(exe, proc, self.items)
        # Show anything the tree walk turned up that the top-level scan missed,
        # so its block state is visible in the list too.
        known = {os.path.normcase(e) for e, _n, _p in self.items}
        for path in sorted(related - known):
            self.items.append((path, os.path.basename(path), None))
        self.selected = (exe, name, related)
        self.mode = "guard"
        self.flash(f"Guarding {name} ({len(related)} processes)")

    # ── input ────────────────────────────────────────────────────────
    def handle(self, k: str) -> None:
        self.dirty = True
        if k == "q":
            self.running = False
        elif k == "r":
            self.rescan()
        elif k == "h":
            self.prompt_hotkey()
        elif k == "c" and self.mode == "select":
            self.clear_all_blocks()
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
                self.guard_selected()
        elif self.mode == "guard":
            if k in ("b", "esc"):
                self.mode = "select"

    # ── shutdown ─────────────────────────────────────────────────────
    def cleanup_prompt(self) -> None:
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
        with self.lock:
            removed = self._delete_rules(active)
        leftover, _err = list_blocked()
        if leftover is None:
            print(f"  Removed {removed} rule(s); could not re-check the firewall.")
        elif leftover:
            print(f"  Removed {removed}; {len(leftover)} rule(s) remain.")
            print("  Clear manually: netsh advfirewall firewall delete rule "
                  'name=all program="<path>"')
        else:
            print(f"  Removed {removed} rule(s).")

    # ── loop ─────────────────────────────────────────────────────────
    def run(self) -> None:
        try:
            self.install_hotkey(self.hotkey)
        except Exception as e:
            self.flash(f"Could not bind hotkey [{self.hotkey}]: {e}")
        self.overlay.start()
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
            self.overlay.stop()
            self.remove_hotkey()
            try:
                self.cleanup_prompt()
            except Exception:
                pass


# ── main ────────────────────────────────────────────────────────────
def preflight() -> List[str]:
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


def main() -> int:
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
