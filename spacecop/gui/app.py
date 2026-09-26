"""SpaceCopVPN graphical client — dark, rounded, card-based UI (Tkinter only).

Two connection modes:

* **SOCKS5-прокси** — no privileges; apps are pointed at 127.0.0.1:<port>.
* **Вся система** (Linux) — a TUN interface takes *all* traffic; the GUI runs
  ``spacecop vpn`` as root through ``pkexec`` (one password prompt), streams
  its log here, receives the node table as JSON lines, and stops it by
  writing ``stop`` to its stdin.

ttk cannot draw rounded corners, so cards, buttons and entries are drawn on
Canvas widgets (``RoundedCard``, ``RoundedButton``, ``RoundedEntry``).  All
network work runs on background threads; UI updates go through a queue polled
with ``after()``.
"""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from typing import Callable, Dict, List, Optional

from .. import __version__
from ..client import VPNClient
from ..protocol.uri import URIError, parse_uri
from ..tun.socks_proxy import Socks5Proxy

APP_TITLE = "SpaceCopVPN"


def _not_root() -> bool:
    """True when we lack root; on platforms without geteuid (Windows) always True."""
    return getattr(os, "geteuid", lambda: 1)() != 0
CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".config", "spacecop")
CONFIG_PATH = os.path.join(CONFIG_DIR, "profiles.json")

DEFAULT_PROFILE = {
    "nodes": [],
    "mode": "socks",            # "socks" | "system"
    "listen_host": "127.0.0.1",
    "listen_port": 1080,
    "test_target": "example.com:80",
    "discover": True,
    "dns": "1.1.1.1:53",
}

# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------
C = {
    "bg": "#0d0f1a",
    "side": "#0a0c15",
    "card": "#151829",
    "card2": "#1b1f36",
    "line": "#262b48",
    "text": "#e8e9f5",
    "muted": "#8b90b5",
    "accent": "#7c5cff",
    "accent2": "#9b82ff",
    "ok": "#3ddc97",
    "warn": "#ffb347",
    "err": "#ff5c7a",
    "danger_bg": "#3a2030",
}
FONT = ("Segoe UI", 10) if sys.platform.startswith("win") else ("DejaVu Sans", 10)
FONT_B = (FONT[0], 10, "bold")
FONT_H = (FONT[0], 15, "bold")
FONT_MONO = ("DejaVu Sans Mono", 9)
RADIUS = 14


def _round_rect(canvas: tk.Canvas, x1, y1, x2, y2, r, **kw):
    """Draw a rounded rectangle as a smoothed polygon."""
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
           x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return canvas.create_polygon(pts, smooth=True, splinesteps=24, **kw)


class RoundedCard(tk.Canvas):
    """A rounded panel; put children into ``.body`` (a Frame)."""

    def __init__(self, parent, fill=C["card"], outline=C["line"], radius=RADIUS, pad=16, **kw):
        super().__init__(parent, bg=parent.cget("bg"), highlightthickness=0, bd=0, **kw)
        self._fill, self._outline, self._r, self._pad = fill, outline, radius, pad
        self.body = tk.Frame(self, bg=fill)
        self._shape = None
        self._win = self.create_window(pad, pad, window=self.body, anchor="nw")
        self.bind("<Configure>", self._redraw)
        self.body.bind("<Configure>", self._fit)

    def _fit(self, _e=None):
        h = self.body.winfo_reqheight() + 2 * self._pad
        if int(self.cget("height")) != h:
            self.configure(height=h)
        self._redraw()

    def _redraw(self, _e=None):
        w, h = self.winfo_width(), self.winfo_height()
        if w < 4 or h < 4:
            return
        if self._shape is not None:
            self.delete(self._shape)
        self._shape = _round_rect(self, 1, 1, w - 2, h - 2, self._r, fill=self._fill,
                                  outline=self._outline, width=1)
        self.tag_lower(self._shape)
        self.itemconfigure(self._win, width=w - 2 * self._pad)


class RoundedButton(tk.Canvas):
    def __init__(self, parent, text: str, command: Callable, kind: str = "normal",
                 padx: int = 18, pady: int = 9, font=FONT_B):
        bg = parent.cget("bg")
        super().__init__(parent, bg=bg, highlightthickness=0, bd=0, cursor="hand2")
        self._command = command
        self._enabled = True
        self._kind = kind
        self._colors = {
            "normal": (C["card2"], C["line"], C["text"]),
            "accent": (C["accent"], C["accent2"], "#ffffff"),
            "danger": (C["danger_bg"], "#4a2838", C["err"]),
        }[kind]
        self._font = font
        self._padx, self._pady = padx, pady
        self._text_id = self.create_text(0, 0, text=text, font=font, fill=self._colors[2])
        bbox = self.bbox(self._text_id)
        w = bbox[2] - bbox[0] + 2 * padx
        h = bbox[3] - bbox[1] + 2 * pady
        self.configure(width=w, height=h)
        self._shape = _round_rect(self, 1, 1, w - 2, h - 2, 11, fill=self._colors[0], outline="")
        self.tag_lower(self._shape)
        self.coords(self._text_id, w / 2, h / 2)
        self.bind("<Enter>", lambda e: self._paint(hover=True))
        self.bind("<Leave>", lambda e: self._paint(hover=False))
        self.bind("<Button-1>", self._click)

    def _paint(self, hover: bool):
        if not self._enabled:
            self.itemconfigure(self._shape, fill=C["card"])
            self.itemconfigure(self._text_id, fill=C["muted"])
            return
        self.itemconfigure(self._shape, fill=self._colors[1] if hover else self._colors[0])
        self.itemconfigure(self._text_id, fill=self._colors[2])

    def _click(self, _e=None):
        if self._enabled:
            self._command()

    def set_enabled(self, enabled: bool):
        self._enabled = enabled
        self.configure(cursor="hand2" if enabled else "arrow")
        self._paint(hover=False)

    # ttk-like API used by the app
    def __setitem__(self, key, value):
        if key == "state":
            self.set_enabled(value != "disabled")


class RoundedEntry(tk.Canvas):
    """A rounded box around a flat tk.Entry; ``.entry`` is the Entry."""

    def __init__(self, parent, width: int = 16, font=FONT, mono: bool = False):
        bg = parent.cget("bg")
        super().__init__(parent, bg=bg, highlightthickness=0, bd=0)
        self.entry = tk.Entry(self, width=width, bg=C["card2"], fg=C["text"], relief="flat",
                              insertbackground=C["text"], highlightthickness=0, bd=0,
                              font=FONT_MONO if mono else font, selectbackground=C["accent"])
        self._shape = None
        self._win = self.create_window(10, 6, window=self.entry, anchor="nw")
        self.entry.bind("<Configure>", self._fit)
        self.bind("<Configure>", self._redraw)
        self.entry.bind("<FocusIn>", lambda e: self._redraw(outline=C["accent"]))
        self.entry.bind("<FocusOut>", lambda e: self._redraw())

    def _fit(self, _e=None):
        self.configure(width=self.entry.winfo_reqwidth() + 20,
                       height=self.entry.winfo_reqheight() + 12)
        self._redraw()

    def _redraw(self, _e=None, outline=None):
        w, h = self.winfo_width(), self.winfo_height()
        if w < 4 or h < 4:
            return
        if self._shape is not None:
            self.delete(self._shape)
        self._shape = _round_rect(self, 1, 1, w - 2, h - 2, 9, fill=C["card2"],
                                  outline=outline or C["line"], width=1)
        self.tag_lower(self._shape)
        self.itemconfigure(self._win, width=w - 20)

    # Text API.  NOTE: never override Canvas.delete/insert here — the canvas
    # calls self.delete(item_id) when it redraws its own shape, and a proxy to
    # the Entry would delete characters from the text instead (that bug once
    # turned "1.1.1.1:53" into "1...:3").
    def get(self) -> str:
        return self.entry.get()

    def set(self, text: str) -> None:
        self.entry.delete(0, "end")
        self.entry.insert(0, text)


def apply_theme(root: tk.Tk) -> ttk.Style:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    root.configure(bg=C["bg"])
    style.configure(".", background=C["bg"], foreground=C["text"], font=FONT,
                    fieldbackground=C["card2"], bordercolor=C["line"], troughcolor=C["card2"],
                    lightcolor=C["line"], darkcolor=C["line"])
    style.configure("TLabel", background=C["card"], foreground=C["text"])
    style.configure("Muted.TLabel", background=C["card"], foreground=C["muted"])
    style.configure("Title.TLabel", background=C["card"], foreground=C["text"], font=FONT_B)
    # Combobox: every state dark (the readonly state was rendering white).
    style.configure("TCombobox", fieldbackground=C["card2"], background=C["card2"],
                    foreground=C["text"], arrowcolor=C["text"], bordercolor=C["line"],
                    lightcolor=C["line"], darkcolor=C["line"], padding=5, arrowsize=14)
    style.map("TCombobox",
              fieldbackground=[("readonly", C["card2"]), ("disabled", C["card2"]), ("active", C["card2"])],
              foreground=[("readonly", C["text"]), ("disabled", C["muted"])],
              background=[("readonly", C["card2"]), ("active", C["line"]), ("pressed", C["line"])],
              selectbackground=[("readonly", C["card2"])],
              selectforeground=[("readonly", C["text"])],
              bordercolor=[("focus", C["accent"])])
    root.option_add("*TCombobox*Listbox.background", C["card2"])
    root.option_add("*TCombobox*Listbox.foreground", C["text"])
    root.option_add("*TCombobox*Listbox.selectBackground", C["accent"])
    root.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")
    style.configure("TCheckbutton", background=C["card"], foreground=C["text"])
    style.map("TCheckbutton", background=[("active", C["card"])],
              indicatorcolor=[("selected", C["accent"]), ("!selected", C["card2"])])
    style.configure("TRadiobutton", background=C["card"], foreground=C["text"])
    style.map("TRadiobutton", background=[("active", C["card"])],
              indicatorcolor=[("selected", C["accent"]), ("!selected", C["card2"])])
    # Treeview: dark in every state, including the heading's active/pressed
    # states that were rendering white.
    style.configure("Treeview", background=C["card2"], fieldbackground=C["card2"],
                    foreground=C["text"], rowheight=26, borderwidth=0, relief="flat",
                    bordercolor=C["line"], lightcolor=C["card2"], darkcolor=C["card2"])
    style.map("Treeview", background=[("selected", C["accent"])], foreground=[("selected", "#fff")])
    style.configure("Treeview.Heading", background=C["card"], foreground=C["muted"],
                    font=FONT_B, borderwidth=0, relief="flat")
    style.map("Treeview.Heading", background=[("active", C["card"]), ("pressed", C["card"])],
              foreground=[("active", C["text"])])
    style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])  # no white border
    style.configure("Vertical.TScrollbar", background=C["card2"], troughcolor=C["card"],
                    arrowcolor=C["muted"], borderwidth=0)
    return style


# ---------------------------------------------------------------------------
# Config persistence
# ---------------------------------------------------------------------------
def load_profiles() -> Dict[str, dict]:
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and data:
            for prof in data.values():
                for k, v in DEFAULT_PROFILE.items():
                    prof.setdefault(k, v)
            return data
    except (OSError, ValueError):
        pass
    return {"По умолчанию": dict(DEFAULT_PROFILE)}


def save_profiles(profiles: Dict[str, dict]) -> None:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(profiles, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, CONFIG_PATH)


def _fmt_bytes(n: int) -> str:
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} ТБ"


# ---------------------------------------------------------------------------
# The application
# ---------------------------------------------------------------------------
class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.minsize(940, 660)
        self.style = apply_theme(root)

        self.profiles = load_profiles()
        self.current_profile = next(iter(self.profiles))
        self.client: Optional[VPNClient] = None
        self.proxy: Optional[Socks5Proxy] = None
        self.sys_proc: Optional[subprocess.Popen] = None
        self._sys_rows: List[dict] = []
        self._events: "queue.Queue[tuple]" = queue.Queue()
        self._busy = False
        self._page = "connect"

        self._build_ui()
        self._load_profile_into_ui(self.current_profile)
        self._show_page("connect")
        self.root.after(200, self._drain_events)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ================================================================ UI build
    def _build_ui(self) -> None:
        outer = tk.Frame(self.root, bg=C["bg"])
        outer.pack(fill="both", expand=True)

        # -- sidebar ------------------------------------------------------------
        side = tk.Frame(outer, bg=C["side"], width=72)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        logo = tk.Canvas(side, width=44, height=44, bg=C["side"], highlightthickness=0)
        logo.pack(pady=(18, 22))
        logo.create_oval(4, 4, 40, 40, fill=C["accent"], outline="")
        logo.create_text(22, 22, text="SC", fill="#fff", font=(FONT[0], 12, "bold"))
        self._side_buttons: Dict[str, tk.Canvas] = {}
        for key, glyph in (("connect", "⏻"), ("nodes", "◎"), ("log", "≡")):
            c = tk.Canvas(side, width=48, height=48, bg=C["side"], highlightthickness=0, cursor="hand2")
            c.pack(pady=6)
            shape = _round_rect(c, 2, 2, 46, 46, 12, fill=C["side"], outline="")
            text = c.create_text(24, 24, text=glyph, fill=C["muted"], font=(FONT[0], 16))
            c.bind("<Button-1>", lambda e, k=key: self._show_page(k))
            c._shape, c._text = shape, text  # type: ignore[attr-defined]
            self._side_buttons[key] = c
        tk.Label(side, text=f"v{__version__}", bg=C["side"], fg=C["muted"],
                 font=(FONT[0], 8)).pack(side="bottom", pady=10)

        # -- main column --------------------------------------------------------
        main = tk.Frame(outer, bg=C["bg"])
        main.pack(side="left", fill="both", expand=True)

        header = tk.Frame(main, bg=C["bg"])
        header.pack(fill="x", padx=24, pady=(18, 8))
        tk.Label(header, text="SpaceCopVPN", bg=C["bg"], fg=C["text"], font=FONT_H).pack(side="left")
        self.chip = tk.Canvas(header, height=30, bg=C["bg"], highlightthickness=0)
        self.chip.pack(side="right")
        self._chip_shape = None
        self._chip_text = self.chip.create_text(0, 15, text="", anchor="w", font=FONT_B, fill=C["err"])
        self._set_chip("● отключено", C["err"])

        self.pages: Dict[str, tk.Frame] = {}
        for key in ("connect", "nodes", "log"):
            self.pages[key] = tk.Frame(main, bg=C["bg"])
        self._build_connect_page(self.pages["connect"])
        self._build_nodes_page(self.pages["nodes"])
        self._build_log_page(self.pages["log"])

    def _set_chip(self, text: str, color: str) -> None:
        self.chip.itemconfigure(self._chip_text, text=text, fill=color)
        bbox = self.chip.bbox(self._chip_text)
        w = (bbox[2] - bbox[0]) + 28
        self.chip.configure(width=w)
        self.chip.coords(self._chip_text, 14, 15)
        if self._chip_shape is not None:
            self.chip.delete(self._chip_shape)
        self._chip_shape = _round_rect(self.chip, 1, 1, w - 2, 28, 12, fill=C["card2"], outline="")
        self.chip.tag_lower(self._chip_shape)

    def _card(self, parent, title: str, subtitle: str = "") -> tk.Frame:
        card = RoundedCard(parent)
        card.pack(fill="x", padx=24, pady=8)
        body = card.body
        tk.Label(body, text=title, bg=C["card"], fg=C["text"], font=FONT_B).pack(anchor="w")
        if subtitle:
            tk.Label(body, text=subtitle, bg=C["card"], fg=C["muted"], font=FONT, wraplength=780,
                     justify="left").pack(anchor="w", pady=(2, 8))
        return body

    def _row(self, parent) -> tk.Frame:
        row = tk.Frame(parent, bg=C["card"])
        row.pack(fill="x", pady=(8, 0))
        return row

    def _label(self, parent, text: str, muted: bool = False) -> tk.Label:
        return tk.Label(parent, text=text, bg=C["card"], fg=C["muted"] if muted else C["text"], font=FONT)

    # -- page: connect ------------------------------------------------------------
    def _build_connect_page(self, page: tk.Frame) -> None:
        body = self._card(page, "Подключение")
        row = self._row(body)
        self._label(row, "Профиль").pack(side="left", padx=(0, 8))
        self.cb_profile = ttk.Combobox(row, state="readonly", width=24, values=list(self.profiles))
        self.cb_profile.pack(side="left")
        self.cb_profile.bind("<<ComboboxSelected>>", self._on_profile_selected)
        RoundedButton(row, "Новый", self._new_profile, padx=14, pady=7).pack(side="left", padx=(10, 0))
        RoundedButton(row, "Удалить", self._delete_profile, padx=14, pady=7).pack(side="left", padx=(6, 0))
        RoundedButton(row, "Сохранить", self._save_current, padx=14, pady=7).pack(side="left", padx=(6, 0))

        row2 = self._row(body)
        row2.configure(pady=0)
        row2.pack_configure(pady=(14, 0))
        self.btn_connect = RoundedButton(row2, "Подключиться", self._connect, kind="accent")
        self.btn_connect.pack(side="left")
        self.btn_disconnect = RoundedButton(row2, "Отключиться", self._disconnect, kind="danger")
        self.btn_disconnect.pack(side="left", padx=(8, 0))
        self.btn_disconnect.set_enabled(False)
        self.btn_test = RoundedButton(row2, "Тест", self._test)
        self.btn_test.pack(side="left", padx=(8, 0))
        self.btn_test.set_enabled(False)
        self.lbl_status = self._label(row2, "", muted=True)
        self.lbl_status.pack(side="left", padx=(16, 0))

        body = self._card(page, "Режим",
                          "«Вся система» заворачивает весь трафик компьютера в VPN через "
                          "виртуальный интерфейс (Linux, спросит пароль администратора). "
                          "«SOCKS5» не требует прав: прокси указывается в браузере или системе.")
        self.var_mode = tk.StringVar(value="socks")
        mrow = self._row(body)
        ttk.Radiobutton(mrow, text="SOCKS5-прокси", variable=self.var_mode, value="socks",
                        command=self._on_mode_change).pack(side="left")
        rb_sys = ttk.Radiobutton(mrow, text="Вся система (TUN)", variable=self.var_mode,
                                 value="system", command=self._on_mode_change)
        rb_sys.pack(side="left", padx=(18, 0))
        if not sys.platform.startswith("linux"):
            rb_sys.state(["disabled"])
        srow = self._row(body)
        self._label(srow, "SOCKS адрес", muted=True).pack(side="left")
        self.e_host = RoundedEntry(srow, width=13)
        self.e_host.pack(side="left", padx=(8, 14))
        self._label(srow, "порт", muted=True).pack(side="left")
        self.e_port = RoundedEntry(srow, width=6)
        self.e_port.pack(side="left", padx=(8, 14))
        self._label(srow, "DNS (вся система)", muted=True).pack(side="left")
        self.e_dns = RoundedEntry(srow, width=13)
        self.e_dns.pack(side="left", padx=(8, 14))
        self._label(srow, "тест", muted=True).pack(side="left")
        self.e_test = RoundedEntry(srow, width=17)
        self.e_test.pack(side="left", padx=(8, 0))

        body = self._card(page, "Состояние узлов · конкуренция за трафик",
                          "Каждый сайт закреплён за одним узлом; быстрые и надёжные узлы получают "
                          "больше сайтов, трафика и очков. При сбое клиент переключается на другой узел.")
        cols = ("node", "addr", "reqs", "fail", "lat", "health", "bytes", "share")
        self.tree = ttk.Treeview(body, columns=cols, show="headings", height=6)
        for col, title, width in (("node", "Узел", 140), ("addr", "Адрес", 170),
                                  ("reqs", "Запросов", 80), ("fail", "Ошибок", 70),
                                  ("lat", "Задержка, мс", 100), ("health", "Здоровье", 80),
                                  ("bytes", "Трафик", 90), ("share", "Доля", 70)):
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, anchor="center")
        self.tree.pack(fill="x", pady=(8, 0))
        self.lbl_leader = self._label(body, "", muted=True)
        self.lbl_leader.pack(anchor="w", pady=(8, 0))

    # -- page: nodes -----------------------------------------------------------------
    def _build_nodes_page(self, page: tk.Frame) -> None:
        body = self._card(page, "Узлы",
                          "Вставьте строку spacecop://…, которую печатает узел при запуске "
                          "(или скрипт установки сервера). Одного узла достаточно: при "
                          "автообнаружении остальные подтянутся сами.")
        lb_card = RoundedCard(body, fill=C["card2"], outline=C["line"], radius=10, pad=6)
        lb_card.pack(fill="x", pady=(6, 8))
        self.lb_nodes = tk.Listbox(lb_card.body, height=7, activestyle="none", bg=C["card2"],
                                   fg=C["text"], selectbackground=C["accent"], selectforeground="#fff",
                                   highlightthickness=0, bd=0, font=FONT_MONO)
        self.lb_nodes.pack(fill="x")
        row = self._row(body)
        self.e_uri = RoundedEntry(row, width=60, mono=True)
        self.e_uri.pack(side="left", fill="x", expand=True)
        RoundedButton(row, "Добавить", self._add_node, padx=14, pady=7).pack(side="left", padx=(8, 0))
        RoundedButton(row, "Удалить", self._remove_node, padx=14, pady=7).pack(side="left", padx=(6, 0))
        row2 = self._row(body)
        self.btn_check = RoundedButton(row2, "Проверить узел", self._check_node)
        self.btn_check.pack(side="left")
        self.btn_find = RoundedButton(row2, "Найти узлы", self._find_nodes, kind="accent")
        self.btn_find.pack(side="left", padx=(8, 0))
        self.var_discover = tk.BooleanVar(value=True)
        ttk.Checkbutton(row2, text="Автообнаружение при подключении",
                        variable=self.var_discover).pack(side="left", padx=(18, 0))
        tk.Label(body, text="«Найти узлы» спрашивает у известных узлов, кого они знают, и "
                            "добавляет найденные в список.", bg=C["card"], fg=C["muted"],
                 font=FONT, wraplength=780, justify="left").pack(anchor="w", pady=(8, 0))

    # -- page: log -----------------------------------------------------------------------
    def _build_log_page(self, page: tk.Frame) -> None:
        body = self._card(page, "Журнал")
        log_card = RoundedCard(body, fill=C["card2"], outline=C["line"], radius=10, pad=8)
        log_card.pack(fill="x", pady=(6, 0))
        self.txt_log = tk.Text(log_card.body, height=24, state="disabled", wrap="word", bg=C["card2"],
                               fg=C["text"], insertbackground=C["text"], bd=0,
                               highlightthickness=0, font=FONT_MONO, padx=6, pady=4)
        self.txt_log.pack(fill="both", expand=True)
        self.txt_log.tag_configure("ok", foreground=C["ok"])
        self.txt_log.tag_configure("err", foreground=C["err"])
        self.txt_log.tag_configure("warn", foreground=C["warn"])
        RoundedButton(body, "Очистить", self._clear_log, padx=14, pady=7).pack(anchor="e", pady=(8, 0))

    def _show_page(self, key: str) -> None:
        for frame in self.pages.values():
            frame.pack_forget()
        self.pages[key].pack(fill="both", expand=True)
        self._page = key
        for k, c in self._side_buttons.items():
            active = k == key
            c.itemconfigure(c._shape, fill=C["card"] if active else C["side"])  # type: ignore[attr-defined]
            c.itemconfigure(c._text, fill=C["accent"] if active else C["muted"])  # type: ignore[attr-defined]

    # ================================================================ profiles
    def _load_profile_into_ui(self, name: str) -> None:
        prof = self.profiles.get(name, dict(DEFAULT_PROFILE))
        self.current_profile = name
        self.cb_profile.set(name)
        self.lb_nodes.delete(0, "end")
        for uri in prof.get("nodes", []):
            self.lb_nodes.insert("end", uri)
        for entry, key, default in ((self.e_host, "listen_host", "127.0.0.1"),
                                    (self.e_port, "listen_port", 1080),
                                    (self.e_test, "test_target", "example.com:80"),
                                    (self.e_dns, "dns", "1.1.1.1:53")):
            entry.set(str(prof.get(key, default)))
        self.var_discover.set(bool(prof.get("discover", True)))
        self.var_mode.set(prof.get("mode", "socks") if sys.platform.startswith("linux") else "socks")

    def _read_ui_into_profile(self) -> dict:
        try:
            port = int(self.e_port.get().strip())
        except ValueError:
            port = 1080
        return {
            "nodes": list(self.lb_nodes.get(0, "end")),
            "mode": self.var_mode.get(),
            "listen_host": self.e_host.get().strip() or "127.0.0.1",
            "listen_port": port,
            "test_target": self.e_test.get().strip() or "example.com:80",
            "discover": bool(self.var_discover.get()),
            "dns": self.e_dns.get().strip() or "1.1.1.1:53",
        }

    def _on_profile_selected(self, _event=None) -> None:
        self._load_profile_into_ui(self.cb_profile.get())

    def _on_mode_change(self) -> None:
        if self.var_mode.get() == "system":
            self._log("Режим «Вся система»: при подключении появится запрос пароля администратора.", "warn")

    def _new_profile(self) -> None:
        name = simpledialog.askstring("Новый профиль", "Название профиля:", parent=self.root)
        if not name:
            return
        name = name.strip()
        if name in self.profiles:
            messagebox.showwarning(APP_TITLE, "Профиль с таким названием уже есть.")
            return
        self.profiles[name] = dict(DEFAULT_PROFILE)
        self.cb_profile["values"] = list(self.profiles)
        self._load_profile_into_ui(name)
        save_profiles(self.profiles)
        self._log(f"Создан профиль «{name}».")

    def _delete_profile(self) -> None:
        if len(self.profiles) <= 1:
            messagebox.showinfo(APP_TITLE, "Нельзя удалить последний профиль.")
            return
        name = self.current_profile
        if not messagebox.askyesno(APP_TITLE, f"Удалить профиль «{name}»?"):
            return
        del self.profiles[name]
        self.cb_profile["values"] = list(self.profiles)
        self._load_profile_into_ui(next(iter(self.profiles)))
        save_profiles(self.profiles)

    def _save_current(self) -> None:
        self.profiles[self.current_profile] = self._read_ui_into_profile()
        save_profiles(self.profiles)
        self._log(f"Профиль «{self.current_profile}» сохранён.", "ok")

    # ================================================================ nodes
    def _add_node(self) -> None:
        text = self.e_uri.get().strip()
        if not text:
            return
        try:
            parse_uri(text)
        except URIError as exc:
            messagebox.showerror(APP_TITLE, f"Неверная строка подключения:\n{exc}")
            return
        if text in self.lb_nodes.get(0, "end"):
            messagebox.showinfo(APP_TITLE, "Этот узел уже добавлен.")
            return
        self.lb_nodes.insert("end", text)
        self.e_uri.set("")
        self._log("Узел добавлен. Не забудьте «Сохранить».")

    def _remove_node(self) -> None:
        sel = self.lb_nodes.curselection()
        if sel:
            self.lb_nodes.delete(sel[0])

    def _node_uris(self) -> List[str]:
        return list(self.lb_nodes.get(0, "end"))

    def _check_node(self) -> None:
        if self._busy:
            return
        text = self.e_uri.get().strip()
        if not text:
            sel = self.lb_nodes.curselection()
            if sel:
                text = self.lb_nodes.get(sel[0])
        if not text:
            messagebox.showinfo(APP_TITLE, "Вставьте строку подключения или выберите узел в списке.")
            return
        try:
            target = parse_uri(text)
        except URIError as exc:
            messagebox.showerror(APP_TITLE, f"Неверная строка подключения:\n{exc}")
            return
        self._set_busy(True, "проверка узла…")
        threading.Thread(target=self._check_node_worker, args=(target,), daemon=True).start()

    def _check_node_worker(self, target) -> None:
        client = VPNClient(discovery_enabled=False)
        client.start()
        try:
            rtt, version = client.probe(target.address, timeout=4.0)
            if rtt is None:
                self._post("check_done", (False,
                    f"{target.host}:{target.port}: узел НЕ отвечает по UDP. На сервере: "
                    f"systemctl status spacecop-node; ss -ulnp | grep {target.port}; "
                    f"открыт ли UDP/{target.port} у провайдера (security group)."))
                return
            if not version:
                self._post("check_done", (False,
                    f"{target.host}:{target.port}: отвечает (PONG {rtt * 1000:.0f} мс), но версия "
                    f"УСТАРЕЛА (нет потоков). Обновите сервер: sudo /opt/spacecop/deploy/update_server.sh"))
                return
            try:
                conn = client.connect(target.x_public, target.address,
                                      expected_node_ed=target.ed_public, timeout=6.0)
                self._post("check_done", (True,
                    f"{target.host}:{target.port}: PONG {rtt * 1000:.0f} мс, версия {version}, "
                    f"рукопожатие OK, узел {conn.node_id_hex()}."))
            except Exception as exc:
                self._post("check_done", (False,
                    f"{target.host}:{target.port}: достижим (PONG {rtt * 1000:.0f} мс), но "
                    f"рукопожатие отклонено: {exc}. Проверьте ключи и часы."))
        finally:
            client.stop()

    def _find_nodes(self) -> None:
        if self._busy:
            return
        uris = self._node_uris()
        if not uris and self.client is None:
            messagebox.showinfo(APP_TITLE, "Сначала добавьте хотя бы один узел.")
            return
        self._set_busy(True, "поиск узлов…")
        threading.Thread(target=self._find_nodes_worker, args=(uris,), daemon=True).start()

    def _find_nodes_worker(self, uris: List[str]) -> None:
        import socket as _socket
        from ..protocol import constants as c, framing
        from ..protocol.messages import PeerList, PeerRequest
        from ..protocol.uri import build_uri

        found: Dict[bytes, str] = {}
        known = set(uris)
        targets = []
        for text in uris:
            try:
                t = parse_uri(text)
                targets.append((t.host, t.port))
            except URIError:
                pass
        if self.client is not None:
            for conn in self.client.connections():
                targets.append(conn.addr)
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.settimeout(0.5)
        req = PeerRequest(max_peers=64).encode()
        for addr in targets:
            try:
                sock.sendto(req, addr)
            except OSError:
                pass
        deadline = time.monotonic() + 4.0
        while time.monotonic() < deadline:
            try:
                data, _ = sock.recvfrom(65535)
            except _socket.timeout:
                continue
            except OSError:
                break
            try:
                msg_type, body = framing.decode_frame(data)
                if msg_type != c.MSG_PEER_LIST:
                    continue
                for p in PeerList.decode(body).peers:
                    uri = build_uri(p.host, p.port, p.x_public, p.ed_public)
                    if uri not in known:
                        found[p.ed_public] = uri
            except Exception:
                continue
        sock.close()
        if self.client is not None:
            for conn in self.client.connections():
                if conn.x_public and conn.node_ed_public:
                    uri = conn.uri()
                    if uri not in known:
                        found[conn.node_ed_public] = uri
        self._post("find_done", list(found.values()))

    # ================================================================ connect
    def _connect(self) -> None:
        if self._busy or self.client is not None or self.sys_proc is not None:
            return
        prof = self._read_ui_into_profile()
        if not prof["nodes"]:
            messagebox.showwarning(APP_TITLE, "Добавьте хотя бы один узел (страница «Узлы»).")
            self._show_page("nodes")
            return
        self.profiles[self.current_profile] = prof
        save_profiles(self.profiles)
        self._set_busy(True, "подключение…")
        if prof["mode"] == "system":
            threading.Thread(target=self._connect_system_worker, args=(prof,), daemon=True).start()
        else:
            threading.Thread(target=self._connect_socks_worker, args=(prof,), daemon=True).start()

    def _connect_socks_worker(self, prof: dict) -> None:
        client = VPNClient(discovery_enabled=bool(prof.get("discover", True)),
                           on_event=lambda text: self._post("log", text))
        client.start()
        ok = 0
        for text in prof["nodes"]:
            try:
                target = parse_uri(text)
                client.connect(target.x_public, target.address,
                               expected_node_ed=target.ed_public, timeout=6.0)
                ok += 1
                _rtt, version = client.probe(target.address, timeout=3.0)
                if version:
                    self._post("log", f"Подключено к узлу {target.host}:{target.port} (v{version}).")
                else:
                    self._post("logw", f"Узел {target.host}:{target.port} УСТАРЕЛ (нет потоков) — "
                                       f"обновите сервер: sudo /opt/spacecop/deploy/update_server.sh")
            except Exception as exc:
                self._post("loge", f"Не удалось подключиться к {text[:48]}…: {exc}")
        if ok == 0:
            client.stop()
            self._post("connect_failed", "ни один узел не ответил")
            return
        try:
            proxy = Socks5Proxy(client, listen_host=prof["listen_host"], listen_port=prof["listen_port"])
            proxy.start()
        except OSError as exc:
            client.stop()
            self._post("connect_failed", f"не удалось открыть SOCKS-порт: {exc}")
            return
        self._post("connected_socks", (client, proxy, ok))

    def _connect_system_worker(self, prof: dict) -> None:
        if shutil.which("pkexec") is None and _not_root():
            self._post("connect_failed", "для режима «Вся система» нужен pkexec (polkit) или запуск от root")
            return
        cmd = [sys.executable, "-m", "spacecop.cli", "vpn", "--dns", prof.get("dns", "1.1.1.1:53"),
               "--status-interval", "3"]
        if not prof.get("discover", True):
            cmd.append("--no-discover")
        for uri in prof["nodes"]:
            cmd += ["--uri", uri]
        if _not_root():
            pypath = os.pathsep.join([p for p in sys.path if p and ("site-packages" in p or "dist-packages" in p)]
                                     + [os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))])
            cmd = ["pkexec", "env", f"PYTHONPATH={pypath}"] + cmd
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, bufsize=1)
        except OSError as exc:
            self._post("connect_failed", f"не удалось запустить помощник: {exc}")
            return
        self._post("sys_started", proc)
        ready = False
        for line in proc.stdout:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("[vpn] NODES "):
                try:
                    self._post("nodes", json.loads(line[len("[vpn] NODES "):]))
                except ValueError:
                    pass
                continue
            if "READY" in line and not ready:
                ready = True
                self._post("connected_system", None)
            elif "failed to start" in line or "STOPPED" in line:
                self._post("logw" if "STOPPED" in line else "loge", line)
            elif line.startswith("[vpn] status:"):
                continue  # numbers are in the table
            else:
                self._post("log", line)
        code = proc.wait()
        self._post("sys_exited", (code, ready))

    def _disconnect(self) -> None:
        if self.client is not None:
            proxy, client = self.proxy, self.client
            self.proxy, self.client = None, None
            threading.Thread(target=self._stop_worker, args=(proxy, client), daemon=True).start()
        if self.sys_proc is not None:
            proc = self.sys_proc
            self.sys_proc = None
            try:
                proc.stdin.write("stop\n")
                proc.stdin.flush()
            except Exception:
                pass
        self._sys_rows = []
        self._set_connected(False)
        self.tree.delete(*self.tree.get_children())
        self.lbl_leader.configure(text="")
        self._log("Отключено.")

    @staticmethod
    def _stop_worker(proxy, client) -> None:
        try:
            if proxy:
                proxy.stop()
        finally:
            if client:
                client.stop()

    def _test(self) -> None:
        if self._busy:
            return
        target = self.e_test.get().strip() or "example.com:80"
        host, _, port = target.rpartition(":")
        if not host:
            messagebox.showwarning(APP_TITLE, "Тестовый адрес должен быть в виде host:port.")
            return
        self._set_busy(True, "тест…")
        threading.Thread(target=self._test_worker, args=(host, int(port)), daemon=True).start()

    def _test_worker(self, host: str, port: int) -> None:
        req = f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
        started = time.monotonic()
        try:
            if self.client is not None:
                s = self.client.open_stream(host, port, timeout=15)
                s.send(req)
                s.send_eof()
                resp = b""
                while len(resp) < 4096:
                    chunk = s.recv(timeout=10)
                    if not chunk:
                        break
                    resp += chunk
                s.close()
            else:
                import socket as _socket
                with _socket.create_connection((host, port), timeout=15) as sk:  # through the TUN
                    sk.sendall(req)
                    sk.settimeout(10)
                    resp = sk.recv(4096)
            ms = (time.monotonic() - started) * 1000
            first = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")[:80]
            self._post("test_done", (True, f"Тест OK за {ms:.0f} мс: {first}"))
        except Exception as exc:
            self._post("test_done", (False, f"Тест не пройден: {exc}"))

    # ================================================================ events
    def _post(self, kind: str, payload=None) -> None:
        self._events.put((kind, payload))

    def _drain_events(self) -> None:
        try:
            while True:
                kind, payload = self._events.get_nowait()
                self._handle_event(kind, payload)
        except queue.Empty:
            pass
        self._refresh_table()
        self.root.after(300, self._drain_events)

    def _handle_event(self, kind: str, payload) -> None:
        if kind == "log":
            self._log(payload)
        elif kind == "logw":
            self._log(payload, "warn")
        elif kind == "loge":
            self._log(payload, "err")
        elif kind == "nodes":
            self._sys_rows = payload
        elif kind == "connected_socks":
            self.client, self.proxy, ok = payload
            host, port = self.proxy.address
            self._set_busy(False)
            self._set_connected(True, f"SOCKS5 {host}:{port} · узлов: {ok}")
            self._log(f"SOCKS5-прокси запущен на {host}:{port}. Укажите его в браузере/системе.", "ok")
        elif kind == "sys_started":
            self.sys_proc = payload
        elif kind == "connected_system":
            self._set_busy(False)
            self._set_connected(True, "вся система · TUN spacecop0")
            self._log("Весь трафик компьютера идёт через VPN.", "ok")
        elif kind == "sys_exited":
            code, ready = payload
            self.sys_proc = None
            self._sys_rows = []
            self._set_busy(False)
            self._set_connected(False)
            if not ready:
                self._log(f"Помощник завершился с кодом {code}. Отменён ввод пароля, или установлен "
                          f"старый клиент.", "err")
        elif kind == "connect_failed":
            self._set_busy(False)
            self._set_connected(False)
            self._log(f"Подключение не удалось: {payload}", "err")
        elif kind == "check_done":
            ok, text = payload
            self._set_busy(False)
            self._log(("✓ " if ok else "✗ ") + text, "ok" if ok else "err")
        elif kind == "find_done":
            uris = payload
            self._set_busy(False)
            if not uris:
                self._log("Новых узлов не найдено (узлы пока никого не знают).", "warn")
            for uri in uris:
                if uri not in self._node_uris():
                    self.lb_nodes.insert("end", uri)
                    self._log(f"Найден узел: {uri[:60]}…", "ok")
            if uris:
                self._log(f"Добавлено узлов: {len(uris)}. Нажмите «Сохранить».", "ok")
        elif kind == "test_done":
            ok, text = payload
            self._set_busy(False)
            self._log(text, "ok" if ok else "err")

    def _refresh_table(self) -> None:
        rows: List[dict] = []
        if self.client is not None:
            for conn in self.client._selector.ranking():
                rows.append({
                    "id": conn.node_id_hex(), "addr": f"{conn.addr[0]}:{conn.addr[1]}",
                    "requests": conn.requests, "failures": conn.failures,
                    "latency_ms": round(conn.ewma_latency * 1000) if conn.ewma_latency else None,
                    "health": round(conn.health_score(), 1), "bytes": conn.bytes_served,
                })
        elif self.sys_proc is not None:
            rows = self._sys_rows
        else:
            return
        total = sum(r.get("bytes", 0) for r in rows) or 0
        self.tree.delete(*self.tree.get_children())
        for r in rows:
            share = (100.0 * r.get("bytes", 0) / total) if total else 0.0
            self.tree.insert("", "end", values=(
                r["id"], r["addr"], r["requests"], r["failures"],
                r["latency_ms"] if r["latency_ms"] is not None else "—",
                r["health"], _fmt_bytes(r.get("bytes", 0)), f"{share:.0f}%",
            ))
        if rows:
            leader = max(rows, key=lambda r: r.get("bytes", 0))
            self.lbl_leader.configure(
                text=f"Лидер по трафику: {leader['id']} ({_fmt_bytes(leader.get('bytes', 0))}) · "
                     f"узлов: {len(rows)} · всего передано: {_fmt_bytes(total)}")

    # ================================================================ helpers
    def _set_busy(self, busy: bool, status: str = "") -> None:
        self._busy = busy
        connected = self.client is not None or self.sys_proc is not None
        self.btn_connect.set_enabled(not (busy or connected))
        self.btn_test.set_enabled(connected and not busy)
        self.btn_check.set_enabled(not busy)
        self.btn_find.set_enabled(not busy)
        self.lbl_status.configure(text=status)

    def _set_connected(self, connected: bool, detail: str = "") -> None:
        if connected:
            self._set_chip(f"● подключено · {detail}" if detail else "● подключено", C["ok"])
            self.btn_connect.set_enabled(False)
            self.btn_disconnect.set_enabled(True)
            self.btn_test.set_enabled(True)
        else:
            self._set_chip("● отключено", C["err"])
            self.btn_connect.set_enabled(True)
            self.btn_disconnect.set_enabled(False)
            self.btn_test.set_enabled(False)
        self.lbl_status.configure(text="")

    def _log(self, text: str, tag: str = "") -> None:
        stamp = time.strftime("%H:%M:%S")
        self.txt_log.configure(state="normal")
        self.txt_log.insert("end", f"[{stamp}] {text}\n", tag or ())
        self.txt_log.see("end")
        self.txt_log.configure(state="disabled")

    def _clear_log(self) -> None:
        self.txt_log.configure(state="normal")
        self.txt_log.delete("1.0", "end")
        self.txt_log.configure(state="disabled")

    def _on_close(self) -> None:
        if self.client is not None or self.sys_proc is not None:
            self._disconnect()
        self.root.after(300, self.root.destroy)


def main() -> int:
    root = tk.Tk()
    App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
