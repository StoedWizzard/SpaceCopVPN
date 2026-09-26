"""SpaceCopVPN graphical client — dark, card-based UI (Tkinter, stdlib only).

Two connection modes:

* **SOCKS5-прокси** — no privileges; apps are pointed at 127.0.0.1:<port>.
* **Вся система** (Linux) — a TUN interface takes *all* traffic; the GUI runs
  ``spacecop vpn`` as root through ``pkexec`` (one password prompt), streams
  its log here and stops it by writing ``stop`` to its stdin.

Layout: a slim icon sidebar (Подключение / Узлы / Журнал), a header with the
big connect button and status chip, and cards for nodes, settings and the log.
All network work runs on background threads; UI updates go through a queue
polled with ``after()``.
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
from typing import Dict, List, Optional

from .. import __version__
from ..client import RelayTimeout, VPNClient
from ..protocol.uri import URIError, parse_uri
from ..tun.socks_proxy import Socks5Proxy

APP_TITLE = "SpaceCopVPN"
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
# Theme (inspired by the dark violet look of the messenger screenshot)
# ---------------------------------------------------------------------------
C = {
    "bg": "#0d0f1a",        # window background
    "side": "#0a0c15",      # sidebar
    "card": "#151829",      # cards
    "card2": "#1b1f36",     # inputs / nested surfaces
    "line": "#262b48",      # borders
    "text": "#e8e9f5",
    "muted": "#8b90b5",
    "accent": "#7c5cff",    # violet
    "accent2": "#5c8dff",
    "ok": "#3ddc97",
    "warn": "#ffb347",
    "err": "#ff5c7a",
}
FONT = ("Segoe UI", 10) if sys.platform.startswith("win") else ("DejaVu Sans", 10)
FONT_B = (FONT[0], 10, "bold")
FONT_H = (FONT[0], 15, "bold")
FONT_MONO = ("DejaVu Sans Mono", 9)


def apply_theme(root: tk.Tk) -> ttk.Style:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    root.configure(bg=C["bg"])
    style.configure(".", background=C["bg"], foreground=C["text"], font=FONT,
                    fieldbackground=C["card2"], bordercolor=C["line"], troughcolor=C["card2"])
    style.configure("Card.TFrame", background=C["card"])
    style.configure("Side.TFrame", background=C["side"])
    style.configure("Bg.TFrame", background=C["bg"])
    style.configure("TLabel", background=C["card"], foreground=C["text"])
    style.configure("Bg.TLabel", background=C["bg"], foreground=C["text"])
    style.configure("Muted.TLabel", background=C["card"], foreground=C["muted"])
    style.configure("Head.TLabel", background=C["bg"], foreground=C["text"], font=FONT_H)
    style.configure("Title.TLabel", background=C["card"], foreground=C["text"], font=FONT_B)
    style.configure("Chip.TLabel", background=C["card2"], foreground=C["muted"], padding=(10, 4))
    style.configure("TEntry", fieldbackground=C["card2"], foreground=C["text"],
                    insertcolor=C["text"], bordercolor=C["line"], lightcolor=C["line"],
                    darkcolor=C["line"], padding=6)
    style.configure("TCombobox", fieldbackground=C["card2"], foreground=C["text"],
                    background=C["card2"], arrowcolor=C["text"], bordercolor=C["line"], padding=4)
    root.option_add("*TCombobox*Listbox.background", C["card2"])
    root.option_add("*TCombobox*Listbox.foreground", C["text"])
    root.option_add("*TCombobox*Listbox.selectBackground", C["accent"])
    style.configure("TButton", background=C["card2"], foreground=C["text"], borderwidth=0,
                    focusthickness=0, padding=(14, 8))
    style.map("TButton", background=[("active", C["line"]), ("disabled", C["card"])],
              foreground=[("disabled", C["muted"])])
    style.configure("Accent.TButton", background=C["accent"], foreground="#ffffff",
                    font=FONT_B, padding=(18, 10))
    style.map("Accent.TButton", background=[("active", C["accent2"]), ("disabled", C["line"])])
    style.configure("Danger.TButton", background="#3a2030", foreground=C["err"], padding=(14, 8))
    style.map("Danger.TButton", background=[("active", "#4a2838")])
    style.configure("TCheckbutton", background=C["card"], foreground=C["text"])
    style.map("TCheckbutton", background=[("active", C["card"])],
              indicatorcolor=[("selected", C["accent"]), ("!selected", C["card2"])])
    style.configure("TRadiobutton", background=C["card"], foreground=C["text"])
    style.map("TRadiobutton", background=[("active", C["card"])],
              indicatorcolor=[("selected", C["accent"]), ("!selected", C["card2"])])
    style.configure("Treeview", background=C["card2"], fieldbackground=C["card2"],
                    foreground=C["text"], rowheight=26, borderwidth=0)
    style.configure("Treeview.Heading", background=C["card"], foreground=C["muted"],
                    font=FONT_B, borderwidth=0)
    style.map("Treeview", background=[("selected", C["accent"])])
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


# ---------------------------------------------------------------------------
# The application
# ---------------------------------------------------------------------------
class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.minsize(900, 640)
        self.style = apply_theme(root)

        self.profiles = load_profiles()
        self.current_profile = next(iter(self.profiles))
        self.client: Optional[VPNClient] = None
        self.proxy: Optional[Socks5Proxy] = None
        self.sys_proc: Optional[subprocess.Popen] = None
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
        outer = ttk.Frame(self.root, style="Bg.TFrame")
        outer.pack(fill="both", expand=True)

        # -- sidebar ------------------------------------------------------------
        side = tk.Frame(outer, bg=C["side"], width=72)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        logo = tk.Canvas(side, width=44, height=44, bg=C["side"], highlightthickness=0)
        logo.pack(pady=(18, 22))
        logo.create_oval(4, 4, 40, 40, fill=C["accent"], outline="")
        logo.create_text(22, 22, text="SC", fill="#fff", font=(FONT[0], 12, "bold"))
        self._side_buttons: Dict[str, tk.Button] = {}
        for key, glyph, tip in (("connect", "⏻", "Подключение"), ("nodes", "◎", "Узлы"),
                                ("log", "≡", "Журнал")):
            b = tk.Button(side, text=glyph, font=(FONT[0], 16), bg=C["side"], fg=C["muted"],
                          activebackground=C["card"], activeforeground=C["text"], bd=0,
                          relief="flat", cursor="hand2", width=3, height=1,
                          command=lambda k=key: self._show_page(k))
            b.pack(pady=6)
            self._side_buttons[key] = b
        tk.Label(side, text=f"v{__version__}", bg=C["side"], fg=C["muted"],
                 font=(FONT[0], 8)).pack(side="bottom", pady=10)

        # -- main column --------------------------------------------------------
        main = tk.Frame(outer, bg=C["bg"])
        main.pack(side="left", fill="both", expand=True)

        header = tk.Frame(main, bg=C["bg"])
        header.pack(fill="x", padx=24, pady=(18, 8))
        ttk.Label(header, text="SpaceCopVPN", style="Head.TLabel").pack(side="left")
        self.chip = tk.Label(header, text="● отключено", bg=C["card2"], fg=C["err"],
                             font=FONT_B, padx=12, pady=4)
        self.chip.pack(side="right")

        self.pages: Dict[str, tk.Frame] = {}
        for key in ("connect", "nodes", "log"):
            self.pages[key] = tk.Frame(main, bg=C["bg"])

        self._build_connect_page(self.pages["connect"])
        self._build_nodes_page(self.pages["nodes"])
        self._build_log_page(self.pages["log"])

    def _card(self, parent, title: str, subtitle: str = "") -> ttk.Frame:
        wrap = tk.Frame(parent, bg=C["line"], padx=1, pady=1)     # 1px border
        wrap.pack(fill="x", padx=24, pady=8)
        card = ttk.Frame(wrap, style="Card.TFrame", padding=16)
        card.pack(fill="both", expand=True)
        ttk.Label(card, text=title, style="Title.TLabel").pack(anchor="w")
        if subtitle:
            ttk.Label(card, text=subtitle, style="Muted.TLabel", wraplength=760,
                      justify="left").pack(anchor="w", pady=(2, 8))
        return card

    # -- page: connect ------------------------------------------------------------
    def _build_connect_page(self, page: tk.Frame) -> None:
        # Profile + big button
        card = self._card(page, "Подключение")
        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x", pady=(6, 0))
        ttk.Label(row, text="Профиль").pack(side="left", padx=(0, 8))
        self.cb_profile = ttk.Combobox(row, state="readonly", width=24, values=list(self.profiles))
        self.cb_profile.pack(side="left")
        self.cb_profile.bind("<<ComboboxSelected>>", self._on_profile_selected)
        ttk.Button(row, text="Новый", command=self._new_profile).pack(side="left", padx=(8, 0))
        ttk.Button(row, text="Удалить", command=self._delete_profile).pack(side="left", padx=(6, 0))
        ttk.Button(row, text="Сохранить", command=self._save_current).pack(side="left", padx=(6, 0))

        row2 = ttk.Frame(card, style="Card.TFrame")
        row2.pack(fill="x", pady=(14, 0))
        self.btn_connect = ttk.Button(row2, text="Подключиться", style="Accent.TButton",
                                      command=self._connect)
        self.btn_connect.pack(side="left")
        self.btn_disconnect = ttk.Button(row2, text="Отключиться", style="Danger.TButton",
                                         command=self._disconnect, state="disabled")
        self.btn_disconnect.pack(side="left", padx=(8, 0))
        self.btn_test = ttk.Button(row2, text="Тест", command=self._test, state="disabled")
        self.btn_test.pack(side="left", padx=(8, 0))
        self.lbl_status = ttk.Label(row2, text="", style="Muted.TLabel")
        self.lbl_status.pack(side="left", padx=(16, 0))

        # Mode
        card = self._card(page, "Режим",
                          "«Вся система» заворачивает весь трафик компьютера в VPN через "
                          "виртуальный интерфейс (Linux, спросит пароль администратора). "
                          "«SOCKS5» не требует прав: прокси указывается в браузере или системе.")
        self.var_mode = tk.StringVar(value="socks")
        mrow = ttk.Frame(card, style="Card.TFrame")
        mrow.pack(fill="x")
        ttk.Radiobutton(mrow, text="SOCKS5-прокси", variable=self.var_mode, value="socks",
                        command=self._on_mode_change).pack(side="left")
        rb_sys = ttk.Radiobutton(mrow, text="Вся система (TUN)", variable=self.var_mode,
                                 value="system", command=self._on_mode_change)
        rb_sys.pack(side="left", padx=(18, 0))
        if not sys.platform.startswith("linux"):
            rb_sys.state(["disabled"])
        srow = ttk.Frame(card, style="Card.TFrame")
        srow.pack(fill="x", pady=(10, 0))
        ttk.Label(srow, text="SOCKS адрес").pack(side="left")
        self.e_host = ttk.Entry(srow, width=14)
        self.e_host.pack(side="left", padx=(8, 14))
        ttk.Label(srow, text="порт").pack(side="left")
        self.e_port = ttk.Entry(srow, width=7)
        self.e_port.pack(side="left", padx=(8, 14))
        ttk.Label(srow, text="DNS (вся система)").pack(side="left")
        self.e_dns = ttk.Entry(srow, width=14)
        self.e_dns.pack(side="left", padx=(8, 14))
        ttk.Label(srow, text="тест").pack(side="left")
        self.e_test = ttk.Entry(srow, width=18)
        self.e_test.pack(side="left", padx=(8, 0))

        # Node health
        card = self._card(page, "Состояние узлов", "Узлы конкурируют за трафик; каждый сайт "
                          "закреплён за одним узлом, при сбое клиент переключается на другой.")
        cols = ("node", "addr", "reqs", "fail", "lat", "health")
        self.tree = ttk.Treeview(card, columns=cols, show="headings", height=6)
        for col, title, width in (("node", "Узел", 150), ("addr", "Адрес", 190),
                                  ("reqs", "Запросов", 80), ("fail", "Ошибок", 70),
                                  ("lat", "Задержка, мс", 110), ("health", "Здоровье", 90)):
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, anchor="center")
        self.tree.pack(fill="x", pady=(6, 0))

    # -- page: nodes -----------------------------------------------------------------
    def _build_nodes_page(self, page: tk.Frame) -> None:
        card = self._card(page, "Узлы",
                          "Вставьте строку spacecop://…, которую печатает узел при запуске "
                          "(или скрипт установки сервера). Одного узла достаточно: при "
                          "автообнаружении остальные подтянутся сами.")
        self.lb_nodes = tk.Listbox(card, height=7, activestyle="none", bg=C["card2"], fg=C["text"],
                                   selectbackground=C["accent"], selectforeground="#fff",
                                   highlightthickness=0, bd=0, font=FONT_MONO)
        self.lb_nodes.pack(fill="x", pady=(6, 8))
        row = ttk.Frame(card, style="Card.TFrame")
        row.pack(fill="x")
        self.e_uri = ttk.Entry(row)
        self.e_uri.pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Добавить", command=self._add_node).pack(side="left", padx=(8, 0))
        ttk.Button(row, text="Удалить", command=self._remove_node).pack(side="left", padx=(6, 0))
        row2 = ttk.Frame(card, style="Card.TFrame")
        row2.pack(fill="x", pady=(10, 0))
        self.btn_check = ttk.Button(row2, text="Проверить узел", command=self._check_node)
        self.btn_check.pack(side="left")
        self.btn_find = ttk.Button(row2, text="Найти узлы", style="Accent.TButton",
                                   command=self._find_nodes)
        self.btn_find.pack(side="left", padx=(8, 0))
        self.var_discover = tk.BooleanVar(value=True)
        ttk.Checkbutton(row2, text="Автообнаружение при подключении",
                        variable=self.var_discover).pack(side="left", padx=(18, 0))
        ttk.Label(card, text="«Найти узлы» спрашивает у известных узлов, кого они знают, "
                            "и добавляет найденные в список.", style="Muted.TLabel",
                  wraplength=760).pack(anchor="w", pady=(8, 0))

    # -- page: log -----------------------------------------------------------------------
    def _build_log_page(self, page: tk.Frame) -> None:
        card = self._card(page, "Журнал")
        self.txt_log = tk.Text(card, height=22, state="disabled", wrap="word", bg=C["card2"],
                               fg=C["text"], insertbackground=C["text"], bd=0,
                               highlightthickness=0, font=FONT_MONO, padx=10, pady=8)
        self.txt_log.pack(fill="both", expand=True, pady=(6, 0))
        self.txt_log.tag_configure("ok", foreground=C["ok"])
        self.txt_log.tag_configure("err", foreground=C["err"])
        self.txt_log.tag_configure("warn", foreground=C["warn"])
        ttk.Button(card, text="Очистить", command=self._clear_log).pack(anchor="e", pady=(8, 0))

    def _show_page(self, key: str) -> None:
        for k, frame in self.pages.items():
            frame.pack_forget()
        self.pages[key].pack(fill="both", expand=True)
        self._page = key
        for k, b in self._side_buttons.items():
            b.configure(fg=C["accent"] if k == key else C["muted"])

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
            entry.delete(0, "end")
            entry.insert(0, str(prof.get(key, default)))
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
        self.e_uri.delete(0, "end")
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
        """Ask every known node who else it knows; add new URIs to the list."""
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
        # Also list nodes the running client discovered by itself.
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

    # -- SOCKS mode ------------------------------------------------------------------
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

    # -- system mode (pkexec spacecop vpn) --------------------------------------------
    def _connect_system_worker(self, prof: dict) -> None:
        if shutil.which("pkexec") is None and os.geteuid() != 0:
            self._post("connect_failed", "для режима «Вся система» нужен pkexec (polkit) или запуск от root")
            return
        cmd = [sys.executable, "-m", "spacecop.cli", "vpn", "--dns", prof.get("dns", "1.1.1.1:53"),
               "--status-interval", "5"]
        if not prof.get("discover", True):
            cmd.append("--no-discover")
        for uri in prof["nodes"]:
            cmd += ["--uri", uri]
        if os.geteuid() != 0:
            env_args = [f"PYTHONPATH={os.pathsep.join(sys.path[:1] + [p for p in sys.path if 'site-packages' in p])}"]
            cmd = ["pkexec", "env"] + env_args + cmd
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
            if "READY" in line and not ready:
                ready = True
                self._post("connected_system", None)
            elif "failed to start" in line or "STOPPED" in line:
                self._post("logw" if "STOPPED" in line else "loge", line)
            else:
                self._post("log", line)
        code = proc.wait()
        self._post("sys_exited", (code, ready))

    # -- disconnect ----------------------------------------------------------------
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
        self._set_connected(False)
        self.tree.delete(*self.tree.get_children())
        self._log("Отключено.")

    @staticmethod
    def _stop_worker(proxy, client) -> None:
        try:
            if proxy:
                proxy.stop()
        finally:
            if client:
                client.stop()

    # -- test ----------------------------------------------------------------------
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
                with _socket.create_connection((host, port), timeout=15) as sk:  # via the TUN
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
            self._set_busy(False)
            self._set_connected(False)
            if not ready:
                self._log(f"Помощник завершился с кодом {code}. Отменён ввод пароля? "
                          f"Или установлен старый клиент.", "err")
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
        if self.client is None:
            return
        self.tree.delete(*self.tree.get_children())
        for conn in self.client._selector.ranking():
            self.tree.insert("", "end", values=(
                conn.node_id_hex(), f"{conn.addr[0]}:{conn.addr[1]}", conn.requests, conn.failures,
                f"{conn.ewma_latency * 1000:.0f}" if conn.ewma_latency else "—",
                f"{conn.health_score():.1f}",
            ))

    # ================================================================ helpers
    def _set_busy(self, busy: bool, status: str = "") -> None:
        self._busy = busy
        connected = self.client is not None or self.sys_proc is not None
        self.btn_connect["state"] = "disabled" if (busy or connected) else "normal"
        self.btn_test["state"] = "normal" if (connected and not busy) else "disabled"
        self.btn_check["state"] = "disabled" if busy else "normal"
        self.btn_find["state"] = "disabled" if busy else "normal"
        self.lbl_status.configure(text=status)

    def _set_connected(self, connected: bool, detail: str = "") -> None:
        if connected:
            self.chip.configure(text=f"● подключено · {detail}" if detail else "● подключено", fg=C["ok"])
            self.btn_connect["state"] = "disabled"
            self.btn_disconnect["state"] = "normal"
            self.btn_test["state"] = "normal"
        else:
            self.chip.configure(text="● отключено", fg=C["err"])
            self.btn_connect["state"] = "normal"
            self.btn_disconnect["state"] = "disabled"
            self.btn_test["state"] = "disabled"
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
