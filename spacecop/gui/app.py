"""SpaceCopVPN graphical client — configure and run the VPN with a few clicks.

Built with Tkinter (Python standard library), so the only system dependency is
the ``tk`` package.  The UI is in Russian; the code and comments are English.

Layout
------
* **Профиль** — named connection profiles saved to
  ``~/.config/spacecop/profiles.json``.
* **Узлы** — one or more node connection URIs (``spacecop://...``); paste the
  string a node prints on start-up.  Several nodes = several competing relays.
* **SOCKS5** — where the local proxy listens (default 127.0.0.1:1080).
* **Подключиться / Отключиться / Тест** and a live table of node health plus
  a log.

All network work runs on background threads; UI updates are marshalled back to
the Tk main loop through a queue polled with ``after()``.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from typing import Dict, List, Optional

from ..client import RelayTimeout, VPNClient
from ..protocol.uri import URIError, parse_uri
from ..tun.socks_proxy import Socks5Proxy

APP_TITLE = "SpaceCopVPN"
CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".config", "spacecop")
CONFIG_PATH = os.path.join(CONFIG_DIR, "profiles.json")

DEFAULT_PROFILE = {
    "nodes": [],
    "listen_host": "127.0.0.1",
    "listen_port": 1080,
    "test_target": "example.com:80",
}


# ---------------------------------------------------------------------------
# Config persistence
# ---------------------------------------------------------------------------
def load_profiles() -> Dict[str, dict]:
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and data:
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
        self.root.minsize(760, 620)

        self.profiles = load_profiles()
        self.current_profile = next(iter(self.profiles))
        self.client: Optional[VPNClient] = None
        self.proxy: Optional[Socks5Proxy] = None
        self._events: "queue.Queue[tuple]" = queue.Queue()
        self._busy = False

        self._build_ui()
        self._load_profile_into_ui(self.current_profile)
        self.root.after(200, self._drain_events)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # -- UI construction ----------------------------------------------------
    def _build_ui(self) -> None:
        pad = {"padx": 8, "pady": 4}
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        # Profile row
        f_prof = ttk.LabelFrame(self.root, text="Профиль")
        f_prof.pack(fill="x", **pad)
        ttk.Label(f_prof, text="Профиль:").grid(row=0, column=0, sticky="w", **pad)
        self.cb_profile = ttk.Combobox(f_prof, state="readonly", width=28,
                                       values=list(self.profiles))
        self.cb_profile.grid(row=0, column=1, sticky="w", **pad)
        self.cb_profile.bind("<<ComboboxSelected>>", self._on_profile_selected)
        ttk.Button(f_prof, text="Новый", command=self._new_profile).grid(row=0, column=2, **pad)
        ttk.Button(f_prof, text="Удалить", command=self._delete_profile).grid(row=0, column=3, **pad)
        ttk.Button(f_prof, text="Сохранить", command=self._save_current).grid(row=0, column=4, **pad)

        # Nodes
        f_nodes = ttk.LabelFrame(self.root, text="Узлы (строки подключения spacecop://…)")
        f_nodes.pack(fill="both", expand=False, **pad)
        self.lb_nodes = tk.Listbox(f_nodes, height=5, activestyle="none")
        self.lb_nodes.grid(row=0, column=0, columnspan=4, sticky="nsew", **pad)
        f_nodes.columnconfigure(0, weight=1)
        self.e_uri = ttk.Entry(f_nodes)
        self.e_uri.grid(row=1, column=0, columnspan=2, sticky="ew", **pad)
        ttk.Button(f_nodes, text="Добавить узел", command=self._add_node).grid(row=1, column=2, **pad)
        ttk.Button(f_nodes, text="Удалить узел", command=self._remove_node).grid(row=1, column=3, **pad)
        self.btn_check = ttk.Button(f_nodes, text="Проверить узел", command=self._check_node)
        self.btn_check.grid(row=1, column=4, **pad)
        ttk.Label(f_nodes, foreground="#555",
                  text="Вставьте строку, которую узел печатает при запуске "
                       "(или выдаёт скрипт установки сервера).").grid(
            row=2, column=0, columnspan=4, sticky="w", padx=8)

        # SOCKS + actions
        f_socks = ttk.LabelFrame(self.root, text="Локальный SOCKS5-прокси")
        f_socks.pack(fill="x", **pad)
        ttk.Label(f_socks, text="Адрес:").grid(row=0, column=0, sticky="w", **pad)
        self.e_host = ttk.Entry(f_socks, width=16)
        self.e_host.grid(row=0, column=1, sticky="w", **pad)
        ttk.Label(f_socks, text="Порт:").grid(row=0, column=2, sticky="w", **pad)
        self.e_port = ttk.Entry(f_socks, width=8)
        self.e_port.grid(row=0, column=3, sticky="w", **pad)
        ttk.Label(f_socks, text="Тестовый адрес:").grid(row=0, column=4, sticky="w", **pad)
        self.e_test = ttk.Entry(f_socks, width=20)
        self.e_test.grid(row=0, column=5, sticky="w", **pad)

        f_act = ttk.Frame(self.root)
        f_act.pack(fill="x", **pad)
        self.btn_connect = ttk.Button(f_act, text="Подключиться", command=self._connect)
        self.btn_connect.pack(side="left", padx=4)
        self.btn_disconnect = ttk.Button(f_act, text="Отключиться", command=self._disconnect,
                                         state="disabled")
        self.btn_disconnect.pack(side="left", padx=4)
        self.btn_test = ttk.Button(f_act, text="Тест", command=self._test, state="disabled")
        self.btn_test.pack(side="left", padx=4)
        self.lbl_status = ttk.Label(f_act, text="Статус: отключено", foreground="#a00")
        self.lbl_status.pack(side="left", padx=16)

        # Node health table
        f_tbl = ttk.LabelFrame(self.root, text="Состояние узлов (конкуренция за трафик)")
        f_tbl.pack(fill="both", expand=True, **pad)
        cols = ("node", "addr", "reqs", "fail", "lat", "health")
        self.tree = ttk.Treeview(f_tbl, columns=cols, show="headings", height=5)
        for col, title, width in (
            ("node", "Узел", 150), ("addr", "Адрес", 170), ("reqs", "Запросов", 80),
            ("fail", "Ошибок", 70), ("lat", "Задержка, мс", 100), ("health", "Здоровье", 90),
        ):
            self.tree.heading(col, text=title)
            self.tree.column(col, width=width, anchor="center")
        self.tree.pack(fill="both", expand=True, padx=8, pady=4)

        # Log
        f_log = ttk.LabelFrame(self.root, text="Журнал")
        f_log.pack(fill="both", expand=True, **pad)
        self.txt_log = tk.Text(f_log, height=8, state="disabled", wrap="word")
        self.txt_log.pack(fill="both", expand=True, padx=8, pady=4)

    # -- profile handling ---------------------------------------------------
    def _load_profile_into_ui(self, name: str) -> None:
        prof = self.profiles.get(name, dict(DEFAULT_PROFILE))
        self.current_profile = name
        self.cb_profile.set(name)
        self.lb_nodes.delete(0, "end")
        for uri in prof.get("nodes", []):
            self.lb_nodes.insert("end", uri)
        self.e_host.delete(0, "end")
        self.e_host.insert(0, prof.get("listen_host", "127.0.0.1"))
        self.e_port.delete(0, "end")
        self.e_port.insert(0, str(prof.get("listen_port", 1080)))
        self.e_test.delete(0, "end")
        self.e_test.insert(0, prof.get("test_target", "example.com:80"))

    def _read_ui_into_profile(self) -> dict:
        try:
            port = int(self.e_port.get().strip())
        except ValueError:
            port = 1080
        return {
            "nodes": list(self.lb_nodes.get(0, "end")),
            "listen_host": self.e_host.get().strip() or "127.0.0.1",
            "listen_port": port,
            "test_target": self.e_test.get().strip() or "example.com:80",
        }

    def _on_profile_selected(self, _event=None) -> None:
        self._load_profile_into_ui(self.cb_profile.get())

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
        self._log(f"Удалён профиль «{name}».")

    def _save_current(self) -> None:
        self.profiles[self.current_profile] = self._read_ui_into_profile()
        save_profiles(self.profiles)
        self._log(f"Профиль «{self.current_profile}» сохранён в {CONFIG_PATH}.")

    # -- node list ----------------------------------------------------------
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

    # -- node diagnostics ---------------------------------------------------
    def _check_node(self) -> None:
        """Ping + handshake the URI in the entry (or the selected list item)."""
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
        self._set_busy(True, "Статус: проверка узла…", "#a60")
        self.btn_check["state"] = "disabled"
        threading.Thread(target=self._check_node_worker, args=(target,), daemon=True).start()

    def _check_node_worker(self, target) -> None:
        client = VPNClient()
        client.start()
        try:
            rtt = client.ping(target.address, timeout=4.0)
            if rtt is None:
                self._post("check_done", (False,
                    f"{target.host}:{target.port}: узел НЕ отвечает по UDP. Проверьте на сервере: "
                    f"systemctl status spacecop-node, ss -ulnp | grep {target.port}, и что UDP/{target.port} "
                    f"открыт в файрволе провайдера (security group)."))
                return
            try:
                conn = client.connect(target.x_public, target.address,
                                      expected_node_ed=target.ed_public, timeout=6.0)
                self._post("check_done", (True,
                    f"{target.host}:{target.port}: PONG за {rtt * 1000:.0f} мс, рукопожатие OK, "
                    f"узел {conn.node_id_hex()}."))
            except Exception as exc:
                self._post("check_done", (False,
                    f"{target.host}:{target.port}: узел достижим (PONG {rtt * 1000:.0f} мс), "
                    f"но рукопожатие отклонено: {exc}. Проверьте ключи в строке и часы на обеих машинах."))
        finally:
            client.stop()

    # -- connect / disconnect / test ----------------------------------------
    def _connect(self) -> None:
        if self._busy or self.client is not None:
            return
        prof = self._read_ui_into_profile()
        if not prof["nodes"]:
            messagebox.showwarning(APP_TITLE, "Добавьте хотя бы один узел.")
            return
        self.profiles[self.current_profile] = prof
        save_profiles(self.profiles)
        self._set_busy(True, "Статус: подключение…", "#a60")
        threading.Thread(target=self._connect_worker, args=(prof,), daemon=True).start()

    def _connect_worker(self, prof: dict) -> None:
        client = VPNClient()
        client.start()
        ok = 0
        for text in prof["nodes"]:
            try:
                target = parse_uri(text)
                client.connect(target.x_public, target.address,
                               expected_node_ed=target.ed_public, timeout=6.0)
                ok += 1
                self._post("log", f"Подключено к узлу {target.host}:{target.port}.")
            except Exception as exc:
                self._post("log", f"Не удалось подключиться к {text[:48]}…: {exc}")
        if ok == 0:
            client.stop()
            self._post("connect_failed", "ни один узел не ответил")
            return
        try:
            proxy = Socks5Proxy(client, listen_host=prof["listen_host"],
                                listen_port=prof["listen_port"])
            proxy.start()
        except OSError as exc:
            client.stop()
            self._post("connect_failed", f"не удалось открыть SOCKS-порт: {exc}")
            return
        self._post("connected", (client, proxy, ok))

    def _disconnect(self) -> None:
        if self.client is None:
            return
        proxy, client = self.proxy, self.client
        self.proxy, self.client = None, None
        threading.Thread(target=self._stop_worker, args=(proxy, client), daemon=True).start()
        self._set_status("Статус: отключено", "#a00")
        self.btn_connect["state"] = "normal"
        self.btn_disconnect["state"] = "disabled"
        self.btn_test["state"] = "disabled"
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

    def _test(self) -> None:
        if self.client is None or self._busy:
            return
        target = self.e_test.get().strip() or "example.com:80"
        host, _, port = target.rpartition(":")
        if not host:
            messagebox.showwarning(APP_TITLE, "Тестовый адрес должен быть в виде host:port.")
            return
        self._set_busy(True, "Статус: тест…", "#a60")
        threading.Thread(target=self._test_worker, args=(host, int(port)), daemon=True).start()

    def _test_worker(self, host: str, port: int) -> None:
        req = f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
        started = time.monotonic()
        try:
            resp = self.client.relay(host, port, req, timeout=15)
            ms = (time.monotonic() - started) * 1000
            first = resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")[:80]
            self._post("test_done", f"Тест OK за {ms:.0f} мс, получено {len(resp)} байт: {first}")
        except RelayTimeout as exc:
            self._post("test_done", f"Тест не пройден: {exc}")
        except Exception as exc:
            self._post("test_done", f"Тест: ошибка {exc}")

    # -- event plumbing (worker threads -> Tk main loop) --------------------
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
        elif kind == "connected":
            self.client, self.proxy, ok = payload
            host, port = self.proxy.address
            self._set_busy(False)
            self._set_status(f"Статус: подключено ({ok} узл.) — SOCKS5 {host}:{port}", "#080")
            self.btn_connect["state"] = "disabled"
            self.btn_disconnect["state"] = "normal"
            self.btn_test["state"] = "normal"
            self._log(f"SOCKS5-прокси запущен на {host}:{port}. "
                      f"Укажите его в настройках браузера/системы.")
        elif kind == "connect_failed":
            self._set_busy(False)
            self._set_status("Статус: ошибка подключения", "#a00")
            self._log(f"Подключение не удалось: {payload}")
        elif kind == "check_done":
            ok, text = payload
            self._set_busy(False)
            self.btn_check["state"] = "normal"
            if self.client is None:
                self._set_status("Статус: узел проверен" if ok else "Статус: узел недоступен",
                                 "#080" if ok else "#a00")
            self._log(("✓ " if ok else "✗ ") + text)
        elif kind == "test_done":
            self._set_busy(False)
            if self.client is not None:
                host, port = self.proxy.address
                self._set_status(f"Статус: подключено — SOCKS5 {host}:{port}", "#080")
            self._log(payload)

    def _refresh_table(self) -> None:
        if self.client is None:
            return
        self.tree.delete(*self.tree.get_children())
        for conn in self.client._selector.ranking():
            self.tree.insert("", "end", values=(
                conn.node_id_hex(),
                f"{conn.addr[0]}:{conn.addr[1]}",
                conn.requests,
                conn.failures,
                f"{conn.ewma_latency * 1000:.0f}" if conn.ewma_latency else "—",
                f"{conn.health_score():.1f}",
            ))

    # -- helpers ------------------------------------------------------------
    def _set_busy(self, busy: bool, status: str = "", color: str = "") -> None:
        self._busy = busy
        state = "disabled" if busy else "normal"
        self.btn_connect["state"] = state if self.client is None else "disabled"
        self.btn_test["state"] = "disabled" if (busy or self.client is None) else "normal"
        if status:
            self._set_status(status, color)

    def _set_status(self, text: str, color: str) -> None:
        self.lbl_status.configure(text=text, foreground=color)

    def _log(self, text: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        self.txt_log.configure(state="normal")
        self.txt_log.insert("end", f"[{stamp}] {text}\n")
        self.txt_log.see("end")
        self.txt_log.configure(state="disabled")

    def _on_close(self) -> None:
        if self.client is not None:
            self._disconnect()
        self.root.after(150, self.root.destroy)


def main() -> int:
    root = tk.Tk()
    App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
