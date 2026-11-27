"""MaeGuard GUI"""

import os
import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import maeguard as mg
import maeguard_engines as me

VERSION = "1.5.0"
FOLDER_NAMES = {"downloads": "다운로드", "desktop": "바탕화면", "바탕 화면": "바탕화면",
                "documents": "문서", "문서": "문서", "startup": "시작프로그램"}


def folder_label(p: Path) -> str:
    name = FOLDER_NAMES.get(p.name.lower(), p.name)
    one = os.environ.get("OneDrive")
    if one and name != "시작프로그램":
        try:
            if Path(one).resolve() in p.resolve().parents:
                return name + "(OneDrive)"
        except OSError:
            pass
    return name


def folder_labels(folders) -> str:
    return ", ".join(dict.fromkeys(folder_label(f) for f in folders))

BG = "#0a0b0c"
HEAD = "#000000"
CARD = "#141618"
LINE = "#24282c"
BTN = "#1c1f22"
BTN_HOVER = "#2a2f33"
ACCENT = "#6a986c"
ACCENT_HOVER = "#7fae81"
DANGER = "#e5484d"
OK = ACCENT
WARN = "#e0a33a"
TEXT = "#f2f4f3"
MUTED = "#8b9390"


INSTANCE_PORT = 47391
AUTOSTART_NAME = "MaeGuard"
RUN_KEY = "Software\\Microsoft\\Windows\\" + "Current" + "Version\\" + "Run"


def autostart_command() -> str:
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --tray'
    pyw = Path(sys.executable).with_name("pythonw.exe")
    exe = pyw if pyw.exists() else Path(sys.executable)
    return f'"{exe}" "{Path(__file__).resolve()}" --tray'


def installed_by_setup() -> bool:
    if os.name != "nt":
        return False
    import winreg
    key = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\MaeGuard"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key):
            return True
    except OSError:
        return False


def autostart_enabled() -> bool:
    if os.name != "nt":
        return False
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            winreg.QueryValueEx(k, AUTOSTART_NAME)
            return True
    except OSError:
        return False


def set_autostart(on: bool) -> bool:
    if os.name != "nt":
        return False
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
            if on:
                winreg.SetValueEx(k, AUTOSTART_NAME, 0, winreg.REG_SZ, autostart_command())
            else:
                try:
                    winreg.DeleteValue(k, AUTOSTART_NAME)
                except FileNotFoundError:
                    pass
        mg.log(f"자동 실행 {'켜짐' if on else '꺼짐'}")
        return True
    except OSError as e:
        mg.log(f"자동 실행 설정 실패: {e}")
        return False


def claim_single_instance():
    import socket
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        srv.bind(("127.0.0.1", INSTANCE_PORT))
        srv.listen(2)
        return srv
    except OSError:
        srv.close()
        try:
            with socket.create_connection(("127.0.0.1", INSTANCE_PORT), timeout=2) as c:
                c.sendall(b"show")
        except OSError:
            pass
        return None


def dark_titlebar(win) -> None:
    if os.name != "nt":
        return
    try:
        import ctypes
        win.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(win.winfo_id())
        val = ctypes.c_int(1)
        for attr in (20, 19):
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(val), ctypes.sizeof(val)) == 0:
                break
    except Exception:
        pass


def resource(name: str) -> Path:
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).parent))
    return base / name


class MaeGuardApp:
    def __init__(self, root: tk.Tk, start_hidden: bool = False, instance_sock=None):
        self.root = root
        self.tray = None
        self.tray_notified = False
        self.ui_queue = queue.Queue()
        self.watch_stop = None
        self.scan_running = False
        self.prompt_lock = threading.Lock()
        self.watch_folders = []
        self.sig_count = len(mg.load_signatures())
        self.engines = me.Engines()

        root.title(f"{mg.APP_NAME} {VERSION}")
        root.geometry("880x580")
        root.minsize(820, 480)
        root.configure(bg=BG)
        try:
            root.iconbitmap(default=str(resource("icon.ico")))
        except Exception:
            pass

        self._setup_style()
        self._build_ui()
        dark_titlebar(root)
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(100, self._drain_queue)

        self._setup_tray()
        if instance_sock is not None:
            threading.Thread(target=self._listen_instance, args=(instance_sock,), daemon=True).start()

        cfg = me.load_config()
        if "autostart" not in cfg:
            if installed_by_setup():
                cfg["autostart"] = autostart_enabled()
            else:
                cfg["autostart"] = True
                if getattr(sys, "frozen", False):
                    set_autostart(True)
            me.save_config(cfg)

        if start_hidden and self.tray is not None:
            root.withdraw()

        self.start_watch()
        self.update_db(manual=False)

    def _setup_style(self):
        family = "Malgun Gothic" if os.name == "nt" else "TkDefaultFont"
        self.family = family
        self.f_title = (family, 17, "bold")
        self.f_big = (family, 13, "bold")
        self.f_norm = (family, 10)
        self.f_small = (family, 9)
        st = ttk.Style()
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure(".", background=BG, foreground=TEXT, fieldbackground=BTN, bordercolor=LINE,
                     lightcolor=LINE, darkcolor=LINE, troughcolor=BTN, focuscolor=ACCENT,
                     selectbackground="#23302a", selectforeground=TEXT, insertcolor=TEXT)
        st.configure("TButton", font=self.f_norm, padding=(14, 8), background=BTN, foreground=TEXT,
                     bordercolor=LINE, lightcolor=BTN, darkcolor=BTN, focusthickness=0)
        st.map("TButton", background=[("disabled", BG), ("active", BTN_HOVER)],
               foreground=[("disabled", "#4a504d")],
               lightcolor=[("active", BTN_HOVER)], darkcolor=[("active", BTN_HOVER)])
        st.configure("Accent.TButton", font=(family, 10, "bold"), foreground="#0a0b0c",
                     background=ACCENT, bordercolor=ACCENT, lightcolor=ACCENT, darkcolor=ACCENT)
        st.map("Accent.TButton", background=[("disabled", "#2c3a2d"), ("active", ACCENT_HOVER)],
               foreground=[("disabled", "#5d6b5e")],
               lightcolor=[("active", ACCENT_HOVER)], darkcolor=[("active", ACCENT_HOVER)])
        st.configure("Treeview", font=self.f_small, rowheight=28, background=CARD, fieldbackground=CARD,
                     foreground=TEXT, bordercolor=LINE, lightcolor=CARD, darkcolor=CARD)
        st.map("Treeview", background=[("selected", "#23302a")], foreground=[("selected", TEXT)])
        st.configure("Treeview.Heading", font=(family, 9, "bold"), background=BTN, foreground=MUTED,
                     bordercolor=LINE, lightcolor=BTN, darkcolor=BTN, relief="flat")
        st.map("Treeview.Heading", background=[("active", BTN_HOVER)])
        st.configure("TProgressbar", thickness=4, background=ACCENT, troughcolor=BTN,
                     bordercolor=BG, lightcolor=ACCENT, darkcolor=ACCENT)
        st.configure("Vertical.TScrollbar", background=BTN, troughcolor=CARD, bordercolor=CARD,
                     arrowcolor=MUTED, lightcolor=BTN, darkcolor=BTN)
        st.map("Vertical.TScrollbar", background=[("active", BTN_HOVER)])
        st.configure("TCheckbutton", background=BG, foreground=TEXT, font=self.f_norm,
                     indicatorbackground=BTN, indicatorforeground=ACCENT)
        st.map("TCheckbutton", background=[("active", BG)],
               indicatorbackground=[("selected", BTN), ("active", BTN_HOVER)])
        st.configure("TEntry", fieldbackground=BTN, foreground=TEXT, bordercolor=LINE,
                     lightcolor=LINE, darkcolor=LINE, padding=6)
        st.map("TEntry", bordercolor=[("focus", ACCENT)], lightcolor=[("focus", ACCENT)])

    def _build_ui(self):
        r = self.root
        head = tk.Frame(r, bg=HEAD, height=68)
        head.pack(fill="x")
        head.pack_propagate(False)
        try:
            self.logo_img = tk.PhotoImage(file=str(resource("assets/mark_small.png")))
            tk.Label(head, image=self.logo_img, bg=HEAD).pack(side="left", padx=(20, 12))
        except Exception:
            self.logo_img = None
        names = tk.Frame(head, bg=HEAD)
        names.pack(side="left")
        tk.Label(names, text=mg.APP_NAME, font=self.f_title, fg=TEXT, bg=HEAD).pack(anchor="w")
        tk.Label(names, text="M A E S I L   G U A R D", font=(self.family, 7), fg=MUTED, bg=HEAD
                 ).pack(anchor="w")
        tk.Button(head, text="설정", font=self.f_norm, fg=TEXT, bg=HEAD, activebackground=BTN,
                  activeforeground=TEXT, relief="flat", bd=0, padx=14, pady=6, cursor="hand2",
                  highlightthickness=1, highlightbackground=LINE,
                  command=self.open_settings).pack(side="right", padx=20)
        tk.Frame(r, bg=LINE, height=1).pack(fill="x")

        card = tk.Frame(r, bg=CARD, highlightthickness=1, highlightbackground=LINE)
        card.pack(fill="x", padx=18, pady=(16, 10))
        tk.Frame(card, bg=ACCENT, width=4).pack(side="left", fill="y")
        self.status_bar = card.winfo_children()[-1]
        self.status_dot = tk.Label(card, text="●", font=(None, 22), bg=CARD, fg=MUTED)
        self.status_dot.pack(side="left", padx=(14, 8), pady=12)
        self.watch_btn = ttk.Button(card, text="", command=self.toggle_watch)
        self.watch_btn.pack(side="right", padx=16)
        box = tk.Frame(card, bg=CARD)
        box.pack(side="left", fill="x", expand=True, pady=10)
        self.status_title = tk.Label(box, text="", font=self.f_big, bg=CARD, fg=TEXT, anchor="w")
        self.status_title.pack(fill="x")
        self.status_sub = tk.Label(box, text="", font=self.f_small, bg=CARD, fg=MUTED, anchor="w")
        self.status_sub.pack(fill="x")
        self.status_eng = tk.Label(box, text="", font=self.f_small, bg=CARD, fg=MUTED, anchor="w")
        self.status_eng.pack(fill="x")

        bar = tk.Frame(r, bg=BG)
        bar.pack(fill="x", padx=18, pady=4)
        self.btn_quick = ttk.Button(bar, text="빠른 검사", style="Accent.TButton",
                                    command=lambda: self.start_scan(mg.default_watch_folders(), "빠른 검사"))
        self.btn_quick.pack(side="left")
        self.btn_full = ttk.Button(bar, text="정밀 검사", command=self.full_scan)
        self.btn_full.pack(side="left", padx=(6, 0))
        self.btn_folder = ttk.Button(bar, text="폴더 검사", command=self.pick_folder)
        self.btn_folder.pack(side="left", padx=6)
        self.btn_file = ttk.Button(bar, text="파일 검사", command=self.pick_file)
        self.btn_file.pack(side="left")
        ttk.Button(bar, text="격리소", command=self.open_quarantine).pack(side="right")
        self.btn_update = ttk.Button(bar, text="업데이트", command=lambda: self.update_db(manual=True))
        self.btn_update.pack(side="right", padx=6)

        prog = tk.Frame(r, bg=BG)
        prog.pack(fill="x", padx=18, pady=(10, 0))
        self.progress = ttk.Progressbar(prog, mode="determinate", value=0)
        self.progress.pack(fill="x")
        self.progress_label = tk.Label(prog, text="", font=self.f_small, bg=BG, fg=MUTED, anchor="w")
        self.progress_label.pack(fill="x")

        tk.Label(r, text="활동 기록", font=(self.family, 10, "bold"), bg=BG, fg=TEXT, anchor="w"
                 ).pack(fill="x", padx=18, pady=(6, 4))
        frame = tk.Frame(r, bg=LINE, highlightthickness=0)
        frame.pack(fill="both", expand=True, padx=18, pady=(0, 16))
        cols = ("time", "result", "file", "detail")
        self.tree = ttk.Treeview(frame, columns=cols, show="headings")
        for c, t, w in [("time", "시간", 70), ("result", "결과", 70),
                        ("file", "파일", 220), ("detail", "내용", 360)]:
            self.tree.heading(c, text=t, anchor="w")
            self.tree.column(c, width=w, anchor="w", stretch=(c in ("file", "detail")))
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=1, pady=1)
        sb.pack(side="right", fill="y", pady=1)
        self.tree.tag_configure("block", foreground=DANGER)
        self.tree.tag_configure("allow", foreground=WARN)
        self.tree.tag_configure("ok", foreground=OK)

        self._update_status()

    def _drain_queue(self):
        try:
            while True:
                fn = self.ui_queue.get_nowait()
                fn()
        except queue.Empty:
            pass
        self.root.after(100, self._drain_queue)

    def ui(self, fn):
        self.ui_queue.put(fn)

    def add_row(self, result, path, detail, tag=""):
        from datetime import datetime
        name = Path(path).name if path else ""
        self.tree.insert("", 0, values=(f"{datetime.now():%H:%M:%S}", result, name, detail), tags=(tag,))

    def _update_status(self):
        on = self.watch_stop is not None
        names = ["매가드"] + self.engines.active_names()
        missing = []
        if self.engines.vt is not None and not self.engines.vt.available:
            missing.append("VirusTotal")
        if not me.load_config().get("abusech_key"):
            missing.append("MalwareBazaar")
        self.status_eng.config(text="검사 엔진: " + " · ".join(names)
                               + (f"   (꺼짐: {' · '.join(missing)} - 설정에서 키를 입력하세요)" if missing else ""))
        if on:
            self.status_dot.config(fg=OK)
            self.status_bar.config(bg=OK)
            self.status_title.config(text="실시간 감시가 켜져 있습니다")
            names = folder_labels(self.watch_folders)
            self.status_sub.config(text=f"감시 중인 폴더: {names}  ·  악성코드 해시 {self.sig_count:,}개")
            self.watch_btn.config(text="실시간 감시 끄기")
        else:
            self.status_dot.config(fg=DANGER)
            self.status_bar.config(bg=DANGER)
            self.status_title.config(text="실시간 감시가 꺼져 있습니다")
            self.status_sub.config(text=f"새 파일을 자동으로 검사하지 않습니다  ·  악성코드 해시 {self.sig_count:,}개")
            self.watch_btn.config(text="실시간 감시 켜기")
        self._refresh_tray()

    def ask_block(self, r) -> bool:
        with self.prompt_lock:
            answer = {}
            done = threading.Event()

            def show():
                title = f"{mg.APP_NAME} - {'악성코드 발견!' if r.verdict == '악성' else '의심스러운 파일'}"
                scores = getattr(r, "_scores", [0] * len(r.reasons))
                ranked = [x for _, x in sorted(zip(scores, r.reasons), key=lambda t: -t[0])]
                shown = ranked[:8]
                more = f"\n • 외 {len(ranked) - len(shown)}개" if len(ranked) > len(shown) else ""
                body = (f"파일: {r.path}\n위험 점수: {r.score}\n\n이유:\n"
                        + "\n".join(f" • {x}" for x in shown) + more
                        + "\n\n이 파일을 차단(격리)할까요?")
                self.root.deiconify()
                self.root.lift()
                self.root.attributes("-topmost", True)
                answer["v"] = messagebox.askyesno(title, body, icon="warning", parent=self.root)
                self.root.attributes("-topmost", False)
                done.set()

            self.ui(show)
            done.wait()
            return answer["v"]

    def handle_result(self, r):
        if r.verdict == "안전":
            return "안전"
        if self.ask_block(r):
            try:
                qid = mg.quarantine(r)
                self.ui(lambda: self.add_row("차단", r.path, f"{r.verdict} · {r.top_reason} · 격리 ID {qid}", "block"))
                return "차단"
            except OSError as e:
                self.ui(lambda err=str(e): self.add_row("실패", r.path, f"차단 실패: {err}", "allow"))
                return "허용"
        mg.log(f"허용: {r.path} ({r.verdict}, 점수 {r.score})")
        self.ui(lambda: self.add_row("허용", r.path, f"{r.verdict} · {r.top_reason} · 점수 {r.score}", "allow"))
        return "허용"

    def start_watch(self, quiet: bool = False):
        if self.watch_stop is not None:
            return
        self.watch_folders = mg.default_watch_folders()
        if not self.watch_folders:
            self.add_row("실패", "", "감시할 폴더를 찾을 수 없습니다", "allow")
            return
        self.watch_stop = threading.Event()
        stop = self.watch_stop

        def on_result(r):
            if r.verdict == "안전":
                self.ui(lambda: self.add_row("안전", r.path, f"새 파일 검사 완료 ({folder_label(r.path.parent)})", "ok"))
            else:
                self.handle_result(r)

        for folder in self.watch_folders:
            threading.Thread(target=lambda f=folder: mg.Watcher(f, on_result, engines=self.engines).run(stop), daemon=True).start()
        names = folder_labels(self.watch_folders)
        mg.log(f"감시 시작: {[str(f) for f in self.watch_folders]}")
        if not quiet:
            self.add_row("켜짐", "", f"실시간 감시를 켰습니다 ({names})", "ok")
        self._update_status()

    def stop_watch(self, quiet: bool = False):
        if self.watch_stop is None:
            return
        self.watch_stop.set()
        self.watch_stop = None
        mg.log("감시 종료")
        if not quiet:
            self.add_row("꺼짐", "", "실시간 감시를 껐습니다", "allow")
        self._update_status()

    def toggle_watch(self):
        if self.watch_stop is None:
            self.start_watch()
        else:
            self.stop_watch()

    def full_scan(self):
        if messagebox.askyesno(mg.APP_NAME, "사용자 폴더 전체를 검사합니다.\n파일이 많으면 몇 분 걸릴 수 있어요. 시작할까요?"):
            self.start_scan([Path.home()], "정밀 검사")

    def update_db(self, manual: bool):
        self.btn_update.config(state="disabled")

        def run():
            msgs, failed = [], False
            try:
                added = mg.update_signatures(me.load_config().get("abusech_key", ""))
                msgs.append(f"악성코드 해시 {added:,}개 추가")
            except mg.NoAuthKey:
                if manual:
                    msgs.append("악성코드 해시: 건너뜀 (설정에서 abuse.ch 키를 입력하세요)")
            except Exception as e:
                failed = True
                mg.log(f"악성코드 DB 업데이트 실패: {e}")
                msgs.append(f"악성코드 해시: 실패 ({e})")
            y = self.engines.yara
            if y is not None and y.yara is not None and (manual or y.needs_update()):
                try:
                    msgs.append(f"YARA 규칙 {y.update():,}개로 갱신")
                except Exception as e:
                    failed = True
                    mg.log(f"YARA 업데이트 실패: {e}")
                    msgs.append("YARA 규칙: 실패")
            total = len(mg.load_signatures())

            def done():
                self.sig_count = total
                self._update_status()
                if msgs:
                    text = " · ".join(msgs) + f" (악성코드 해시 총 {total:,}개)"
                    self.add_row("실패" if failed else "업데이트", "", text, "allow" if failed else "ok")
                if manual:
                    body = "\n".join(msgs) or "이미 최신입니다."
                    (messagebox.showwarning if failed else messagebox.showinfo)(mg.APP_NAME, body)
            self.ui(done)
            self.ui(lambda: self.btn_update.config(state="normal"))

        threading.Thread(target=run, daemon=True).start()

    def pick_folder(self):
        d = filedialog.askdirectory(title="검사할 폴더 선택")
        if d:
            self.start_scan([Path(d)], "폴더 검사")

    def pick_file(self):
        f = filedialog.askopenfilename(title="검사할 파일 선택")
        if f:
            self.start_scan([Path(f)], "파일 검사")

    def _set_scanning(self, on: bool):
        self.scan_running = on
        state = "disabled" if on else "normal"
        for b in (self.btn_quick, self.btn_full, self.btn_folder, self.btn_file):
            b.config(state=state)
        if on:
            self.progress.config(mode="indeterminate")
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.config(mode="determinate", value=0)

    def start_scan(self, targets, label="검사"):
        if self.scan_running:
            return
        targets = [t for t in targets if t.exists()]
        if not targets:
            messagebox.showerror(mg.APP_NAME, "검사할 경로가 없습니다.")
            return
        self._set_scanning(True)
        self.add_row("검사", "", f"{label} 시작: " + ", ".join(folder_label(t) for t in targets))

        def run():
            sigs = mg.load_signatures()
            stats = {"검사": 0, "안전": 0, "차단": 0, "허용": 0}
            files = (p for t in targets for p in mg.iter_files(t))
            for p in files:
                try:
                    if p.is_symlink() or not p.is_file():
                        continue
                except OSError:
                    continue
                stats["검사"] += 1
                if stats["검사"] % 20 == 1:
                    n, name = stats["검사"], str(p)
                    self.ui(lambda n=n, name=name: self.progress_label.config(text=f"{n}개 검사 중… {name}"))
                stats[self.handle_result(mg.scan_file(p, sigs, self.engines, vt_wait=0))] += 1
            mg.log(f"{label} 완료: {[str(t) for t in targets]} {stats}")

            def finish():
                self._set_scanning(False)
                found = stats["차단"] + stats["허용"]
                msg = (f"검사 {stats['검사']}개 · 차단 {stats['차단']} · 허용 {stats['허용']}")
                self.progress_label.config(text="검사 완료  ·  " + msg)
                self.add_row("완료", "", f"{label} 완료 · {msg}", "allow" if found else "ok")
                if not found:
                    messagebox.showinfo(mg.APP_NAME, f"위협이 발견되지 않았습니다.\n\n{msg}")
            self.ui(finish)

        threading.Thread(target=run, daemon=True).start()

    def open_settings(self):
        cfg = me.load_config()
        win = tk.Toplevel(self.root)
        win.after(10, lambda: dark_titlebar(win))
        win.title(f"{mg.APP_NAME} - 설정")
        win.geometry("560x560")
        win.configure(bg=BG)
        win.transient(self.root)
        win.after(100, lambda: win.winfo_exists() and win.grab_set())

        def section(text):
            tk.Label(win, text=text, font=(self.f_norm[0], 11, "bold"), bg=BG, fg=TEXT, anchor="w"
                     ).pack(fill="x", padx=18, pady=(14, 4))

        def note(text):
            tk.Label(win, text=text, font=self.f_small, bg=BG, fg=MUTED, anchor="w", justify="left",
                     wraplength=520).pack(fill="x", padx=36)

        section("검사 엔진")
        v_def = tk.BooleanVar(value=cfg["use_defender"])
        v_vt = tk.BooleanVar(value=cfg["use_virustotal"])
        v_yara = tk.BooleanVar(value=cfg["use_yara"])
        d_ok = me.DefenderEngine().available
        ttk.Checkbutton(win, text="Windows Defender 엔진" + ("" if d_ok else "  (이 PC에서 사용 불가)"),
                        variable=v_def).pack(anchor="w", padx=30)
        ttk.Checkbutton(win, text="YARA 규칙 (보안 업계 공개 규칙 약 5천 개)", variable=v_yara).pack(anchor="w", padx=30)
        ttk.Checkbutton(win, text="VirusTotal (70여 개 백신 판정 조회)", variable=v_vt).pack(anchor="w", padx=30)
        note("VirusTotal에는 파일 내용이 아니라 지문(해시)만 보냅니다.")

        section("일반")
        v_auto = tk.BooleanVar(value=autostart_enabled() if os.name == "nt" else cfg.get("autostart", True))
        ttk.Checkbutton(win, text="윈도우 시작 시 자동 실행 (트레이에서 조용히 보호)", variable=v_auto).pack(anchor="w", padx=30)

        section("MalwareBazaar 키 (abuse.ch)")
        note("auth.abuse.ch 무료 가입 → Auth-Key 복사. 최신 악성코드 해시 목록을 받는 데 씁니다.")
        v_abuse = tk.StringVar(value=cfg.get("abusech_key", ""))
        ttk.Entry(win, textvariable=v_abuse, show="•", width=44).pack(anchor="w", padx=36, pady=6)

        section("VirusTotal API 키")
        note("virustotal.com 무료 가입 → 오른쪽 위 프로필 → API key 에서 복사해 붙여넣으세요.")
        row = tk.Frame(win, bg=BG)
        row.pack(fill="x", padx=36, pady=6)
        v_key = tk.StringVar(value=cfg.get("vt_api_key", ""))
        ent = ttk.Entry(row, textvariable=v_key, show="•", width=36)
        ent.pack(side="left", fill="x", expand=True)
        key_msg = tk.Label(win, text="", font=self.f_small, bg=BG, fg=MUTED, anchor="w")
        key_msg.pack(fill="x", padx=36)

        def test_key():
            key_msg.config(text="확인 중…", fg=MUTED)

            def run():
                ok, msg = me.test_vt_key(v_key.get())
                self.ui(lambda: key_msg.config(text=msg, fg=OK if ok else DANGER))
            threading.Thread(target=run, daemon=True).start()
        ttk.Button(row, text="키 확인", command=test_key).pack(side="left", padx=(6, 0))

        def save():
            cfg.update(use_defender=v_def.get(), use_virustotal=v_vt.get(), use_yara=v_yara.get(),
                       vt_api_key=v_key.get().strip(), autostart=v_auto.get(),
                       abusech_key=v_abuse.get().strip())
            key_changed = cfg["abusech_key"] != me.load_config().get("abusech_key", "")
            set_autostart(v_auto.get())
            me.save_config(cfg)
            self.engines = me.Engines(cfg)
            if self.watch_stop is not None:
                self.stop_watch(quiet=True)
                self.start_watch(quiet=True)
            self._update_status()
            self.add_row("설정", "", "설정을 저장했습니다 · 검사 엔진: " + " · ".join(["매가드"] + self.engines.active_names()), "ok")
            win.destroy()
            y = self.engines.yara
            if key_changed and cfg["abusech_key"]:
                self.update_db(manual=True)
            elif y is not None and y.yara is not None and not y.available:
                self.update_db(manual=False)

        bar = tk.Frame(win, bg=BG)
        bar.pack(side="bottom", fill="x", padx=18, pady=14)
        ttk.Button(bar, text="저장", style="Accent.TButton", command=save).pack(side="right")
        ttk.Button(bar, text="취소", command=win.destroy).pack(side="right", padx=6)

    def open_quarantine(self):
        win = tk.Toplevel(self.root)
        win.after(10, lambda: dark_titlebar(win))
        win.title(f"{mg.APP_NAME} - 격리소")
        win.geometry("700x360")
        win.configure(bg=BG)
        win.transient(self.root)

        tk.Label(win, text="차단된 파일은 실행할 수 없는 상태로 보관됩니다.", font=self.f_small,
                 bg=BG, fg=MUTED, anchor="w").pack(fill="x", padx=12, pady=(10, 4))
        cols = ("id", "date", "verdict", "path")
        tv = ttk.Treeview(win, columns=cols, show="headings", selectmode="browse")
        for c, t, w in [("id", "ID", 80), ("date", "날짜", 140), ("verdict", "판정", 80), ("path", "원래 위치", 380)]:
            tv.heading(c, text=t, anchor="w")
            tv.column(c, width=w, anchor="w", stretch=(c == "path"))
        qbar = tk.Frame(win, bg=BG)
        qbar.pack(side="bottom", fill="x", padx=12, pady=10)
        tv.pack(fill="both", expand=True, padx=12)

        def refresh():
            tv.delete(*tv.get_children())
            for k, v in mg.list_quarantine().items():
                tv.insert("", "end", iid=k, values=(k, v["date"], f"{v['verdict']}({v['score']})", v["original"]))

        def selected():
            sel = tv.selection()
            if not sel:
                messagebox.showinfo(mg.APP_NAME, "파일을 먼저 선택하세요.", parent=win)
            return sel[0] if sel else None

        def restore():
            qid = selected()
            if qid and messagebox.askyesno(mg.APP_NAME, "이 파일을 복원할까요?\n위험할 수 있습니다.",
                                           icon="warning", parent=win):
                dst = mg.restore_quarantine(qid)
                self.add_row("복원", dst, f"격리 ID {qid} 복원", "allow")
                refresh()

        def delete():
            qid = selected()
            if qid and messagebox.askyesno(mg.APP_NAME, "이 파일을 영구 삭제할까요?", parent=win):
                mg.delete_quarantine(qid)
                self.add_row("삭제", "", f"격리 ID {qid} 영구 삭제", "ok")
                refresh()

        bar = qbar
        ttk.Button(bar, text="복원", command=restore).pack(side="left")
        ttk.Button(bar, text="영구 삭제", command=delete).pack(side="left", padx=6)
        ttk.Button(bar, text="닫기", command=win.destroy).pack(side="right")
        refresh()

    def _setup_tray(self):
        try:
            import pystray
            from PIL import Image
        except Exception as e:
            mg.log(f"트레이 사용 불가: {e}")
            return
        try:
            img = Image.open(resource("icon.ico"))
        except Exception:
            img = Image.new("RGB", (64, 64), ACCENT)
        M = pystray.MenuItem
        menu = pystray.Menu(
            M("매가드 열기", lambda: self.ui(self.show_window), default=True),
            M("실시간 감시", lambda: self.ui(self.toggle_watch), checked=lambda item: self.watch_stop is not None),
            M("빠른 검사", lambda: self.ui(lambda: (self.show_window(),
                                                 self.start_scan(mg.default_watch_folders(), "빠른 검사")))),
            pystray.Menu.SEPARATOR,
            M("완전히 종료", lambda: self.ui(self.quit_app)),
        )
        try:
            self.tray = pystray.Icon("MaeGuard", img, self._tray_title(), menu)
        except Exception as e:
            mg.log(f"트레이 생성 실패: {e}")
            self.tray = None
            return
        threading.Thread(target=self.tray.run, daemon=True).start()

    def _tray_title(self) -> str:
        on = self.watch_stop is not None
        if os.name != "nt":
            return "MaeGuard"
        return f"{mg.APP_NAME} - " + ("보호 중" if on else "실시간 감시 꺼짐")

    def _refresh_tray(self):
        if self.tray is not None:
            try:
                self.tray.title = self._tray_title()
                self.tray.update_menu()
            except Exception:
                pass

    def _listen_instance(self, srv):
        while True:
            try:
                conn, _ = srv.accept()
                with conn:
                    if conn.recv(16) == b"show":
                        self.ui(self.show_window)
            except OSError:
                return

    def show_window(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def on_close(self):
        if self.tray is None:
            if self.watch_stop is not None and not messagebox.askyesno(
                    mg.APP_NAME, "매가드를 종료하면 실시간 감시도 꺼집니다.\n종료할까요?"):
                return
            self.quit_app()
            return
        self.root.withdraw()
        if not self.tray_notified:
            self.tray_notified = True
            try:
                self.tray.notify("창을 닫아도 백그라운드에서 계속 보호합니다.\n"
                                 "시계 옆 방패 아이콘으로 다시 열 수 있어요.", mg.APP_NAME)
            except Exception:
                pass

    def quit_app(self):
        if self.watch_stop is not None:
            self.show_window()
            if not messagebox.askyesno(mg.APP_NAME, "매가드를 완전히 종료하면 실시간 감시가 꺼집니다.\n종료할까요?"):
                return
        self.stop_watch()
        if self.tray is not None:
            try:
                self.tray.stop()
            except Exception:
                pass
        self.root.destroy()


def main():
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    sock = claim_single_instance()
    if sock is None:
        return
    root = tk.Tk()
    MaeGuardApp(root, start_hidden="--tray" in sys.argv, instance_sock=sock)
    root.mainloop()


if __name__ == "__main__":
    main()
