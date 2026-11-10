"""LOG USE - Personal Cybersecurity Monitor (Windows).  See docs/USER_GUIDE for the full manual."""
import os
import re
import sys
import csv
import json
import queue
import socket
import argparse
import threading
from datetime import datetime
from urllib.parse import urlparse
import tkinter as tk
from tkinter import ttk, messagebox

import core
from core import (APP_NAME, VERSION, APP_DIR, REPORT_DIR, db, init_db, now, log_event,
                  get_setting, set_setting)
import winevents
import threatintel
import camera
import browsers
from monitor import LiveMonitor

BG, PANEL, CARD, TEXT, MUTED, ACCENT = "#090d12", "#111923", "#14202b", "#dce7ef", "#91a4b5", "#00d6a5"
LOCK_PORT = 47653


# ----------------------------------------------------------------- small helpers
def resolve_website_ips(limit=1000):
    with db() as con:
        rows = con.execute("SELECT id,domain FROM websites WHERE domain!='' AND resolved_ip IS NULL LIMIT ?",
                           (limit,)).fetchall()
    for row in rows:
        try:
            ips = sorted({i[4][0] for i in socket.getaddrinfo(row["domain"], None)})
            text = ", ".join(ips)
        except Exception as exc:
            text = f"Lookup failed: {exc.__class__.__name__}"
        with db() as con:
            con.execute("UPDATE websites SET resolved_ip=?,ip_checked_at=? WHERE id=?", (text, now(), row["id"]))
    log_event("DNS_LOOKUP", f"Resolved {len(rows)} website records")
    return len(rows)


def check_website(url):
    import requests
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.hostname:
        raise ValueError("Enter a valid website URL.")
    https = "Yes" if parsed.scheme == "https" else "No"
    tls, headers_result, notes = "Not checked", {}, []
    try:
        resp = requests.get(url, timeout=12, allow_redirects=True,
                            headers={"User-Agent": "LOG-USE-Security-Checker/2.0"})
        if urlparse(resp.url).scheme == "https":
            tls = "HTTPS connection succeeded (certificate validation enabled)"
        else:
            tls = "Final destination is not HTTPS"
            notes.append("The final destination does not use HTTPS.")
        for name in ["Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options",
                     "X-Frame-Options", "Referrer-Policy"]:
            headers_result[name] = resp.headers.get(name, "Missing")
            if name not in resp.headers:
                notes.append(f"Missing security header: {name}")
        if resp.status_code >= 400:
            notes.append(f"HTTP status: {resp.status_code}")
    except requests.exceptions.SSLError:
        tls = "TLS certificate validation failed"
        notes.append("Do not enter sensitive information until the certificate issue is investigated.")
    except Exception as exc:
        notes.append(f"Connection check failed: {exc.__class__.__name__}")
    level, detail = threatintel.assess(url)
    if level != "none":
        notes.insert(0, f"THREAT INTEL: {level.upper()} - {detail}")
    with db() as con:
        con.execute("INSERT INTO security_checks(checked_at,url,https,tls,headers,notes) VALUES(?,?,?,?,?,?)",
                    (now(), url, https, tls, json.dumps(headers_result), "; ".join(notes)))
    return {"url": url, "https": https, "tls": tls, "headers": headers_result, "notes": notes,
            "intel": (level, detail)}


def export_csv():
    out = REPORT_DIR / f"log_use_websites_{datetime.now():%Y%m%d_%H%M%S}.csv"
    with db() as con:
        rows = con.execute("SELECT visit_time,browser,url,domain,threat_level,threat_detail,resolved_ip,"
                           "ip_checked_at FROM websites ORDER BY id DESC").fetchall()
    with out.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["Visit time", "Browser", "URL", "Domain", "Threat level", "Threat detail",
                    "Resolved IP (current lookup)", "IP checked at"])
        w.writerows([tuple(r) for r in rows])
    return out


def export_logons_csv():
    out = REPORT_DIR / f"log_use_windows_signins_{datetime.now():%Y%m%d_%H%M%S}.csv"
    with db() as con:
        rows = con.execute("SELECT event_time,event_id,kind,username,domain,logon_desc,source_ip,workstation,"
                           "status,photo FROM logon_events ORDER BY event_time DESC").fetchall()
    with out.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["Time", "Event ID", "Event", "User", "Domain", "Sign-in type", "Source IP",
                    "Workstation", "Failure reason", "Photo"])
        w.writerows([tuple(r) for r in rows])
    return out


# --------------------------------------------------------------------------- GUI
class LogUseApp:
    def __init__(self, root, args, monitor, ui_q):
        self.root, self.args, self.monitor, self.q = root, args, monitor, ui_q
        self.user_email = None
        self.alert_count = 0
        self.popup_open = False
        root.title(f"LOG USE - Cybersecurity Monitor {VERSION}")
        root.geometry("1180x760")
        root.minsize(1000, 650)
        root.configure(bg=BG)
        try:
            root.iconbitmap(core.resource_path("assets/log_use.ico"))
        except Exception:
            pass
        st = ttk.Style()
        try:
            st.theme_use("clam")
        except Exception:
            pass
        st.configure("TNotebook", background=BG, borderwidth=0)
        st.configure("TNotebook.Tab", background="#17212b", foreground=TEXT, padding=(14, 8))
        st.map("TNotebook.Tab", background=[("selected", "#00a884")], foreground=[("selected", "#ffffff")])
        st.configure("Treeview", background=PANEL, foreground="#e6edf3", fieldbackground=PANEL, rowheight=26)
        st.configure("Treeview.Heading", background="#1c2935", foreground="#ffffff")
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.show_auth()
        root.after(1000, self.pump)
        if args.logon or self.started_by_signin():
            root.iconify()                       # visible in the taskbar, not hidden
            root.after(2500, self.logon_flow)

    def logo(self, factor):
        """Logo image from assets/logo.png (kept referenced so Tk does not discard it)."""
        try:
            img = tk.PhotoImage(file=core.resource_path("assets/logo.png")).subsample(factor, factor)
            self._logos = getattr(self, "_logos", []) + [img]
            return img
        except Exception:
            return None

    def started_by_signin(self):
        """Packaged startup tasks cannot pass --logon: treat a start within 3 min of sign-in as sign-in."""
        if not core.is_packaged():
            return False
        try:
            import psutil
            me = os.getenv("USERNAME", "").lower()
            starts = [u.started for u in psutil.users() if u.name.lower() == me]
            import time
            return bool(starts) and (time.time() - min(starts)) < 180
        except Exception:
            return False

    def offer_signin_setup(self):
        """First run: ask once for permission to read Windows sign-in events (one UAC prompt)."""
        if get_setting("signin_setup_prompted") == "1":
            return
        set_setting("signin_setup_prompted", "1")
        if messagebox.askyesno(
                "Windows sign-in monitoring",
                "To show exact Windows sign-in events, LOG USE needs a one-time permission:\n"
                "  - turn on Windows sign-in auditing\n  - allow you to read the Security log\n\n"
                "Windows will ask you to confirm. Continue?"):
            if winevents.enable_signin_monitoring():
                messagebox.showinfo("Almost done", "Done. Please sign out of Windows and sign in once "
                                                   "so the permission takes effect.")

    # widgets ---------------------------------------------------------------
    def label(self, parent, text, size=10, color=TEXT, bold=False, **kw):
        return tk.Label(parent, text=text, bg=parent.cget("bg"), fg=color,
                        font=("Segoe UI", size, "bold" if bold else "normal"), **kw)

    def entry(self, parent, show=None, pack=True):
        e = tk.Entry(parent, show=show, bg="#17212b", fg="#ffffff", insertbackground="white",
                     relief="flat", font=("Segoe UI", 11))
        if pack:
            e.pack(fill="x", ipady=8, pady=4)
        return e

    def button(self, parent, text, command, color="#00a884"):
        return tk.Button(parent, text=text, command=command, bg=color, fg="white",
                         activebackground="#087f68", activeforeground="white", relief="flat",
                         font=("Segoe UI", 10, "bold"), padx=14, pady=8, cursor="hand2")

    def tree(self, parent, cols):
        frame = tk.Frame(parent, bg=BG)
        t = ttk.Treeview(frame, columns=[c[0] for c in cols], show="headings")
        for key, title, width in cols:
            t.heading(key, text=title)
            t.column(key, width=width, anchor="w")
        sb = ttk.Scrollbar(frame, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=sb.set)
        t.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        t.tag_configure("malicious", background="#5a1d22", foreground="#ffd7d7")
        t.tag_configure("suspicious", background="#4d3b12", foreground="#ffe9b0")
        t.tag_configure("failed", background="#5a1d22", foreground="#ffd7d7")
        t.tag_configure("ok", background="#10301f", foreground="#c9f2dc")
        return frame, t

    # authentication --------------------------------------------------------
    def show_auth(self):
        for w in self.root.winfo_children():
            w.destroy()
        outer = tk.Frame(self.root, bg=BG)
        outer.pack(expand=True)
        card = tk.Frame(outer, bg=PANEL, padx=38, pady=32)
        card.pack()
        img = self.logo(3)
        if img:
            tk.Label(card, image=img, bg=PANEL).pack(pady=(0, 6))
        self.label(card, "LOG USE", 27, ACCENT, True).pack(pady=(0, 4))
        self.label(card, "PERSONAL CYBERSECURITY MONITOR", 9, MUTED, True).pack(pady=(0, 22))
        self.label(card, "Email address").pack(anchor="w")
        email = self.entry(card)
        self.label(card, "Password").pack(anchor="w")
        pw = self.entry(card, "•")

        def login(_=None):
            if core.authenticate(email.get(), pw.get()):
                self.user_email = email.get().strip().lower()
                self.show_dashboard()
            else:
                messagebox.showerror("Login failed", "Incorrect email or password.")
        pw.bind("<Return>", login)
        self.button(card, "SIGN IN", login).pack(fill="x", pady=(14, 8))
        row = tk.Frame(card, bg=PANEL)
        row.pack(fill="x")
        tk.Button(row, text="Create account", command=lambda: self.auth_dialog("register"),
                  bg=PANEL, fg=ACCENT, relief="flat").pack(side="left")
        tk.Button(row, text="Forgot password?", command=lambda: self.auth_dialog("reset"),
                  bg=PANEL, fg="#9bb0c2", relief="flat").pack(side="right")
        mon = "ACTIVE" if get_setting("live_monitor") == "1" else "PAUSED"
        self.label(card, f"Visible monitoring • Local data only • Live monitoring: {mon}",
                   8, "#728596").pack(pady=(18, 0))

    def auth_dialog(self, mode):
        win = tk.Toplevel(self.root)
        win.withdraw()
        win.configure(bg=PANEL)
        win.resizable(False, False)
        win.title("Create account" if mode == "register" else "Password recovery")
        win.transient(self.root)
        f = tk.Frame(win, bg=PANEL, padx=24, pady=22)
        f.pack(fill="both", expand=True)
        self.label(f, "Email address").pack(anchor="w")
        em = self.entry(f)
        if mode == "register":
            self.label(f, "Password (minimum 10 characters)").pack(anchor="w")
            pw = self.entry(f, "•")

            def submit():
                try:
                    core.register_user(em.get(), pw.get())
                    messagebox.showinfo("Account created", "You can now sign in.", parent=win)
                    win.destroy()
                except Exception as ex:
                    messagebox.showerror("Registration", str(ex), parent=win)
            self.button(f, "CREATE ACCOUNT", submit).pack(fill="x", pady=10)
        else:
            self.label(f, "OTP code").pack(anchor="w")
            otp = self.entry(f)
            self.label(f, "New password (minimum 10 characters)").pack(anchor="w")
            pw = self.entry(f, "•")

            def send():
                try:
                    messagebox.showinfo("OTP", core.request_otp(em.get()), parent=win)
                except Exception as ex:
                    messagebox.showerror("Email setup", str(ex), parent=win)

            def reset():
                try:
                    core.reset_password(em.get(), otp.get(), pw.get())
                    messagebox.showinfo("Password reset", "Password updated. Please sign in.", parent=win)
                    win.destroy()
                except Exception as ex:
                    messagebox.showerror("Password reset", str(ex), parent=win)
            self.button(f, "SEND OTP", send, "#286a9b").pack(fill="x", pady=5)
            self.button(f, "RESET PASSWORD", reset).pack(fill="x", pady=5)

        # Center the dialog over the main application window.
        win.update_idletasks()
        self.root.update_idletasks()
        dialog_w, dialog_h = win.winfo_reqwidth(), win.winfo_reqheight()
        parent_x, parent_y = self.root.winfo_rootx(), self.root.winfo_rooty()
        parent_w, parent_h = self.root.winfo_width(), self.root.winfo_height()
        x = parent_x + max(0, (parent_w - dialog_w) // 2)
        y = parent_y + max(0, (parent_h - dialog_h) // 2)
        win.geometry(f"{dialog_w}x{dialog_h}+{x}+{y}")
        win.deiconify()
        win.grab_set()
        win.focus_set()

    # dashboard -------------------------------------------------------------
    def show_dashboard(self):
        for w in self.root.winfo_children():
            w.destroy()
        head = tk.Frame(self.root, bg="#101923", padx=20, pady=12)
        head.pack(fill="x")
        img = self.logo(8)
        if img:
            tk.Label(head, image=img, bg="#101923").pack(side="left", padx=(0, 10))
        self.label(head, "LOG USE", 20, ACCENT, True).pack(side="left")
        self.status_lbl = self.label(head, "", 9, "#a9bac8")
        self.status_lbl.pack(side="right")
        self.label(head, f"Signed in: {self.user_email}   |   ", 9, "#a9bac8").pack(side="right")
        self.banner = tk.Label(self.root, text="", bg="#5a1d22", fg="#ffd7d7", font=("Segoe UI", 10, "bold"),
                               anchor="w", padx=18, pady=6)
        tabs = ttk.Notebook(self.root)
        tabs.pack(fill="both", expand=True, padx=16, pady=10)
        self.tabs = tabs
        names = ["Dashboard", "Windows sign-ins", "Website history", "Threat intelligence",
                 "Website security", "Activity", "Settings"]
        self.tab = {}
        for n in names:
            self.tab[n] = tk.Frame(tabs, bg=BG)
            tabs.add(self.tab[n], text=n)
        self.build_dashboard()
        self.build_signins()
        self.build_web()
        self.build_intel()
        self.build_security()
        self.build_activity()
        self.build_settings()
        log_event("DASHBOARD_OPENED", self.user_email)
        self.refresh_all()

    def refresh_all(self):
        self.refresh_stats()
        self.refresh_signins()
        self.refresh_web()
        self.refresh_intel()
        self.refresh_activity()

    def build_dashboard(self):
        t = self.tab["Dashboard"]
        for i in range(5):
            t.grid_columnconfigure(i, weight=1)
        self.cards = {}
        for i, (key, title) in enumerate([("web", "WEBSITE RECORDS"), ("sign", "WINDOWS SIGN-IN EVENTS"),
                                          ("fail", "FAILED SIGN-INS"), ("threat", "THREAT ALERTS"),
                                          ("act", "ACTIVITY EVENTS")]):
            f = tk.Frame(t, bg=CARD, padx=16, pady=14)
            f.grid(row=0, column=i, padx=6, pady=12, sticky="ew")
            self.label(f, title, 8, MUTED, True).pack(anchor="w")
            self.cards[key] = self.label(f, "0", 22, ACCENT, True)
            self.cards[key].pack(anchor="w", pady=(6, 0))
        box = tk.Frame(t, bg=PANEL, padx=18, pady=14)
        box.grid(row=1, column=0, columnspan=5, sticky="ew", padx=6, pady=6)
        self.live_var = tk.BooleanVar(value=get_setting("live_monitor") == "1")
        self.logon_var = tk.BooleanVar(value=get_setting("logon_monitor") == "1")
        self.auto_var = tk.BooleanVar(value=self.safe_autostart())
        for var, text, cmd in [
            (self.live_var, "Continuous live monitoring of browsers + live threat checks", self.toggle_live),
            (self.logon_var, "Read Windows sign-in events (Security log)", self.toggle_logon),
            (self.auto_var, "Start LOG USE (visibly) every time I sign in to Windows", self.toggle_autostart)]:
            tk.Checkbutton(box, text=text, variable=var, command=cmd, bg=PANEL, fg=TEXT, selectcolor="#17212b",
                           activebackground=PANEL, activeforeground=TEXT, font=("Segoe UI", 10)).pack(anchor="w")
        actions = tk.Frame(t, bg=BG)
        actions.grid(row=2, column=0, columnspan=5, sticky="ew", padx=4, pady=8)
        for text, cmd, color in [("IMPORT BROWSER HISTORY NOW", self.do_import, "#00a884"),
                                 ("READ SIGN-IN EVENTS NOW", self.do_read_signins, "#286a9b"),
                                 ("UPDATE THREAT FEEDS", self.do_update_feeds, "#286a9b"),
                                 ("RESOLVE WEBSITE IPs", self.do_resolve, "#475569"),
                                 ("CAMERA PHOTO (ASKS FIRST)", self.camera_manual, "#8a5b22")]:
            self.button(actions, text, cmd, color).pack(side="left", padx=4, pady=4)
        self.health = self.label(t, "", 9, "#9aabba", justify="left", anchor="w")
        self.health.grid(row=3, column=0, columnspan=5, sticky="w", padx=12, pady=10)

    def safe_autostart(self):
        try:
            return core.autostart_enabled()
        except Exception:
            return False

    def toggle_live(self):
        set_setting("live_monitor", "1" if self.live_var.get() else "0")
        log_event("LIVE_MONITOR", "enabled" if self.live_var.get() else "paused")
        self.refresh_stats()

    def toggle_logon(self):
        set_setting("logon_monitor", "1" if self.logon_var.get() else "0")
        log_event("LOGON_MONITOR", "enabled" if self.logon_var.get() else "disabled")

    def toggle_autostart(self):
        if core.is_packaged():
            self.auto_var.set(True)
            messagebox.showinfo("Start at sign-in",
                                "LOG USE starts at sign-in through Windows' own startup list.\n\n"
                                "To switch it off or on: Windows Settings > Apps > Startup > LOG USE.")
            if os.name == "nt":
                os.startfile("ms-settings:startupapps")
            return
        try:
            core.set_autostart(self.auto_var.get())
        except Exception as ex:
            messagebox.showerror("Start at sign-in", str(ex))
            self.auto_var.set(self.safe_autostart())

    def refresh_stats(self):
        if not hasattr(self, "cards"):
            return
        with db() as con:
            one = lambda sql: con.execute(sql).fetchone()[0]
            vals = {"web": one("SELECT COUNT(*) FROM websites"),
                    "sign": one("SELECT COUNT(*) FROM logon_events"),
                    "fail": one("SELECT COUNT(*) FROM logon_events WHERE event_id=4625"),
                    "threat": one("SELECT COUNT(*) FROM threat_alerts"),
                    "act": one("SELECT COUNT(*) FROM activity")}
        for k, v in vals.items():
            self.cards[k].config(text=str(v))
        mon = self.monitor
        state = "ACTIVE" if get_setting("live_monitor") == "1" else "PAUSED"
        self.status_lbl.config(text=f"Live monitoring: {state}   |   last check: {mon.last_poll or 'pending'}")
        perm = camera.camera_permission()
        counts = threatintel.intel_counts()
        lines = [f"Camera: {perm['text']}",
                 f"Threat feeds: {sum(counts.values()):,} indicators loaded "
                 f"(last update: {get_setting('intel_last_update', '') or 'never'})"]
        if mon.winlog_error:
            lines.append("Windows sign-in log: " + mon.winlog_error)
        if mon.last_error:
            lines.append("Browser monitor note: " + mon.last_error)
        if hasattr(self, "health"):
            self.health.config(text="\n".join(lines))

    # actions ---------------------------------------------------------------
    def busy(self, work, done):
        def run():
            try:
                res, err = work(), None
            except Exception as ex:
                res, err = None, ex
            self.root.after(0, lambda: done(res, err))
        threading.Thread(target=run, daemon=True).start()

    def do_import(self):
        def done(res, err):
            if err:
                return messagebox.showerror("Import failed", str(err))
            n, alerts, errors = res
            for sev, url, detail in alerts:
                self.raise_alert(sev, url, detail)
            self.refresh_all()
            msg = f"Collected {n} new browser history records."
            if errors:
                msg += "\n\nCould not read: " + ", ".join(errors) + "\n(Close that browser and retry.)"
            messagebox.showinfo("Import complete", msg)
        self.busy(browsers.import_all, done)

    def do_read_signins(self):
        def done(res, err):
            if err:
                return messagebox.showerror("Sign-in events", str(err))
            rows, e = res
            self.refresh_all()
            if e:
                messagebox.showwarning("Windows sign-in events", e)
            else:
                messagebox.showinfo("Windows sign-in events", f"{len(rows)} new events collected.")
        self.busy(winevents.collect_logon_events, done)

    def do_update_feeds(self):
        def done(res, err):
            if err:
                return messagebox.showerror("Threat feeds", str(err))
            changed = res[1]
            self.refresh_all()
            lines = [f"{n}: " + (f"{c:,} entries" if c else f"FAILED ({e})") for n, c, e in res[0]]
            messagebox.showinfo("Threat feeds", "\n".join(lines) + f"\n\nHistory re-checked: {changed} changed.")

        def work():
            r = threatintel.update_feeds()
            return r, threatintel.rescan_websites()
        self.busy(work, done)

    def do_resolve(self):
        def done(res, err):
            self.refresh_all()
            messagebox.showinfo("IP lookup", f"Processed {res or 0} records. These are current DNS results, "
                                             "not guaranteed historical IPs.")
        self.busy(resolve_website_ips, done)

    def camera_manual(self):
        perm = camera.camera_permission()
        if not perm.get("ok", True):
            if messagebox.askyesno("Camera permission", perm["text"] + "\n\nOpen Windows camera settings now?"):
                camera.open_camera_settings()
            return
        if not messagebox.askyesno("Camera consent",
                                   "LOG USE will switch on your camera and save ONE photo on this PC. Continue?"):
            return

        def done(path, err):
            if err:
                messagebox.showerror("Camera", str(err))
            else:
                messagebox.showinfo("Photo saved", f"Saved:\n{path}")
            self.refresh_all()
        self.busy(lambda: camera.capture_photo("manual"), done)

    # sign-ins tab ----------------------------------------------------------
    def build_signins(self):
        t = self.tab["Windows sign-ins"]
        bar = tk.Frame(t, bg=BG)
        bar.pack(fill="x", padx=8, pady=8)
        self.button(bar, "READ EVENTS NOW", self.do_read_signins).pack(side="left", padx=4)
        self.button(bar, "EXPORT CSV", lambda: messagebox.showinfo("Saved", str(export_logons_csv())),
                    "#475569").pack(side="left", padx=4)
        self.label(bar, "Double-click a row with a photo to open it.", 9, MUTED).pack(side="left", padx=10)
        f, self.sign_tree = self.tree(t, [("time", "Time", 160), ("kind", "Event", 170), ("user", "User", 150),
                                         ("type", "Sign-in type", 190), ("ip", "Source IP", 120),
                                         ("why", "Failure reason", 190), ("photo", "Photo", 120)])
        f.pack(fill="both", expand=True, padx=8, pady=6)
        self.sign_tree.bind("<Double-1>", self.open_photo)

    def refresh_signins(self):
        if not hasattr(self, "sign_tree"):
            return
        self.sign_tree.delete(*self.sign_tree.get_children())
        with db() as con:
            rows = con.execute("SELECT * FROM logon_events ORDER BY event_time DESC, id DESC LIMIT 1500").fetchall()
        for r in rows:
            tag = "failed" if r["event_id"] == 4625 else ("ok" if r["event_id"] == 4624 else "")
            user = f"{r['domain']}\\{r['username']}" if r["domain"] else r["username"]
            self.sign_tree.insert("", "end", values=(r["event_time"], r["kind"], user, r["logon_desc"],
                                                     r["source_ip"], r["status"], r["photo"] or ""), tags=(tag,))

    def open_photo(self, _):
        sel = self.sign_tree.selection()
        if sel:
            p = self.sign_tree.item(sel[0])["values"][-1]
            if p and os.path.exists(str(p)) and os.name == "nt":
                os.startfile(str(p))

    # website history tab ---------------------------------------------------
    def build_web(self):
        t = self.tab["Website history"]
        bar = tk.Frame(t, bg=BG)
        bar.pack(fill="x", padx=8, pady=8)
        self.button(bar, "IMPORT NOW", self.do_import).pack(side="left", padx=4)
        self.button(bar, "RESOLVE IPs", self.do_resolve, "#286a9b").pack(side="left", padx=4)
        self.button(bar, "EXPORT CSV", lambda: messagebox.showinfo("Saved", str(export_csv())),
                    "#475569").pack(side="left", padx=4)
        self.only_threats = tk.BooleanVar(value=False)
        tk.Checkbutton(bar, text="Show only threats", variable=self.only_threats, command=self.refresh_web,
                       bg=BG, fg=TEXT, selectcolor="#17212b", activebackground=BG,
                       activeforeground=TEXT).pack(side="left", padx=12)
        f, self.web_tree = self.tree(t, [("time", "Visit time", 150), ("browser", "Browser", 80),
                                        ("threat", "Threat", 85), ("domain", "Domain", 170),
                                        ("ip", "Resolved IP (current)", 140), ("url", "URL", 420)])
        f.pack(fill="both", expand=True, padx=8, pady=6)

    def refresh_web(self):
        if not hasattr(self, "web_tree"):
            return
        self.web_tree.delete(*self.web_tree.get_children())
        where = "WHERE threat_level IN ('malicious','suspicious')" if self.only_threats.get() else ""
        with db() as con:
            rows = con.execute(f"SELECT visit_time,browser,threat_level,domain,resolved_ip,url FROM websites "
                               f"{where} ORDER BY visit_time DESC LIMIT 1500").fetchall()
        for r in rows:
            lvl = r["threat_level"] or "none"
            self.web_tree.insert("", "end", tags=(lvl,), values=(
                r["visit_time"], r["browser"], "" if lvl == "none" else lvl.upper(),
                r["domain"], r["resolved_ip"] or "", r["url"]))

    # threat intelligence tab -----------------------------------------------
    def build_intel(self):
        t = self.tab["Threat intelligence"]
        bar = tk.Frame(t, bg=BG)
        bar.pack(fill="x", padx=8, pady=8)
        self.button(bar, "UPDATE FEEDS NOW", self.do_update_feeds).pack(side="left", padx=4)
        self.label(bar, "Check a domain with VirusTotal:", 9, MUTED).pack(side="left", padx=(16, 4))
        self.vt_entry = tk.Entry(bar, bg="#17212b", fg="white", insertbackground="white", relief="flat",
                                 font=("Segoe UI", 11), width=28)
        self.vt_entry.pack(side="left", ipady=6)
        self.button(bar, "CHECK", self.do_vt, "#286a9b").pack(side="left", padx=6)
        self.intel_info = self.label(t, "", 9, "#9aabba", justify="left", anchor="w")
        self.intel_info.pack(fill="x", padx=12)
        f, self.alert_tree = self.tree(t, [("time", "Time", 150), ("sev", "Severity", 90),
                                          ("src", "Source", 150), ("ind", "Indicator", 330), ("det", "Detail", 380)])
        f.pack(fill="both", expand=True, padx=8, pady=6)

    def refresh_intel(self):
        if not hasattr(self, "alert_tree"):
            return
        counts = threatintel.intel_counts()
        txt = "Loaded indicators: " + (", ".join(f"{k}: {v:,}" for k, v in counts.items()) or
                                       "none yet - press UPDATE FEEDS NOW (needs internet)")
        self.intel_info.config(text=txt + "\nNo match does NOT prove a site is safe.")
        self.alert_tree.delete(*self.alert_tree.get_children())
        with db() as con:
            rows = con.execute("SELECT * FROM threat_alerts ORDER BY id DESC LIMIT 500").fetchall()
        for r in rows:
            self.alert_tree.insert("", "end", tags=(r["severity"],),
                                   values=(r["alert_time"], r["severity"].upper(), r["source"],
                                           r["indicator"], r["detail"]))

    def do_vt(self):
        dom = self.vt_entry.get().strip().lower()
        if not dom:
            return
        dom = urlparse(dom if "//" in dom else "//" + dom).hostname or dom

        def done(res, err):
            messagebox.showinfo("VirusTotal", res) if not err else messagebox.showerror("VirusTotal", str(err))
        self.busy(lambda: threatintel.virustotal_domain(dom), done)

    # security tab ----------------------------------------------------------
    def build_security(self):
        t = self.tab["Website security"]
        top = tk.Frame(t, bg=BG)
        top.pack(fill="x", padx=12, pady=12)
        self.label(top, "Website URL").pack(anchor="w")
        self.url_entry = tk.Entry(top, bg="#17212b", fg="white", insertbackground="white", relief="flat",
                                  font=("Segoe UI", 11))
        self.url_entry.pack(fill="x", ipady=8, pady=6)
        self.button(top, "CHECK WEBSITE SECURITY", self.do_security).pack(anchor="w", pady=4)
        self.sec_out = tk.Text(t, bg=PANEL, fg=TEXT, insertbackground="white", relief="flat", wrap="word")
        self.sec_out.pack(fill="both", expand=True, padx=12, pady=8)

    def do_security(self):
        url = self.url_entry.get().strip()
        if not url:
            return messagebox.showwarning("Website", "Enter a website URL.")
        self.sec_out.delete("1.0", "end")
        self.sec_out.insert("end", "Checking... (basic configuration + threat-list check, not a guarantee of safety)\n")

        def done(r, err):
            self.sec_out.delete("1.0", "end")
            if err:
                return self.sec_out.insert("end", f"Check failed: {err}")
            lines = [f"URL: {r['url']}", f"HTTPS requested: {r['https']}", f"TLS: {r['tls']}",
                     f"Threat lists: {r['intel'][0].upper()} {r['intel'][1]}", "", "SECURITY HEADERS:"]
            lines += [f"{k}: {v}" for k, v in r["headers"].items()]
            lines += ["", "OBSERVATIONS:"] + (r["notes"] or ["No issues found by this basic test."])
            self.sec_out.insert("end", "\n".join(lines))
            self.refresh_stats()
        self.busy(lambda: check_website(url), done)

    # activity tab ----------------------------------------------------------
    def build_activity(self):
        f, self.act_tree = self.tree(self.tab["Activity"], [("time", "Time", 200), ("type", "Event", 200),
                                                           ("det", "Details", 650)])
        f.pack(fill="both", expand=True, padx=8, pady=8)

    def refresh_activity(self):
        if not hasattr(self, "act_tree"):
            return
        self.act_tree.delete(*self.act_tree.get_children())
        with db() as con:
            rows = con.execute("SELECT event_time,event_type,details FROM activity ORDER BY id DESC LIMIT 800").fetchall()
        for r in rows:
            self.act_tree.insert("", "end", values=tuple(r))

    # settings tab ----------------------------------------------------------
    def build_settings(self):
        t = self.tab["Settings"]
        canvas = tk.Frame(t, bg=BG)
        canvas.pack(fill="both", expand=True, padx=16, pady=10)
        left = tk.Frame(canvas, bg=BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 20))
        right = tk.Frame(canvas, bg=BG)
        right.pack(side="left", fill="both", expand=True)
        self.set_vars = {}

        def field(parent, key, title, secret=False):
            self.label(parent, title, 9, MUTED).pack(anchor="w", pady=(8, 0))
            e = self.entry(parent, "•" if secret else None)
            e.insert(0, get_setting(key))
            self.set_vars[key] = e

        self.label(left, "Camera at Windows sign-in", 12, ACCENT, True).pack(anchor="w")
        self.cam_mode = tk.StringVar(value=get_setting("camera_mode"))
        for val, txt in [("prompt", "Ask me each time (recommended)"),
                         ("auto", "Automatic photo after a visible countdown that I can cancel"),
                         ("off", "Never use the camera at sign-in")]:
            tk.Radiobutton(left, text=txt, variable=self.cam_mode, value=val, bg=BG, fg=TEXT, selectcolor="#17212b",
                           activebackground=BG, activeforeground=TEXT).pack(anchor="w")
        field(left, "auto_delay", "Countdown seconds (automatic mode)")
        field(left, "poll_seconds", "Browser check interval (seconds, minimum 5)")
        field(left, "intel_update_hours", "Update threat feeds every (hours)")
        field(left, "vt_api_key", "VirusTotal API key (optional)", True)
        row = tk.Frame(left, bg=BG)
        row.pack(anchor="w", pady=12)
        self.button(row, "CHECK CAMERA PERMISSION", self.check_cam, "#286a9b").pack(side="left", padx=(0, 6))
        self.button(row, "OPEN WINDOWS CAMERA SETTINGS", camera.open_camera_settings, "#475569").pack(side="left")
        row2 = tk.Frame(left, bg=BG)
        row2.pack(anchor="w")
        self.button(row2, "ENABLE WINDOWS SIGN-IN MONITORING", lambda: winevents.enable_signin_monitoring(),
                    "#286a9b").pack(side="left")
        self.label(right, "Email for password reset (SMTP)", 12, ACCENT, True).pack(anchor="w")
        field(right, "smtp_host", "SMTP server (e.g. smtp.gmail.com)")
        field(right, "smtp_port", "Port (587 or 465)")
        field(right, "smtp_user", "Email username")
        field(right, "smtp_password", "App password (stored encrypted for this Windows user)", True)
        field(right, "smtp_from", "From address (optional)")
        actions = tk.Frame(right, bg=BG)
        actions.pack(anchor="w", pady=14)
        self.button(actions, "SAVE SETTINGS", self.save_settings).pack(side="left", padx=(0, 8))
        self.button(actions, "SEND TEST EMAIL", self.test_smtp, "#286a9b").pack(side="left")

    def save_settings(self):
        try:
            if int(self.set_vars["poll_seconds"].get()) < 5:
                raise ValueError("Browser check interval must be 5 seconds or more.")
            int(self.set_vars["auto_delay"].get())
            float(self.set_vars["intel_update_hours"].get())
        except ValueError as ex:
            return messagebox.showerror("Settings", str(ex) if "Browser" in str(ex) else "Numbers only, please.")
        set_setting("camera_mode", self.cam_mode.get())
        for k, e in self.set_vars.items():
            set_setting(k, e.get().strip())
        log_event("SETTINGS_SAVED", "")
        messagebox.showinfo("Settings", "Saved.")

    def test_smtp(self):
        try:
            for key in ("smtp_host", "smtp_port", "smtp_user", "smtp_password", "smtp_from"):
                set_setting(key, self.set_vars[key].get().strip())
            recipient = self.set_vars["smtp_from"].get().strip() or self.set_vars["smtp_user"].get().strip()
            if not recipient:
                raise ValueError("Enter the SMTP username or From address first.")
            core.send_email(recipient, "LOG USE SMTP test",
                            "This is a test message. Your LOG USE SMTP settings are working.")
            messagebox.showinfo("SMTP test", f"Test email sent to {recipient}.")
        except Exception as ex:
            messagebox.showerror("SMTP test failed", str(ex))

    def check_cam(self):
        p = camera.camera_permission()
        messagebox.showinfo("Camera permission", p["text"] + ("" if p.get("ok") else
                            "\n\nClick 'Open Windows camera settings' and switch the options on."))

    # alerts & event pump ---------------------------------------------------
    def raise_alert(self, sev, indicator, detail):
        self.alert_count += 1
        if hasattr(self, "banner"):
            self.banner.config(text=f"  {sev.upper()} THREAT: {indicator[:90]}  -  {detail[:110]}"
                                    f"   ({self.alert_count} this session - see 'Threat intelligence')")
            self.banner.pack(fill="x", before=self.tabs)
        if sev == "malicious" and not self.popup_open:
            self.popup_open = True
            try:
                self.root.deiconify()
                self.root.bell()
                messagebox.showwarning("LOG USE - threat detected",
                                       f"{indicator}\n\n{detail}\n\nDo not enter passwords or download files "
                                       "from this site/address.")
            finally:
                self.popup_open = False

    def pump(self):
        try:
            while True:
                msg = self.q.get_nowait()
                if msg[0] == "alert":
                    self.raise_alert(msg[1], msg[2], msg[3])
                if msg[0] == "logon":
                    bad = [r for r in msg[1] if r["event_id"] == 4625]
                    if bad and hasattr(self, "banner"):
                        self.banner.config(text=f"  {len(bad)} failed Windows sign-in attempt(s) detected "
                                                f"- see 'Windows sign-ins'")
                        self.banner.pack(fill="x", before=self.tabs)
                if hasattr(self, "cards"):
                    self.refresh_all()
        except queue.Empty:
            pass
        if hasattr(self, "cards"):
            self.refresh_stats()
            if "denied" in (self.monitor.winlog_error or "").lower():
                self.offer_signin_setup()
        self.root.after(3000, self.pump)

    # Windows sign-in flow + camera prompt ----------------------------------
    def logon_flow(self):
        def work():
            rows, err = winevents.collect_logon_events()
            me = os.getenv("USERNAME", "")
            return winevents.latest_signin(me), err
        self.busy(work, self.show_logon_dialog)

    def show_logon_dialog(self, res, err):
        sign, error = (res if res else (None, str(err)))
        last_seen = get_setting("last_logon_prompt", "")
        failed = winevents.failed_since(last_seen) if last_seen else []
        set_setting("last_logon_prompt", now())
        mode = get_setting("camera_mode")
        win = tk.Toplevel(self.root)
        win.title("LOG USE - Windows sign-in detected")
        win.configure(bg=PANEL)
        win.attributes("-topmost", True)
        win.resizable(False, False)
        f = tk.Frame(win, bg=PANEL, padx=28, pady=22)
        f.pack()
        self.label(f, "Windows sign-in detected", 16, ACCENT, True).pack(anchor="w")
        if sign:
            self.label(f, f"User: {sign['domain']}\\{sign['username']}\nTime: {sign['event_time']}\n"
                          f"Type: {sign['logon_desc']}   (Windows Security event {sign['event_id']})",
                       10, justify="left").pack(anchor="w", pady=8)
        else:
            self.label(f, f"User: {os.getenv('USERNAME', '?')}\nSession started: {winevents.session_fallback()}\n"
                          "(Exact Security-log details unavailable)", 10, justify="left").pack(anchor="w", pady=8)
            if error:
                self.label(f, error, 9, "#ffb86b", wraplength=420, justify="left").pack(anchor="w")
        if failed:
            self.label(f, f"WARNING: {len(failed)} failed sign-in attempt(s) since LOG USE last ran.\n"
                          f"Most recent: {failed[0]['event_time']} ({failed[0]['status'] or 'failure'})",
                       10, "#ff8f8f", True, justify="left").pack(anchor="w", pady=6)
        status = self.label(f, "", 10, "#9fd8c8", wraplength=420, justify="left")
        row = tk.Frame(f, bg=PANEL)

        def close():
            win.destroy()

        def take(reason="logon"):
            perm = camera.camera_permission()
            if not perm.get("ok", True):
                status.config(text=perm["text"] + " Opening Windows camera settings...")
                camera.open_camera_settings()
                return
            status.config(text="Camera is ON - taking one photo...")
            win.update()

            def done(path, e):
                if e:
                    status.config(text=f"Camera error: {e}", fg="#ff8f8f")
                    return
                if sign:
                    with db() as con:
                        con.execute("UPDATE logon_events SET photo=? WHERE id=?", (path, sign["id"]))
                status.config(text=f"Photo saved:\n{path}")
                self.refresh_signins()
            self.busy(lambda: camera.capture_photo(reason), done)

        if mode == "off":
            self.button(row, "CLOSE", close).pack(side="left")
        elif mode == "prompt":
            self.label(f, "Take a photo with the camera to record who signed in?", 10).pack(anchor="w", pady=(10, 4))
            self.button(row, "TAKE PHOTO", take).pack(side="left", padx=(0, 8))
            self.button(row, "SKIP", close, "#475569").pack(side="left")
        else:                                           # auto, with visible, cancelable countdown
            try:
                n = max(3, int(get_setting("auto_delay")))
            except ValueError:
                n = 10
            state = {"left": n, "cancel": False}
            self.button(row, "CANCEL", lambda: (state.update(cancel=True), status.config(text="Cancelled."))
                        , "#475569").pack(side="left")
            self.button(row, "TAKE PHOTO NOW", lambda: (state.update(cancel=True), take("logon"))).pack(side="left", padx=8)

            def tick():
                if state["cancel"] or not win.winfo_exists():
                    return
                if state["left"] <= 0:
                    state["cancel"] = True
                    return take("logon_auto")
                status.config(text=f"Camera photo will be taken in {state['left']} s. Press CANCEL to stop.")
                state["left"] -= 1
                win.after(1000, tick)
            tick()
        status.pack(anchor="w", pady=8)
        row.pack(anchor="w", pady=6)
        log_event("LOGON_PROMPT_SHOWN", f"camera_mode={mode}")
        win.deiconify()
        win.lift()
        self.root.deiconify()

    # closing ---------------------------------------------------------------
    def on_close(self):
        if get_setting("live_monitor") == "1":
            ans = messagebox.askyesnocancel(
                "Close LOG USE?",
                "Closing LOG USE STOPS live monitoring.\n\nYes = close and stop\nNo = minimize and keep monitoring",
            )
            if ans is None:
                return
            if ans is False:
                self.root.iconify()
                return
        self.monitor.stop()
        log_event("APP_CLOSED", "")
        self.root.destroy()


# ---------------------------------------------------------------------- startup
def single_instance():
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", LOCK_PORT))
        s.listen(1)
        return s
    except OSError:
        return None


def main():
    ap = argparse.ArgumentParser(prog=APP_NAME)
    ap.add_argument("--logon", action="store_true", help="started by Windows sign-in")
    ap.add_argument("--enable-autostart", action="store_true")
    ap.add_argument("--disable-autostart", action="store_true")
    ap.add_argument("--version", action="store_true")
    args, _ = ap.parse_known_args()
    init_db()
    if args.version:
        print(VERSION)
        return
    if args.enable_autostart or args.disable_autostart:
        try:
            core.set_autostart(args.enable_autostart)
        except Exception as ex:
            log_event("AUTOSTART_ERROR", str(ex))
        return
    lock = single_instance()
    if lock is None:
        try:
            r = tk.Tk(); r.withdraw()
            messagebox.showinfo(APP_NAME, "LOG USE is already running. Look for it in the taskbar.")
        except Exception:
            pass
        return
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    log_event("APP_STARTED", "--logon" if args.logon else "manual start")
    ui_q = queue.Queue()
    mon = LiveMonitor(ui_q)
    mon.start()
    root = tk.Tk()
    LogUseApp(root, args, mon, ui_q)
    root.mainloop()


if __name__ == "__main__":
    main()
