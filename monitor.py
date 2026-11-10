"""Background monitor thread: live browsers + Windows sign-in events + threat feeds.

It runs only while the LOG USE window is open (the window stays visible in the taskbar), and it
can be paused from the Dashboard. Results are pushed to the GUI through a queue.
"""
import threading
import time
import queue

from core import get_setting, log_event, now
import browsers
import threatintel
import winevents


class LiveMonitor(threading.Thread):
    def __init__(self, ui_queue: "queue.Queue"):
        super().__init__(daemon=True, name="LogUseMonitor")
        self.q = ui_queue
        self.stop_evt = threading.Event()
        self.last_poll = ""
        self.last_error = ""
        self.winlog_error = ""

    def stop(self):
        self.stop_evt.set()

    # one tick of each task -------------------------------------------------
    def _browsers(self):
        n, alerts, errors = browsers.poll_once()
        self.last_poll = now()
        self.last_error = "; ".join(errors)
        for sev, url, detail in alerts:
            self.q.put(("alert", sev, url, detail))
        if n:
            self.q.put(("websites", n))

    def _logon(self):
        rows, err = winevents.collect_logon_events()
        self.winlog_error = err or ""
        if rows:
            self.q.put(("logon", rows))

    def _connections(self):
        for ip, port, proc, src in threatintel.check_live_connections():
            if threatintel.add_alert("malicious", f"{ip}:{port}", "live connection",
                                     f"{proc} is connected to a known botnet server ({src})"):
                self.q.put(("alert", "malicious", f"{ip}:{port}",
                            f"Process '{proc}' is connected to a known botnet server ({src})"))

    def _intel(self):
        if threatintel.feeds_due():
            res = threatintel.update_feeds()
            changed = threatintel.rescan_websites()
            self.q.put(("intel", res, changed))

    def run(self):
        threatintel.reload()
        t_logon = t_conn = 0.0
        while not self.stop_evt.is_set():
            tick = time.monotonic()
            try:
                if get_setting("live_monitor") == "1":
                    self._browsers()
                if get_setting("logon_monitor") == "1" and tick - t_logon >= 30:
                    t_logon = tick
                    self._logon()
                if get_setting("live_monitor") == "1" and tick - t_conn >= 60:
                    t_conn = tick
                    self._connections()
                self._intel()
            except Exception as exc:                       # never let the thread die silently
                self.last_error = f"{exc.__class__.__name__}: {exc}"
                try:
                    log_event("MONITOR_ERROR", self.last_error)
                except Exception:
                    pass
            try:
                wait = max(5, int(get_setting("poll_seconds") or 30))
            except ValueError:
                wait = 30
            self.stop_evt.wait(wait)
