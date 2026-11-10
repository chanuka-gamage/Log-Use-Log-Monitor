"""Browser history reader for Chrome, Edge, Brave, Vivaldi, Opera, Opera GX, Chromium and Firefox.

Read-only: copies each browser's local history database to a temp folder and reads the copy.
Incremental: remembers the newest visit already collected per browser profile, so it can be
called every few seconds for continuous monitoring.
"""
import os
import shutil
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from core import db, get_setting, set_setting, log_event
import threatintel

UTC = timezone.utc
CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
FIRST_RUN_DAYS = 30
MAX_ROWS = 20000


def chromium_roots():
    local = Path(os.getenv("LOCALAPPDATA", ""))
    roaming = Path(os.getenv("APPDATA", ""))
    return [
        ("Chrome", local / "Google/Chrome/User Data"),
        ("Edge", local / "Microsoft/Edge/User Data"),
        ("Brave", local / "BraveSoftware/Brave-Browser/User Data"),
        ("Vivaldi", local / "Vivaldi/User Data"),
        ("Chromium", local / "Chromium/User Data"),
        ("Opera", roaming / "Opera Software/Opera Stable"),
        ("Opera GX", roaming / "Opera Software/Opera GX Stable"),
    ]


def find_sources():
    """List (browser, kind, history_file, profile_name) for every profile found."""
    out = []
    for name, root in chromium_roots():
        if not root.exists():
            continue
        if (root / "History").exists():                 # Opera keeps History in the root
            out.append((name, "chromium", root / "History", "Default"))
        for prof in list(root.glob("Default")) + list(root.glob("Profile *")):
            if (prof / "History").exists():
                out.append((name, "chromium", prof / "History", prof.name))
    ff = Path(os.getenv("APPDATA", "")) / "Mozilla/Firefox/Profiles"
    if ff.exists():
        for prof in ff.iterdir():
            if (prof / "places.sqlite").exists():
                out.append(("Firefox", "firefox", prof / "places.sqlite", prof.name))
    return out


def _chromium_to_iso(raw):
    return (CHROME_EPOCH + timedelta(microseconds=raw)).astimezone().isoformat(timespec="seconds")


def _unix_us_to_iso(raw):
    return datetime.fromtimestamp(raw / 1_000_000, tz=UTC).astimezone().isoformat(timespec="seconds")


def _copy_db(src: Path, tmpdir: Path) -> Path:
    dst = tmpdir / "h.sqlite"
    shutil.copy2(src, dst)
    for suffix in ("-wal", "-shm"):                     # recent visits may still be in the WAL file
        side = Path(str(src) + suffix)
        if side.exists():
            try:
                shutil.copy2(side, Path(str(dst) + suffix))
            except OSError:
                pass
    return dst


def _read_rows(browser, kind, path, last_raw):
    """Return list of (url, raw_time) newer than last_raw, oldest first."""
    with tempfile.TemporaryDirectory(prefix="loguse_") as td:
        copy = _copy_db(path, Path(td))
        con = sqlite3.connect(f"file:{copy}?mode=ro", uri=True)
        try:
            if kind == "chromium":
                if last_raw is None:
                    since = datetime.now(UTC) - timedelta(days=FIRST_RUN_DAYS)
                    last_raw = int((since - CHROME_EPOCH).total_seconds() * 1_000_000)
                q = ("SELECT u.url, v.visit_time FROM visits v JOIN urls u ON u.id=v.url "
                     "WHERE v.visit_time>? ORDER BY v.visit_time ASC LIMIT ?")
            else:
                if last_raw is None:
                    last_raw = int((datetime.now(UTC) - timedelta(days=FIRST_RUN_DAYS)).timestamp() * 1_000_000)
                q = ("SELECT p.url, h.visit_date FROM moz_historyvisits h JOIN moz_places p "
                     "ON p.id=h.place_id WHERE h.visit_date>? ORDER BY h.visit_date ASC LIMIT ?")
            return con.execute(q, (last_raw, MAX_ROWS)).fetchall()
        finally:
            con.close()


def poll_once():
    """Collect new visits from all browsers. Returns (new_count, alerts, errors).

    alerts: list of (severity, url, detail) that are new (not alerted in the last 24 h).
    """
    new_count, alerts, errors = 0, [], []
    for browser, kind, path, profile in find_sources():
        state_key = f"hist:{browser}:{profile}"
        raw_last = get_setting(state_key, "")
        last = int(raw_last) if raw_last else None
        try:
            rows = _read_rows(browser, kind, path, last)
        except Exception as exc:
            errors.append(f"{browser}/{profile}: {exc.__class__.__name__}")
            continue
        if not rows:
            continue
        flagged = []
        with db() as con:
            for url, raw in rows:
                if not url.lower().startswith(("http://", "https://")):
                    continue
                when = _chromium_to_iso(raw) if kind == "chromium" else _unix_us_to_iso(raw)
                level, detail = threatintel.assess(url)
                cur = con.execute(
                    """INSERT OR IGNORE INTO websites(visit_time,browser,url,domain,threat_level,threat_detail)
                       VALUES(?,?,?,?,?,?)""",
                    (when, browser, url, urlparse(url).hostname or "", level, detail))
                if cur.rowcount:
                    new_count += 1
                    if level in ("malicious", "suspicious"):
                        flagged.append((level, url, detail))
        for level, url, detail in flagged:               # after the DB transaction is closed
            if threatintel.add_alert(level, url, f"{browser} history", detail):
                alerts.append((level, url, detail))
        set_setting(state_key, rows[-1][1])
    return new_count, alerts, errors


def import_all():
    """Manual 'Import now' button: same incremental logic."""
    n, alerts, errors = poll_once()
    log_event("BROWSER_HISTORY_IMPORT", f"{n} new records; {len(errors)} source errors")
    return n, alerts, errors
