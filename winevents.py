"""Exact Windows authentication events from the Security event log.

Uses the built-in `wevtutil` tool (no extra libraries). Reading the Security log needs either
Administrator rights or membership of the "Event Log Readers" group (the installer adds the
installing user to that group; it takes effect at the next Windows sign-in).
"""
import os
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from core import db, get_setting, set_setting, log_event, now

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

EVENT_KIND = {
    4624: "Sign-in SUCCESS",
    4625: "Sign-in FAILED",
    4647: "Sign-out (user initiated)",
    4634: "Sign-out",
    4800: "Workstation LOCKED",
    4801: "Workstation UNLOCKED",
}
LOGON_TYPES = {
    2: "Interactive (keyboard/screen)", 3: "Network (remote share)", 7: "Unlock",
    10: "Remote Desktop", 11: "Cached interactive",
}
KEEP_4624_TYPES = {2, 3, 7, 10, 11}
STATUS_TEXT = {
    "0xc000006a": "Wrong password", "0xc0000064": "Unknown user name",
    "0xc000006d": "Bad user name or authentication info", "0xc0000234": "Account locked out",
    "0xc0000072": "Account disabled", "0xc0000070": "Workstation restriction",
    "0xc0000071": "Password expired", "0xc000006f": "Outside permitted hours",
    "0xc000015b": "Logon type not granted", "0xc0000133": "Clock difference",
    "0xc000006e": "Account restriction", "0xc0000193": "Account expired",
}
SKIP_USERS = {"system", "local service", "network service", "anonymous logon", "-", ""}
BATCH = 500
FIRST_RUN_DAYS = 7


def is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _xpath(last_id: int) -> str:
    ids = " or ".join(f"EventID={i}" for i in EVENT_KIND)
    if last_id > 0:
        return f"*[System[({ids}) and EventRecordID>{last_id}]]"
    ms = FIRST_RUN_DAYS * 24 * 3600 * 1000
    return f"*[System[({ids}) and TimeCreated[timediff(@SystemTime)<={ms}]]]"


def _run_wevtutil(xpath: str):
    cmd = ["wevtutil", "qe", "Security", f"/q:{xpath}", f"/c:{BATCH}", "/rd:false", "/f:xml"]
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=60, creationflags=flags)
    return p.returncode, p.stdout, p.stderr


def _local_time(system_time: str) -> str:
    try:
        s = system_time.rstrip("Z")
        if "." in s:
            head, frac = s.split(".")
            s = f"{head}.{frac[:6]}"
        dt = datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
        return dt.astimezone().isoformat(timespec="seconds")
    except Exception:
        return system_time


def parse_events(xml_text: str):
    """Return (rows_to_store, max_record_id_seen)."""
    if not xml_text.strip():
        return [], 0
    root = ET.fromstring("<Events>" + xml_text + "</Events>")
    rows, max_id = [], 0
    for ev in root.findall("e:Event", NS):
        sysn = ev.find("e:System", NS)
        eid = int(sysn.findtext("e:EventID", "0", NS))
        rid = int(sysn.findtext("e:EventRecordID", "0", NS))
        max_id = max(max_id, rid)
        stamp = sysn.find("e:TimeCreated", NS).get("SystemTime", "")
        d = {x.get("Name"): (x.text or "") for x in ev.findall("e:EventData/e:Data", NS)}
        user = d.get("TargetUserName", "")
        domain = d.get("TargetDomainName", "")
        if user.lower() in SKIP_USERS or user.endswith("$") or user.upper().startswith(("DWM-", "UMFD-")):
            continue
        try:
            ltype = int(d.get("LogonType", "0") or 0)
        except ValueError:
            ltype = 0
        ip = d.get("IpAddress", "") or ""
        if ip in ("-", "::1", "127.0.0.1"):
            ip = ""
        status = ""
        if eid == 4624:
            if ltype not in KEEP_4624_TYPES:
                continue
            if ltype == 3 and not ip:      # local network-style noise
                continue
        elif eid == 4625:
            code = (d.get("SubStatus") or d.get("Status") or "").lower()
            status = STATUS_TEXT.get(code, code or "Failure")
        elif eid == 4634:
            if ltype not in (2, 7, 10, 11):
                continue
        rows.append({
            "record_id": rid, "event_id": eid, "event_time": _local_time(stamp),
            "kind": EVENT_KIND[eid], "username": user, "domain": domain,
            "logon_type": ltype or None, "logon_desc": LOGON_TYPES.get(ltype, ""),
            "source_ip": ip, "workstation": d.get("WorkstationName", "") if eid == 4625 else "",
            "status": status,
        })
    return rows, max_id


def collect_logon_events():
    """Read new events, store them, return (new_rows, error_message_or_None)."""
    if os.name != "nt":
        return [], "Windows event log is only available on Windows."
    last = int(get_setting("winevent_last_id", "0") or 0)
    new_rows, error = [], None
    for _ in range(40):                       # safety cap: 40 * 500 events per call
        try:
            code, out, err = _run_wevtutil(_xpath(last))
        except Exception as exc:
            error = f"Could not run wevtutil: {exc}"
            break
        if code != 0:
            if "denied" in (err or "").lower() or code == 5:
                error = ("Access to the Windows Security log was denied. Sign out and back in once "
                         "(the installer added you to 'Event Log Readers'), or start LOG USE with "
                         "'Run as administrator'.")
            else:
                error = (err or "wevtutil failed").strip()[:300]
            break
        rows, max_id = parse_events(out)
        if max_id == 0:
            break
        with db() as con:
            for r in rows:
                cur = con.execute(
                    """INSERT OR IGNORE INTO logon_events(record_id,event_id,event_time,kind,username,
                       domain,logon_type,logon_desc,source_ip,workstation,status)
                       VALUES(:record_id,:event_id,:event_time,:kind,:username,:domain,:logon_type,
                       :logon_desc,:source_ip,:workstation,:status)""", r)
                if cur.rowcount:
                    new_rows.append(r)
        last = max(last, max_id)
        set_setting("winevent_last_id", last)
        if max_id and len(out) and out.count("<Event ") < BATCH:
            break
    if new_rows:
        log_event("WINDOWS_AUTH_EVENTS", f"{len(new_rows)} new Security-log events")
    return new_rows, error


def session_fallback():
    """Used when the Security log is not readable: Windows session start via psutil."""
    try:
        import psutil
        me = os.getenv("USERNAME", "").lower()
        starts = [u.started for u in psutil.users() if u.name.lower() == me] or [psutil.boot_time()]
        return datetime.fromtimestamp(min(starts)).astimezone().isoformat(timespec="seconds")
    except Exception:
        return ""


def latest_signin(username: str = ""):
    """Most recent successful interactive sign-in/unlock (optionally for one user)."""
    sql = ("SELECT * FROM logon_events WHERE event_id=4624 AND logon_type IN (2,7,10,11) "
           + ("AND lower(username)=lower(?) " if username else "")
           + "ORDER BY event_time DESC, id DESC LIMIT 1")
    with db() as con:
        return con.execute(sql, (username,) if username else ()).fetchone()


def failed_since(iso_time: str):
    with db() as con:
        return con.execute("SELECT * FROM logon_events WHERE event_id=4625 AND event_time>? "
                           "ORDER BY event_time DESC", (iso_time or "",)).fetchall()


def enable_signin_monitoring() -> bool:
    """One-time setup with ONE Windows UAC prompt: turn on sign-in auditing and let this user read
    the Security log (adds the user to 'Event Log Readers'). Returns True if the prompt was accepted."""
    if os.name != "nt":
        return False
    import ctypes
    user = os.getenv("USERNAME", "").replace("'", "''")
    # Audit sub-category GUIDs work on every Windows language: Logon, Logoff, Other Logon/Logoff Events
    G_LOGON, G_LOGOFF, G_OTHER = ("{0CCE9215-69AE-11D9-BED3-505054503030}",
                                  "{0CCE9216-69AE-11D9-BED3-505054503030}",
                                  "{0CCE921C-69AE-11D9-BED3-505054503030}")
    params = (f"/c auditpol /set /subcategory:{G_LOGON} /success:enable /failure:enable"
              f" & auditpol /set /subcategory:{G_LOGOFF} /success:enable"
              f" & auditpol /set /subcategory:{G_OTHER} /success:enable /failure:enable"
              f" & powershell -NoProfile -WindowStyle Hidden -Command "
              f"\"Add-LocalGroupMember -SID S-1-5-32-573 -Member '{user}' -ErrorAction SilentlyContinue\"")
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", "cmd.exe", params, None, 0)  # 0 = hidden window
    if rc > 32:
        log_event("SIGNIN_MONITORING_SETUP", "elevated setup started")
        return True
    return False
