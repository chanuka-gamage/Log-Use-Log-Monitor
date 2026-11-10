"""LOG USE core: paths, database, settings, account/OTP handling, autostart.

Everything is stored locally under %LOCALAPPDATA%\\LOG USE (override with LOGUSE_HOME).
"""
import os
import re
import sys
import ssl
import base64
import hashlib
import secrets
import sqlite3
import smtplib
from contextlib import contextmanager
from datetime import datetime, timedelta
from email.message import EmailMessage
from pathlib import Path

APP_NAME = "LOG USE"
VERSION = "2.0.0"


def _base_dir():
    return Path(os.getenv("LOCALAPPDATA") or (Path.home() / ".local" / "share"))


APP_DIR = Path(os.getenv("LOGUSE_HOME") or (_base_dir() / "LOG USE"))
DB_PATH = APP_DIR / "log_use.db"
REPORT_DIR = APP_DIR / "reports"
PHOTO_DIR = APP_DIR / "photos"
for _d in (APP_DIR, REPORT_DIR, PHOTO_DIR):
    _d.mkdir(parents=True, exist_ok=True)


def is_packaged() -> bool:
    """True when running from the MSIX / App Installer package (registry + AppData are sandboxed)."""
    if os.name != "nt":
        return False
    try:
        import ctypes
        length = ctypes.c_uint32(0)
        # 15700 = APPMODEL_ERROR_NO_PACKAGE
        return ctypes.windll.kernel32.GetCurrentPackageFullName(ctypes.byref(length), None) != 15700
    except Exception:
        return False


def resource_path(rel):
    """Path to a bundled resource (works from source and from a PyInstaller build)."""
    base = getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)
    return str(Path(base) / rel)


# --------------------------------------------------------------------------- DB
@contextmanager
def db():
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS otp_records(
    email TEXT NOT NULL, otp_hash TEXT NOT NULL, expires_at TEXT NOT NULL, used INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS activity(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_time TEXT NOT NULL, event_type TEXT NOT NULL, details TEXT
);
CREATE TABLE IF NOT EXISTS websites(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    visit_time TEXT, browser TEXT, url TEXT NOT NULL, domain TEXT,
    resolved_ip TEXT, ip_checked_at TEXT
);
CREATE TABLE IF NOT EXISTS security_checks(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    checked_at TEXT, url TEXT, https TEXT, tls TEXT, headers TEXT, notes TEXT
);
CREATE TABLE IF NOT EXISTS logon_events(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id INTEGER NOT NULL, event_id INTEGER NOT NULL,
    event_time TEXT, kind TEXT, username TEXT, domain TEXT,
    logon_type INTEGER, logon_desc TEXT, source_ip TEXT, workstation TEXT,
    status TEXT, photo TEXT,
    UNIQUE(record_id, event_id)
);
CREATE TABLE IF NOT EXISTS intel(
    indicator TEXT NOT NULL, kind TEXT NOT NULL, source TEXT NOT NULL, added_at TEXT,
    PRIMARY KEY(indicator, kind, source)
);
CREATE TABLE IF NOT EXISTS threat_alerts(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_time TEXT, severity TEXT, indicator TEXT, source TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
"""


def init_db():
    with db() as con:
        try:
            con.execute("PRAGMA journal_mode=WAL")
        except sqlite3.DatabaseError:
            pass
        con.executescript(SCHEMA)
        cols = {r["name"] for r in con.execute("PRAGMA table_info(websites)")}
        for col in ("threat_level", "threat_detail"):
            if col not in cols:
                con.execute(f"ALTER TABLE websites ADD COLUMN {col} TEXT")
        # v1 imported duplicates on every run; collapse them, then enforce uniqueness.
        con.execute("""DELETE FROM websites WHERE id NOT IN
                       (SELECT MIN(id) FROM websites GROUP BY browser,url,visit_time)""")
        con.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_site ON websites(browser,url,visit_time)")
        con.execute("CREATE INDEX IF NOT EXISTS ix_site_domain ON websites(domain)")
        con.execute("CREATE INDEX IF NOT EXISTS ix_intel_kind ON intel(kind)")


def now():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def log_event(event_type, details=""):
    with db() as con:
        con.execute("INSERT INTO activity(event_time,event_type,details) VALUES(?,?,?)",
                    (now(), event_type, details))


# --------------------------------------------------------------- secret storage
def _dpapi(data: bytes, protect: bool) -> bytes:
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = BLOB()
    fn = ctypes.windll.crypt32.CryptProtectData if protect else ctypes.windll.crypt32.CryptUnprotectData
    ok = fn(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out))
    if not ok:
        raise OSError("DPAPI call failed")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def protect_text(text: str) -> str:
    """Encrypt with Windows DPAPI (tied to this Windows user). Plain base64 off-Windows (dev only)."""
    if not text:
        return ""
    raw = text.encode()
    if os.name == "nt":
        return "dpapi:" + base64.b64encode(_dpapi(raw, True)).decode()
    return "b64:" + base64.b64encode(raw).decode()


def unprotect_text(value: str) -> str:
    if not value:
        return ""
    try:
        if value.startswith("dpapi:"):
            return _dpapi(base64.b64decode(value[6:]), False).decode()
        if value.startswith("b64:"):
            return base64.b64decode(value[4:]).decode()
    except Exception:
        return ""
    return value


SECRET_KEYS = {"smtp_password", "vt_api_key"}
DEFAULTS = {
    "live_monitor": "1",        # continuous browser monitoring while the app is open
    "poll_seconds": "30",
    "logon_monitor": "1",       # read Windows Security log
    "camera_mode": "prompt",    # prompt | auto | off
    "auto_delay": "10",         # visible countdown (seconds) before an "auto" capture
    "intel_auto_update": "1",
    "intel_update_hours": "12",
    "smtp_host": "", "smtp_port": "587", "smtp_user": "", "smtp_password": "", "smtp_from": "",
    "vt_api_key": "",
}


def get_setting(key, default=None):
    with db() as con:
        row = con.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    value = row["value"] if row else DEFAULTS.get(key, default if default is not None else "")
    return unprotect_text(value) if key in SECRET_KEYS else value


def set_setting(key, value):
    value = str(value)
    if key in SECRET_KEYS:
        value = protect_text(value)
    with db() as con:
        con.execute("INSERT INTO settings(key,value) VALUES(?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


# ------------------------------------------------------------------ accounts/OTP
def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 310000)
    return digest.hex(), salt


def verify_password(password, saved_hash, salt):
    return secrets.compare_digest(hash_password(password, salt)[0], saved_hash)


def smtp_config():
    try:
        port = int(get_setting("smtp_port") or os.getenv("LOGUSE_SMTP_PORT", "587") or 587)
    except (TypeError, ValueError):
        raise ValueError("SMTP port must be 587 (STARTTLS) or 465 (SSL).")
    cfg = {
        "host": (get_setting("smtp_host") or os.getenv("LOGUSE_SMTP_HOST", "")).strip(),
        "port": port,
        "user": (get_setting("smtp_user") or os.getenv("LOGUSE_SMTP_USER", "")).strip(),
        "password": get_setting("smtp_password") or os.getenv("LOGUSE_SMTP_PASSWORD", ""),
    }
    cfg["sender"] = (get_setting("smtp_from") or os.getenv("LOGUSE_FROM_EMAIL", "") or cfg["user"]).strip()
    if not all([cfg["host"], cfg["user"], cfg["password"], cfg["sender"]]):
        raise RuntimeError("SMTP is not configured. Enter SMTP server, port, email username, and email app-password in Settings, then save.")
    if cfg["port"] not in (465, 587):
        raise ValueError("Use SMTP port 587 (STARTTLS) or 465 (SSL).")
    return cfg


def send_email(to, subject, body):
    c = smtp_config()
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, c["sender"], to
    msg.set_content(body)
    ctx = ssl.create_default_context()
    try:
        if c["port"] == 465:
            with smtplib.SMTP_SSL(c["host"], c["port"], timeout=20, context=ctx) as server:
                server.login(c["user"], c["password"])
                server.send_message(msg)
        else:
            with smtplib.SMTP(c["host"], c["port"], timeout=20) as server:
                server.ehlo()
                server.starttls(context=ctx)
                server.ehlo()
                server.login(c["user"], c["password"])
                server.send_message(msg)
    except smtplib.SMTPAuthenticationError as exc:
        raise RuntimeError("SMTP login was rejected. For Gmail, enable 2-Step Verification and use a Google App Password, not your normal account password. Check username and app-password.") from exc
    except (smtplib.SMTPConnectError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"Could not connect to SMTP server {c['host']}:{c['port']}. Check server name, port, internet connection, and firewall.") from exc
    except smtplib.SMTPException as exc:
        raise RuntimeError(f"SMTP server error: {exc}") from exc


def request_otp(email):
    email = email.strip().lower()
    if not re.fullmatch(r"[^@\\s]+@[^@\\s]+\\.[^@\\s]+", email):
        raise ValueError("Enter a valid email address.")
    with db() as con:
        user = con.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if not user:
        return "If the account exists, an OTP email has been sent."
    otp = f"{secrets.randbelow(1000000):06d}"
    otp_hash, salt = hash_password(otp)
    # Store only after delivery succeeds, so a failed SMTP attempt cannot leave an active OTP.
    send_email(email, "LOG USE password reset code",
               f"Your LOG USE password reset code is {otp}. It expires in 10 minutes.")
    with db() as con:
        con.execute("UPDATE otp_records SET used=1 WHERE email=? AND used=0", (email,))
        con.execute("INSERT INTO otp_records(email,otp_hash,expires_at,used) VALUES(?,?,?,0)",
                    (email, otp_hash + ":" + salt,
                     (datetime.now() + timedelta(minutes=10)).isoformat()))
    return "OTP sent. Check your email."


def reset_password(email, otp, new_password):
    email = email.strip().lower()
    if len(new_password) < 10:
        raise ValueError("Use a password with at least 10 characters.")
    with db() as con:
        row = con.execute("""SELECT rowid,* FROM otp_records
            WHERE email=? AND used=0 ORDER BY rowid DESC LIMIT 1""", (email,)).fetchone()
        if not row:
            raise ValueError("No active OTP was found.")
        if datetime.fromisoformat(row["expires_at"]) < datetime.now():
            raise ValueError("OTP expired. Request a new one.")
        saved_hash, salt = row["otp_hash"].split(":")
        if not verify_password(otp.strip(), saved_hash, salt):
            raise ValueError("Incorrect OTP.")
        pw_hash, pw_salt = hash_password(new_password)
        con.execute("UPDATE users SET password_hash=?,salt=? WHERE email=?", (pw_hash, pw_salt, email))
        con.execute("UPDATE otp_records SET used=1 WHERE rowid=?", (row["rowid"],))
    log_event("PASSWORD_RESET", email)


def register_user(email, password):
    email = email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ValueError("Enter a valid email address.")
    if len(password) < 10:
        raise ValueError("Password must contain at least 10 characters.")
    pw_hash, salt = hash_password(password)
    try:
        with db() as con:
            con.execute("INSERT INTO users(email,password_hash,salt,created_at) VALUES(?,?,?,?)",
                        (email, pw_hash, salt, now()))
    except sqlite3.IntegrityError:
        raise ValueError("An account with this email already exists.")
    log_event("ACCOUNT_CREATED", email)


def authenticate(email, password):
    email = email.strip().lower()
    with db() as con:
        row = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if row and verify_password(password, row["password_hash"], row["salt"]):
        log_event("APP_LOGIN", email)
        return True
    log_event("FAILED_APP_LOGIN", email)
    return False


# ---------------------------------------------------------------- start at logon
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_NAME = "LOG USE"


def _launch_command():
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --logon'
    return f'"{sys.executable}" "{Path(sys.argv[0]).resolve()}" --logon'


def set_autostart(enabled: bool):
    """Start LOG USE (visibly) every time this Windows user signs in. Per-user, no admin needed."""
    if os.name != "nt":
        raise OSError("Start-at-logon is only available on Windows.")
    if is_packaged():
        raise OSError("PACKAGED")
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
        if enabled:
            winreg.SetValueEx(k, RUN_NAME, 0, winreg.REG_SZ, _launch_command())
        else:
            try:
                winreg.DeleteValue(k, RUN_NAME)
            except FileNotFoundError:
                pass
    log_event("AUTOSTART_" + ("ENABLED" if enabled else "DISABLED"), "")


def autostart_enabled() -> bool:
    if os.name != "nt":
        return False
    if is_packaged():
        return True                      # package startup task (switch in Settings > Apps > Startup)
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            winreg.QueryValueEx(k, RUN_NAME)
            return True
    except OSError:
        return False
