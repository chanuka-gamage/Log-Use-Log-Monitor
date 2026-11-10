"""Threat intelligence: public blocklist feeds, URL heuristics, live-connection check, VirusTotal.

Feeds are public, free lists. If a feed is unreachable the app keeps working with the others.
A "no match" result NEVER means a site is safe - it only means it is not on the loaded lists.
"""
import re
import ipaddress
import threading
from datetime import datetime, timedelta
from urllib.parse import urlparse

from core import db, get_setting, set_setting, log_event, now

FEEDS = [
    # name, url, kind of indicator
    ("URLhaus (malware URLs)", "https://urlhaus.abuse.ch/downloads/text_online/", "url"),
    ("OpenPhish (phishing URLs)", "https://openphish.com/feed.txt", "url"),
    ("Phishing Army (phishing domains)", "https://phishing.army/download/phishing_army_blocklist.txt", "domain"),
    ("Feodo Tracker (botnet C2 IPs)", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "ip"),
]

_lock = threading.Lock()
_cache = None


def _norm_url(u: str) -> str:
    u = u.strip().split("#")[0]
    return u.rstrip("/").lower()


def _load():
    global _cache
    with _lock:
        c = {"url": set(), "domain": {}, "ip": {}}
        with db() as con:
            for r in con.execute("SELECT indicator,kind,source FROM intel"):
                if r["kind"] == "url":
                    c["url"].add(r["indicator"])
                else:
                    c[r["kind"]].setdefault(r["indicator"], r["source"])
        _cache = c
    return _cache


def reload():
    return _load()


def intel_counts():
    with db() as con:
        return {r["source"]: r["n"] for r in con.execute(
            "SELECT source, COUNT(*) n FROM intel GROUP BY source")}


def update_feeds(progress=None):
    """Download all feeds. Returns list of (feed_name, count_or_None, error_or_None)."""
    import requests
    results = []
    for name, url, kind in FEEDS:
        try:
            r = requests.get(url, timeout=40, headers={"User-Agent": "LOG-USE-ThreatIntel/2.0"})
            r.raise_for_status()
            items = set()
            for line in r.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                token = line.split()[0]
                if kind == "url":
                    if re.match(r"^https?://", token, re.I):
                        items.add(_norm_url(token))
                elif kind == "domain":
                    items.add(token.lower().lstrip("*."))
                else:
                    try:
                        ipaddress.ip_address(token)
                        items.add(token)
                    except ValueError:
                        pass
            if not items:
                raise RuntimeError("feed returned no usable entries")
            stamp = now()
            with db() as con:
                con.execute("DELETE FROM intel WHERE source=?", (name,))
                con.executemany("INSERT OR IGNORE INTO intel(indicator,kind,source,added_at) VALUES(?,?,?,?)",
                                [(i, kind, name, stamp) for i in items])
            results.append((name, len(items), None))
        except Exception as exc:
            results.append((name, None, f"{exc.__class__.__name__}: {str(exc)[:120]}"))
        if progress:
            progress(results[-1])
    set_setting("intel_last_update", now())
    reload()
    ok = sum(1 for _, n, _ in results if n)
    log_event("THREAT_FEEDS_UPDATED", f"{ok}/{len(FEEDS)} feeds updated")
    return results


def feeds_due() -> bool:
    if get_setting("intel_auto_update") != "1":
        return False
    last = get_setting("intel_last_update", "")
    if not last:
        return True
    try:
        hours = float(get_setting("intel_update_hours") or 12)
        return datetime.now().astimezone() - datetime.fromisoformat(last) > timedelta(hours=hours)
    except Exception:
        return True


# ------------------------------------------------------------------- heuristics
BRANDS = ["google", "microsoft", "paypal", "apple", "amazon", "facebook", "instagram", "netflix",
          "whatsapp", "linkedin", "github", "dropbox", "outlook", "office365", "icloud", "binance",
          "coinbase", "twitter", "telegram", "youtube", "gmail", "yahoo", "dhl", "fedex", "hsbc"]
SUSPICIOUS_TLDS = {"zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "click", "loan", "work",
                   "rest", "fit", "cam", "icu", "monster", "buzz"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
              "rebrand.ly", "shorturl.at"}
LURE_WORDS = ("login", "signin", "verify", "secure", "account", "update", "wallet", "banking",
              "confirm", "password", "suspend", "recover")
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}


def _lev(a, b):
    if abs(len(a) - len(b)) > 1:
        return 2
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def registrable(host: str):
    p = host.split(".")
    if len(p) >= 3 and len(p[-1]) == 2 and p[-2] in SECOND_LEVEL:
        return ".".join(p[-3:]), p[-3]
    if len(p) >= 2:
        return ".".join(p[-2:]), p[-2]
    return host, host


def _is_ip(host):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def heuristic_score(url: str):
    """Return (score, reasons). >=3 is reported as 'suspicious'."""
    p = urlparse(url)
    host = (p.hostname or "").lower()
    score, why = 0, []
    if not host:
        return 0, why
    ip = _is_ip(host)
    if ip is not None:
        if not (ip.is_private or ip.is_loopback or ip.is_link_local):
            score += 2; why.append("site address is a raw IP, not a name")
        return score, why
    if "@" in (p.netloc or ""):
        score += 3; why.append("URL contains '@' (hides the real destination)")
    if any(lbl.startswith("xn--") for lbl in host.split(".")):
        score += 2; why.append("punycode (look-alike characters) in domain")
    if host.count(".") >= 4:
        score += 1; why.append("unusually many sub-domains")
    if host.count("-") >= 4:
        score += 1; why.append("many hyphens in domain")
    if host.split(".")[-1] in SUSPICIOUS_TLDS:
        score += 1; why.append(f"high-abuse top-level domain .{host.split('.')[-1]}")
    if host in SHORTENERS:
        score += 1; why.append("URL shortener hides the destination")
    reg, sld = registrable(host)
    for b in BRANDS:
        if sld == b:
            break
        if _lev(sld, b) == 1 and len(sld) >= 5:
            score += 3; why.append(f"domain looks like '{b}' (typo-squatting)"); break
        if b in host.replace("-", "") and not host.endswith(f"{b}.com"):
            score += 2; why.append(f"uses brand name '{b}' on an unrelated domain"); break
    if any(w in host for w in LURE_WORDS):
        score += 1; why.append("phishing-style word in domain")
    if p.scheme == "http" and any(w in (p.path or "").lower() for w in ("login", "signin", "password")):
        score += 1; why.append("login page without HTTPS")
    if len(url) > 200:
        score += 1; why.append("very long URL")
    if len(re.findall(r"%[0-9a-fA-F]{2}", url)) > 8:
        score += 1; why.append("heavily encoded URL")
    return score, why


def assess(url: str):
    """Return (level, detail). level: 'malicious' | 'suspicious' | 'none'."""
    c = _cache or _load()
    p = urlparse(url)
    host = (p.hostname or "").lower()
    if not host:
        return "none", ""
    if _norm_url(url) in c["url"]:
        return "malicious", "Listed in a malware/phishing URL feed"
    if host in c["ip"]:
        return "malicious", f"IP is on botnet list ({c['ip'][host]})"
    parts = host.split(".")
    for i in range(len(parts) - 1):
        cand = ".".join(parts[i:])
        if cand in c["domain"]:
            return "malicious", f"Domain on blocklist ({c['domain'][cand]})"
    score, why = heuristic_score(url)
    if score >= 3:
        return "suspicious", "; ".join(why)
    return "none", ("; ".join(why) if why else "")


def add_alert(severity, indicator, source, detail) -> bool:
    """Store an alert; returns False if the same indicator already alerted in the last 24 h."""
    cutoff = (datetime.now().astimezone() - timedelta(hours=24)).isoformat(timespec="seconds")
    with db() as con:
        dup = con.execute("SELECT 1 FROM threat_alerts WHERE indicator=? AND source=? AND alert_time>?",
                          (indicator, source, cutoff)).fetchone()
        if dup:
            return False
        con.execute("INSERT INTO threat_alerts(alert_time,severity,indicator,source,detail) VALUES(?,?,?,?,?)",
                    (now(), severity, indicator, source, detail))
    return True


def rescan_websites():
    """Re-assess stored history after the feeds changed. Returns number of rows changed."""
    reload()
    changed, flagged = 0, []
    with db() as con:
        rows = con.execute("SELECT id,url,threat_level FROM websites ORDER BY id DESC LIMIT 50000").fetchall()
        for r in rows:
            level, detail = assess(r["url"])
            if level != (r["threat_level"] or "none"):
                con.execute("UPDATE websites SET threat_level=?,threat_detail=? WHERE id=?",
                            (level, detail, r["id"]))
                changed += 1
                if level == "malicious":
                    flagged.append((r["url"], detail))
    for url, detail in flagged:
        add_alert("malicious", url, "history rescan", detail)
    return changed


def check_live_connections():
    """Compare this PC's established outbound connections with the botnet-IP feed."""
    hits = []
    try:
        import psutil
    except ImportError:
        return hits
    c = _cache or _load()
    if not c["ip"]:
        return hits
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return hits
    for conn in conns:
        if conn.status != "ESTABLISHED" or not conn.raddr:
            continue
        ip = conn.raddr.ip
        if ip in c["ip"]:
            try:
                proc = psutil.Process(conn.pid).name() if conn.pid else "unknown"
            except Exception:
                proc = "unknown"
            hits.append((ip, conn.raddr.port, proc, c["ip"][ip]))
    return hits


def virustotal_domain(domain: str):
    """Optional: query VirusTotal v3 (needs a free API key in Settings). Returns summary text."""
    import requests
    key = get_setting("vt_api_key")
    if not key:
        raise RuntimeError("Add a VirusTotal API key in Settings first (free at virustotal.com).")
    r = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                     headers={"x-apikey": key}, timeout=25)
    if r.status_code == 404:
        return f"{domain}: not known to VirusTotal."
    if r.status_code in (401, 403):
        raise RuntimeError("VirusTotal rejected the API key.")
    r.raise_for_status()
    a = r.json()["data"]["attributes"]
    s = a.get("last_analysis_stats", {})
    return (f"{domain}: malicious={s.get('malicious', 0)}, suspicious={s.get('suspicious', 0)}, "
            f"harmless={s.get('harmless', 0)}, undetected={s.get('undetected', 0)}; "
            f"reputation={a.get('reputation', 'n/a')}")
