---
title: "LOG USE 2.0 — User Guide"
subtitle: "Personal Cybersecurity Monitor for Windows 10 / 11"
---

# 1. What LOG USE does

LOG USE is a **visible** security monitor for a Windows PC that you own or administer. It shows you who signed in to Windows, which websites were opened in your browsers, and whether any of them (or any live network connection) match known threats.

| Feature | What it does | Where you see it |
|---|---|---|
| **Windows authentication events** | Reads the exact events written by Windows itself: successful sign-in (4624), failed sign-in (4625), sign-out (4634 / 4647), PC locked (4800) and unlocked (4801), with user name, sign-in type (keyboard, Remote Desktop, network), source IP and failure reason. | *Windows sign-ins* tab |
| **Camera prompt at Windows sign-in** | When you sign in to Windows, LOG USE starts, shows a "Windows sign-in detected" window and offers to take a photo. | Pop-up after sign-in; photo path in the *Windows sign-ins* tab |
| **Continuous live monitoring across browsers** | Every 30 seconds (adjustable) it collects new visits from Chrome, Edge, Brave, Vivaldi, Opera, Opera GX, Chromium and Firefox (all profiles). | *Website history* tab |
| **Advanced threat intelligence** | Compares every site with public malware / phishing / botnet lists, scores look-alike and suspicious addresses, checks your live connections against botnet servers, and optionally asks VirusTotal. | Red / amber rows, red banner, *Threat intelligence* tab |
| **Camera permission** | Checks the Windows camera privacy switches and opens the right Windows page for you. | *Settings* tab and Dashboard |

**What LOG USE never does:** it never hides itself, never records passwords or keystrokes, never reads the content of web pages, and never sends your data anywhere. Everything is stored on your PC in `%LOCALAPPDATA%\LOG USE`.

> **Use it responsibly.** Install it only on a PC you own or administer. If other people use the PC, tell them it records sign-ins and browsing and may take a photo at sign-in. Using it to watch another person without their knowledge may be illegal.

# 2. Installing

The installer is a normal Windows setup wizard with the LOG USE logo. No command window appears at any point — all Python libraries are already inside the program.

## 2.0 Two ways to install

**A. Windows App Installer (recommended)** — the standard Windows "Install LOG USE?" window with a progress bar and a *Launch when ready* box. Open the `installer_output` folder and double-click **`Install_LOG_USE.vbs`**. No command window appears. Windows asks once to trust the LOG USE publisher (administrator confirmation), then shows the App Installer window; click **Install**.

* Start at sign-in is built in (Windows *Settings → Apps → Startup → LOG USE* switches it on or off).
* The first time LOG USE opens it asks permission (one Windows confirmation) to turn on sign-in auditing and to read the Security log. Sign out and in once afterwards.
* Camera: Windows shows its own camera permission prompt the first time the camera is used.
* A self-signed publisher shows as *unknown publisher* until its certificate is trusted by the helper above. For a green "Trusted App" label on every PC without this step, sign the package with a purchased code-signing certificate (or Azure Trusted Signing) — see section 9.

**B. Classic setup wizard** — `LOG-USE-Setup.exe` (steps below). It does the sign-in auditing and Event Log Readers setup during installation.

## 2.1 Requirements

* Windows 10 or Windows 11, 64-bit
* An administrator account (needed **once**, during setup)
* A webcam (optional, only for the sign-in photo)
* Internet (optional, only for threat-list updates)

You do **not** need to install Python or any library. Everything — Python, OpenCV (camera), requests (web), psutil (system) — is already packed inside the installer.

## 2.2 Step by step

1. Double-click **LOG-USE-Setup.exe**.
2. If Windows SmartScreen says *"Windows protected your PC"*, click **More info → Run anyway**. (This appears for any new program that is not code-signed.)
3. Click **Yes** on the administrator prompt.
4. Read the disclosure page and click **Next**.
5. Choose the install folder (the default is fine).
6. On the *Select Additional Tasks* page, keep these ticked:
    * **Create a desktop shortcut** (optional)
    * **Start LOG USE every time I sign in to Windows** — needed for the sign-in camera prompt
    * **Turn on Windows sign-in auditing and allow me to read the Security log** — needed for exact authentication events
7. Click **Install**. Setup copies the program and all libraries, switches on Windows *Logon / Logoff* auditing, adds you to the *Event Log Readers* group and creates the start-at-sign-in entry.
8. On the last page, tick **Open Windows camera privacy settings** and **Open the User Guide**, then click **Finish**.
9. **Sign out of Windows and sign in again once.** Windows only applies the *Event Log Readers* membership at the next sign-in.

## 2.3 Allow the camera (one-time, done by you)

Windows does not let any installer switch the camera permission on for you — only you can. Open **Settings → Privacy & security → Camera** and turn ON:

1. **Camera access**
2. **Let apps access your camera**
3. **Let desktop apps access your camera**

In LOG USE you can check this any time: *Settings tab → CHECK CAMERA PERMISSION*.

# 3. First start

1. Open **LOG USE** from the desktop or Start menu.
2. Click **Create account**, enter your e-mail and a password of at least 10 characters, then **Sign in**. This account only protects the LOG USE window on this PC.
3. Press **READ SIGN-IN EVENTS NOW** (Dashboard). The first read loads the last 7 days of Windows sign-in events.
4. Press **UPDATE THREAT FEEDS** (needs internet) to download the threat lists.
5. Press **IMPORT BROWSER HISTORY NOW**. The first import loads the last 30 days; afterwards new visits arrive automatically.

# 4. The tabs

## 4.1 Dashboard

* Five counters: website records, Windows sign-in events, failed sign-ins, threat alerts, activity events.
* Three switches:
    * **Continuous live monitoring** — pauses / resumes the browser and connection checks.
    * **Read Windows sign-in events** — switches the Security-log reader on or off.
    * **Start LOG USE every time I sign in** — adds / removes the start-at-sign-in entry.
* The status line at the bottom shows camera permission, how many threat indicators are loaded and any problem (for example "Access denied" to the Security log).
* The top-right shows **Live monitoring: ACTIVE / PAUSED** and the time of the last check.

## 4.2 Windows sign-ins

One row per event, newest first.

| Colour | Meaning |
|---|---|
| Green | Successful sign-in or unlock |
| Red | **Failed** sign-in — the *Failure reason* column explains why (wrong password, unknown user, locked-out account …) |
| Plain | Sign-out, lock, unlock |

Rows that have a photo show its file name; **double-click** to open it. *EXPORT CSV* saves the list to `%LOCALAPPDATA%\LOG USE\reports`.

**Sign-in types:** *Interactive* = at the keyboard · *Unlock* = unlocking a locked PC · *Remote Desktop* = someone connected remotely · *Cached* = offline domain sign-in · *Network* = access to a shared folder from another PC.

> **Look for:** several red rows in a row, red rows from a *Source IP*, any *Remote Desktop* row you did not make, or a sign-in at a time you were away.

## 4.3 Website history

Every visit with time, browser, threat level, domain, IP (after a lookup) and URL.

* **Red row = MALICIOUS** — the address is on a malware / phishing / botnet list.
* **Amber row = SUSPICIOUS** — it looks like a trick (see 4.4) but is not on a list.
* Tick **Show only threats** to filter.
* **RESOLVE IPs** performs a DNS lookup *now*; it is the current address, not necessarily the one used at the time of the visit.

## 4.4 Threat intelligence

**Feeds used** (public, free; each can be unavailable on a given day):

| Feed | Contains |
|---|---|
| URLhaus | Live malware-distribution URLs |
| OpenPhish | Phishing URLs |
| Phishing Army | Phishing domains |
| Feodo Tracker | Botnet command-and-control IP addresses |

Feeds update automatically every 12 hours while LOG USE is open (change in *Settings*). After each update your whole history is re-checked, so an old visit can turn red later.

**Suspicious-address checks** (each adds points; 3 or more = *suspicious*): raw IP instead of a name · `@` hidden in the address · look-alike characters (punycode) · typo-squatting such as `paypa1.com` · a famous brand name on an unrelated domain · high-abuse endings (.zip, .top, .tk …) · URL shorteners · "login / verify / secure" words in the domain · log-in pages without HTTPS · extremely long or heavily encoded URLs.

**Live connection check** — every minute, the programs on your PC that are talking to a known botnet server are listed with the program name.

**VirusTotal (optional):** get a free key at virustotal.com, paste it in *Settings*, then type a domain in the *Threat intelligence* tab and press **CHECK**.

> **Important:** "No threat found" never means "safe". It only means the address is not on the loaded lists and did not look tricky.

When something is found you get a red banner, a warning window (malicious only) and a row in the alert list. The same address is not announced again for 24 hours.

## 4.5 Website security

Type any address and press **CHECK WEBSITE SECURITY**. You get: HTTPS, certificate validation result, the main security headers (HSTS, CSP, X-Frame-Options …) and the threat-list result. It is a basic configuration check, not a vulnerability scan.

## 4.6 Activity

LOG USE's own log: starts, closes, sign-ins to LOG USE, settings changes, photos, feed updates, errors.

## 4.7 Settings

* **Camera at Windows sign-in** — choose one:
    * **Ask me each time (recommended)** — a window asks *TAKE PHOTO* or *SKIP*.
    * **Automatic photo after a visible countdown** — a window counts down (default 10 s); press **CANCEL** to stop it. The camera light is on while the photo is taken.
    * **Never** — only the sign-in summary is shown.
* **Countdown seconds**, **Browser check interval** (minimum 5 s), **Feed update interval**.
* **VirusTotal API key** — stored encrypted for your Windows user.
* **E-mail (SMTP)** — only needed for "Forgot password?". For Gmail: server `smtp.gmail.com`, port `587`, your address, and an **App password** (Google Account → Security → 2-Step Verification → App passwords). The password is stored encrypted for your Windows user.
* **CHECK CAMERA PERMISSION** and **OPEN WINDOWS CAMERA SETTINGS**.

Press **SAVE SETTINGS** after changes.

# 5. The sign-in camera prompt — how it works

1. You sign in to Windows (password, PIN, Hello …).
2. A few seconds later LOG USE starts (minimised in the taskbar) and reads the Security log.
3. A window **"Windows sign-in detected"** appears with the user, exact time, sign-in type and Windows event number. If anyone **failed** to sign in since LOG USE last ran, a red warning lists how many and when.
4. Depending on your Settings: you click **TAKE PHOTO**, or the countdown runs, or nothing is asked.
5. The photo is saved with a time stamp in `%LOCALAPPDATA%\LOG USE\photos` and linked to that sign-in row.

**Honest limits**

* A program cannot run on the Windows *lock screen*, so the photo is taken **right after a successful sign-in**, not while someone is typing a wrong password. Failed attempts are reported in the warning and in the list, with time, user and source.
* The camera permission switch (section 2.3) must be turned on by you.
* Photos are only of whoever is in front of the camera when the prompt appears.

# 6. Closing, pausing, uninstalling

* Closing the window asks: **Yes** = stop monitoring · **No** = minimise and keep monitoring · **Cancel** = stay open. Monitoring only runs while LOG USE is running — there is no hidden background service.
* **Pause** live monitoring any time on the Dashboard.
* **Uninstall:** *Settings → Apps → Installed apps → LOG USE → Uninstall*. This removes the program and the start-at-sign-in entry. Your data stays in `%LOCALAPPDATA%\LOG USE` — delete that folder to erase it. (The Windows auditing settings and group membership are left as they were, because other tools may use them.)

# 7. Troubleshooting

| Problem | Fix |
|---|---|
| *"Access to the Windows Security log was denied"* | Sign out of Windows and in again (the group change applies at sign-in). Still failing? Right-click **LOG USE → Run as administrator**. |
| No sign-in events appear | Press *READ SIGN-IN EVENTS NOW*. Make sure the *winaudit* task was ticked during setup, or run `auditpol /set /subcategory:"Logon" /success:enable /failure:enable` in an administrator Command Prompt. |
| Camera error / no photo | Section 2.3. Close other programs using the camera (Teams, Zoom). Check *Settings → CHECK CAMERA PERMISSION*. |
| Browser shows "Could not read" | Close that browser for a few seconds and press *IMPORT BROWSER HISTORY NOW*. |
| "Feed FAILED" | The site was unreachable (offline, firewall). Others still work; retry later. |
| Antivirus warns about the installer | New, unsigned programs are often flagged by mistake. Check the file came from your own build, then allow it. A code-signing certificate removes this. |
| "LOG USE is already running" | Only one copy may run. Look for it in the taskbar. |
| "Forgot password" does not send mail | Fill in the e-mail section in *Settings* first (needs an app password). |

# 8. Where your data is

`%LOCALAPPDATA%\LOG USE\` (type this in File Explorer's address bar)

| Item | File |
|---|---|
| All records | `log_use.db` (SQLite) |
| CSV exports | `reports\` |
| Photos | `photos\` |

# 9. For the person building the installer

The build produces both installers in `installer_output`: `LOG-USE-Setup.exe` (classic wizard) and `LOG-USE.msix` + `LOG-USE.cer` + `Install_LOG_USE.vbs` (App Installer window). To remove the publisher warning for everyone, replace the self-signed certificate: sign `LOG-USE.msix` with your own code-signing certificate (the `Publisher` in `msix\AppxManifest.xml` must equal the certificate subject).

You do **not** need to do this if you were given `LOG-USE-Setup.exe`.

**Option A — on any Windows PC (no black window):** extract the project zip and double-click **`Build_LOG_USE_Setup.vbs`**. A normal message box says the build has started; everything else runs invisibly (Python and **every library** from `requirements.txt` are installed, the program is built with PyInstaller, Inno Setup is installed if missing). A second message box announces that `installer_output\LOG-USE-Setup.exe` is ready. If anything fails, the details are saved in `build_log.txt`. Double-clicking `build_installer.bat` does exactly the same (it relaunches itself invisibly); only `build_installer.bat /show` from a command prompt shows the console.

**Option B — without a build PC:** upload the project folder to a GitHub repository, open *Actions → Build Windows installer → Run workflow*, and download **LOG-USE-Setup** from the run's artifacts.

**Silent install (for IT):** `LOG-USE-Setup.exe /VERYSILENT /TASKS="autostart,winaudit,desktopicon"`

# 10. Quick reference

| I want to … | Do this |
|---|---|
| See who signed in and when | *Windows sign-ins* tab |
| Know if someone tried to guess my password | Red rows in *Windows sign-ins* / red banner |
| See a photo of who signed in | Set camera mode (Settings), then double-click the row |
| Check a suspicious link | *Website security* tab, or *Threat intelligence → VirusTotal* |
| Stop monitoring | Dashboard → untick *Continuous live monitoring* |
| Remove everything | Uninstall, then delete `%LOCALAPPDATA%\LOG USE` |
