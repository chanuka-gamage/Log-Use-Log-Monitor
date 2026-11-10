# LOG USE 2.0 – Personal Cybersecurity Monitor (Windows)

Visible, local-only security monitor. **Full manual: `docs/LOG_USE_User_Guide.pdf`** (also `.docx` / `.md`).

## What's new in 2.0
| Feature | Module |
|---|---|
| Exact Windows authentication events (4624, 4625, 4634, 4647, 4800, 4801) from the Security log | `winevents.py` |
| Camera prompt at Windows sign-in (ask / visible cancelable countdown / off) + camera permission check | `main.py`, `camera.py` |
| Continuous live monitoring: Chrome, Edge, Brave, Vivaldi, Opera, Opera GX, Chromium, Firefox, all profiles | `browsers.py`, `monitor.py` |
| Threat intelligence: URLhaus, OpenPhish, Phishing Army, Feodo feeds; look-alike/phishing heuristics; live botnet-connection check; optional VirusTotal | `threatintel.py` |
| One-file Windows installer bundling every Python library | `build_installer.bat`, `installer.iss` |
| In-app Settings (SMTP password / API key encrypted with Windows DPAPI) | `core.py` |
| Fixed: duplicate history rows, wrong Chromium time zone, repeated imports | `browsers.py`, `core.py` |

## Get LOG-USE-Setup.exe (Windows PC)
**A.** Double-click `Build_LOG_USE_Setup.vbs` (silent, no console; message boxes only; log in `build_log.txt`) – or `build_installer.bat` to watch the console – installs Python (if missing) and all libraries in `requirements.txt`, builds with PyInstaller, installs Inno Setup (if missing), writes `installer_output\LOG-USE-Setup.exe`.
**B.** Push the folder to GitHub → *Actions → Build Windows installer → Run workflow* → download the artifact.

The setup EXE contains Python + requests + OpenCV + psutil; end users install nothing else. Setup (as administrator, once) can also enable Windows sign-in auditing, add the user to *Event Log Readers*, and start LOG USE at sign-in. Silent: `LOG-USE-Setup.exe /VERYSILENT /TASKS="autostart,winaudit,desktopicon"`.

## Windows App Installer window (MSIX)
The build also creates `installer_output\LOG-USE.msix` (+ `LOG-USE.cer`, `Install_LOG_USE.vbs`): double-click `Install_LOG_USE.vbs` for the standard Windows "Install LOG USE?" window with progress bar and *Launch when ready*. Packaged mode uses the manifest startup task, requests sign-in-log access on first run (one UAC prompt) and Windows' own camera prompt. Self-signed by default – sign with a real code-signing certificate for a "Trusted App" label.

## Run from source (developers)
```powershell
py -3.12 -m venv .venv ; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```

## Design limits (by intent)
* Monitoring is visible: LOG USE runs in the taskbar, only while open, and can be paused. No hidden service, no keystroke/password capture, no page-content reading.
* The camera only runs after the user clicks *Take photo* or after a visible countdown they can cancel. Windows' own camera switch must be turned on by the user – an installer cannot and must not do it.
* Programs cannot run on the Windows lock screen, so the photo is taken right after a successful sign-in; failed attempts are reported from the Security log.
* "No threat found" ≠ safe. Resolved IPs are current DNS answers, not historical.
* Install only on PCs you own/administer and tell other users.


## Install Python libraries from CMD (Windows)

Open **Command Prompt** in the `LOG_USE_Project` folder and run:

```bat
py -3.12 -m venv .venv
.venv\\Scripts\\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python main.py
```

If `py` is not recognized, install Python 3.12 from python.org and select **Add Python to PATH**.
The OTP feature uses Python's built-in email/SMTP libraries, so no separate OTP package is required.

## Fix / test password-reset OTP email

1. Open LOG USE → Settings.
2. Set SMTP server to `smtp.gmail.com`, port `587`, and SMTP username to your full Gmail address.
3. For Gmail, enable 2-Step Verification and create a Google **App Password**. Use that app password, not your normal Gmail password.
4. Click **SAVE SETTINGS**, then **SEND TEST EMAIL**. The test is sent to the From address, or SMTP username if From is blank.
5. After the test succeeds, choose **Forgot password? → SEND OTP**. OTPs expire after 10 minutes.

For other providers, use their official SMTP host and settings. Port 587 uses STARTTLS; port 465 uses SSL.
The app now gives clearer SMTP connection/authentication errors and does not save an OTP if delivery fails.
