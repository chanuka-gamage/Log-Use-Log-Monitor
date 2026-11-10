"""Camera permission check and visible, user-approved photo capture."""
import os
from datetime import datetime

from core import PHOTO_DIR, log_event, is_packaged as core_is_packaged

CAM_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"


def camera_permission() -> dict:
    """Read Windows privacy settings. Returns {'overall','desktop_apps','text'}."""
    if os.name != "nt":
        return {"overall": "unknown", "desktop_apps": "unknown", "text": "Only checkable on Windows."}
    import winreg

    def read(root, sub):
        try:
            with winreg.OpenKey(root, sub) as k:
                return str(winreg.QueryValueEx(k, "Value")[0]).lower()
        except OSError:
            return None

    overall = read(winreg.HKEY_LOCAL_MACHINE, CAM_KEY) or read(winreg.HKEY_CURRENT_USER, CAM_KEY)
    desktop = None if core_is_packaged() else read(winreg.HKEY_CURRENT_USER, CAM_KEY + r"\NonPackaged")
    ok_overall = overall in (None, "allow")
    ok_desktop = desktop in (None, "allow")
    if ok_overall and ok_desktop:
        text = "Camera access is ALLOWED for desktop apps."
    elif not ok_overall:
        text = "Windows camera access is OFF. Turn on 'Camera access'."
    else:
        text = "'Let desktop apps access your camera' is OFF."
    return {"overall": overall or "allow", "desktop_apps": desktop or "allow",
            "text": text, "ok": ok_overall and ok_desktop}


def open_camera_settings():
    """Open Windows Settings > Privacy > Camera. Windows requires the user to flip the switch."""
    if os.name == "nt":
        os.startfile("ms-settings:privacy-webcam")


def capture_photo(reason="manual") -> str:
    """Capture ONE photo. The caller must already have shown the user a notice/consent dialog."""
    import cv2
    backend = cv2.CAP_DSHOW if os.name == "nt" else 0
    cap = cv2.VideoCapture(0, backend)
    if not cap.isOpened():
        cap.release()
        raise RuntimeError("No accessible camera was found (or camera access is blocked in Windows).")
    frame = None
    try:
        for _ in range(12):               # let exposure settle
            ok, f = cap.read()
            if ok:
                frame = f
    finally:
        cap.release()
    if frame is None:
        raise RuntimeError("The camera did not return an image.")
    stamp = datetime.now()
    cv2.putText(frame, stamp.strftime("%Y-%m-%d %H:%M:%S"), (10, frame.shape[0] - 12),
                cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 2, cv2.LINE_AA)
    target = PHOTO_DIR / f"{reason}_{stamp:%Y%m%d_%H%M%S}.jpg"
    cv2.imwrite(str(target), frame)
    log_event("WEBCAM_PHOTO", f"{reason}: {target}")
    return str(target)
