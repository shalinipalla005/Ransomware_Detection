import os
import time
import psutil
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

HONEY_DIR = "C:\\honey_files"

def create_honey_files():
    os.makedirs(HONEY_DIR, exist_ok=True)

    extensions = ["txt", "docx", "pdf", "jpg"]

    for i in range(10):
        for ext in extensions:
            file = os.path.join(HONEY_DIR, f"file_{i}.{ext}")
            with open(file, "w") as f:
                f.write("important data")

class Handler(FileSystemEventHandler):

    def on_any_event(self, event):
        print("[FILE ALERT]", event.event_type, event.src_path)


def monitor_files():
    observer = Observer()
    observer.schedule(Handler(), HONEY_DIR, recursive=True)
    observer.start()
    return observer

CRYPTO_DLLS = [
    "rsaenh.dll", "crypt32.dll", "bcrypt.dll"
]

def detect_crypto_usage():
    alerts = []

    for proc in psutil.process_iter(['pid', 'name']):
        try:
            for m in proc.memory_maps():
                for dll in CRYPTO_DLLS:
                    if dll in m.path.lower():
                        alerts.append(proc.pid)
        except:
            pass

    return list(set(alerts))


def detect_system_attacks():

    suspicious_patterns = [
        "vssadmin delete shadows",
        "wmic shadowcopy delete",
        "bcdedit"
    ]

    alerts = []

    for proc in psutil.process_iter(['pid', 'cmdline']):
        try:
            cmd = " ".join(proc.info['cmdline']).lower()

            for p in suspicious_patterns:
                if p in cmd:
                    alerts.append((proc.pid, cmd))
        except:
            pass

    return alerts


def check_registry():
    import winreg

    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Run"
    )

    i = 0
    entries = []

    try:
        while True:
            name, value, _ = winreg.EnumValue(key, i)
            entries.append((name, value))
            i += 1
    except:
        pass

    return entries


def run_trap_layer():
    create_honey_files()
    observer = monitor_files()

    print("[*] Trap Layer Running...")

    try:
        while True:

            crypto = detect_crypto_usage()
            if crypto:
                print("[ALERT] Crypto API usage:", crypto)

            attacks = detect_system_attacks()
            for a in attacks:
                print("[ALERT] System attack:", a)

            registry = check_registry()
            if registry:
                print("[INFO] Registry entries:", registry)

            time.sleep(3)

    except KeyboardInterrupt:
        observer.stop()

    observer.join()


if __name__ == "__main__":
    run_trap_layer()