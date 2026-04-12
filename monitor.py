import time
import psutil
from collections import deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from utils import calculate_entropy
import os

event_log = deque()
TIME_WINDOW = 5        # seconds
EVENT_THRESHOLD = 5   # tune this
ALERT_COOLDOWN = 5     # seconds
ENTROPY_THRESHOLD = 7.2
MIN_FILE_SIZE = 100  # ignore tiny files

last_alert_time = 0
processed_files = set()

SUSPICIOUS_EXTENSIONS = [".locked", ".enc", ".crypted"]


class HoneyFileHandler(FileSystemEventHandler):

    def detect_attacker(self, file_path):
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                for f in proc.open_files():
                    if file_path in f.path:
                        return proc
            except:
                continue
        return None

    def respond_to_attack(self, file_path):
        if file_path in processed_files:
            return

        processed_files.add(file_path)

        print(f"\n HONEY TRAP ALERT: {file_path}")

        proc = self.detect_attacker(file_path)

        if proc:
            print(f"[KILLING] {proc.pid} ({proc.name()})")
            try:
                proc.kill()
            except:
                print("[!] Failed to kill process")

    def on_moved(self, event):
        if not event.is_directory:
            for ext in SUSPICIOUS_EXTENSIONS:
                if event.dest_path.endswith(ext):
                    self.respond_to_attack(event.dest_path)


class BehaviorHandler(FileSystemEventHandler):

    def log_event(self, file_path):
        global last_alert_time

        # Ignore useless files
        if file_path.endswith((".tmp", ".log")):
            return

        current_time = time.time()
        event_log.append(current_time)

        # Remove old events
        while event_log and (current_time - event_log[0] > TIME_WINDOW):
            event_log.popleft()

        # Check threshold
        if len(event_log) > EVENT_THRESHOLD:

            # cooldown check
            if current_time - last_alert_time < ALERT_COOLDOWN:
                return

            last_alert_time = current_time
            self.respond_to_attack(file_path)

    def detect_attacker(self, file_path):
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                for f in proc.open_files():
                    if file_path in f.path:
                        return proc
            except:
                continue
        return None

    def respond_to_attack(self, file_path):
        print("\n BEHAVIOR ALERT: Mass file activity detected")

        proc = self.detect_attacker(file_path)

        if proc:
            print(f"[KILLING] {proc.pid} ({proc.name()})")
            try:
                proc.kill()
            except:
                print("[!] Failed to kill process")

    def on_modified(self, event):
        if not event.is_directory:
            self.log_event(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.log_event(event.dest_path)


def run_trap_layer(directory):
    observer = Observer()
    observer.schedule(HoneyFileHandler(), directory, recursive=True)
    observer.start()
    print("[*] Honey Trap Layer ACTIVE")
    return observer


def run_behavior_layer(directory):
    observer = Observer()
    observer.schedule(BehaviorHandler(), directory, recursive=True)
    observer.start()
    print("[*] Behavior Layer ACTIVE")
    return observer

class EntropyHandler(FileSystemEventHandler):

    def calculate_file_entropy(self, file_path):
        try:
            if not file_path or not isinstance(file_path, str):
                return 0

            if not file_path.endswith((".txt", ".docx", ".pdf", ".jpg", ".png", ".locked")):
                return 0

            if not os.path.exists(file_path):
                return 0

            if os.path.getsize(file_path) < MIN_FILE_SIZE:
                return 0

            with open(file_path, "rb") as f:
                data = f.read()

            return calculate_entropy(data)

        except:
            return 0

    def detect_attacker(self, file_path):
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                for f in proc.open_files():
                    if file_path in f.path:
                        return proc
            except:
                continue
        return None

    def respond_to_attack(self, file_path, entropy):
        print(f"\n ENTROPY ALERT: {file_path}")
        print(f"[INFO] Entropy = {entropy:.2f}")

        proc = self.detect_attacker(file_path)

        if proc:
            print(f"[KILLING] {proc.pid} ({proc.name()})")
            try:
                proc.kill()
            except:
                print("[!] Failed to kill process")

    def on_modified(self, event):
        if not event.is_directory:
            entropy = self.calculate_file_entropy(event.src_path)

            if entropy > ENTROPY_THRESHOLD:
                self.respond_to_attack(event.src_path, entropy)

def run_entropy_layer(directory):
    observer = Observer()
    observer.schedule(EntropyHandler(), directory, recursive=True)
    observer.start()
    print("[*] Entropy Layer ACTIVE")
    return observer