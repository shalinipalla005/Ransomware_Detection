from trap import create_honey_files
from monitor import run_trap_layer, run_behavior_layer, run_entropy_layer
import time

if __name__ == "__main__":
    create_honey_files()

    trap = run_trap_layer("honey_files")
    behavior = run_behavior_layer("honey_files")
    entropy = run_entropy_layer("honey_files")

    print("[*] 3-Layer Ransomware Detection ACTIVE")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        trap.stop()
        behavior.stop()
        entropy.stop()

    trap.join()
    behavior.join()
    entropy.join()