from trap import create_honey_files
from monitor import run_trap_layer, run_behavior_layer, run_entropy_layer
from static_layer import run_static_layer
import time

if __name__ == "__main__":

    # --------------------------
    # LAYER 1: STATIC ANALYSIS
    # --------------------------
    suspicious = run_static_layer("dist/ransom.exe")

    # If file is suspicious → continue monitoring
    # (research systems do this)
    
    # --------------------------
    # SETUP HONEY FILES
    # --------------------------
    create_honey_files()

    # --------------------------
    # LAYER 2–4 (RUNTIME)
    # --------------------------
    trap = run_trap_layer("honey_files")
    behavior = run_behavior_layer("honey_files")
    entropy = run_entropy_layer("honey_files")

    print("\n[*] 4-Layer Ransomware Detection ACTIVE")

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