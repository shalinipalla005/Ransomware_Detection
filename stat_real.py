import subprocess
import pefile
import ctypes
import os

def check_signature(file_path):
    """
    Calls Windows API WinVerifyTrust
    """
    try:
        WinVerifyTrust = ctypes.windll.wintrust.WinVerifyTrust
        result = WinVerifyTrust(None, None, None)
        return result == 0
    except:
        return False



def detect_packer(file_path):
    pe = pefile.PE(file_path)

    suspicious_sections = []
    for section in pe.sections:
        entropy = section.get_entropy()

        if entropy > 7.0:
            suspicious_sections.append({
                "name": section.Name.decode().strip(),
                "entropy": entropy
            })

    return suspicious_sections


def run_floss(file_path):
    try:
        result = subprocess.run(
            ["floss", file_path],
            capture_output=True,
            text=True
        )

        output = result.stdout.lower()

        keywords = ["ransom", "bitcoin", "encrypt", "crypto"]

        found = [k for k in keywords if k in output]

        return found

    except Exception as e:
        return []


def static_analysis(file_path):
    return {
        "signature_valid": check_signature(file_path),
        "packed_sections": detect_packer(file_path),
        "suspicious_strings": run_floss(file_path)
    }


if __name__ == "__main__":
    file = "dist/ransom.exe"

    result = static_analysis(file)

    print("\n=== STATIC ANALYSIS (REAL TOOLS) ===")
    for k, v in result.items():
        print(k, ":", v)