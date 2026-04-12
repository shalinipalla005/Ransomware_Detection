import os
import sys
import math
import logging
import platform
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger("RansomWall.StaticLayer")

# ── Optional pefile ───────────────────────────────────────────────────────────
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    log.debug("[StaticLayer] pefile not found. Install: pip install pefile")

try:
    import ctypes
    CTYPES_AVAILABLE = True
except ImportError:
    CTYPES_AVAILABLE = False

SECTION_ENTROPY_THRESHOLD = 7.0
SUSPICIOUS_KEYWORDS = [
    "ransom", "bitcoin", "encrypt", "crypto",
    "decrypt", "payment", "wallet", "tor",
    "your files", "restore", "locked", "key",
]


# ════════════════════════════════════════════════════════════════════════════ #
def check_signature(file_path: str) -> bool:
    """
    Paper §III-D-1a: PE Digital Signature Verification.
    Windows: calls WinVerifyTrust API via ctypes.
    Other OS: checks for authenticode-style certificate data in PE headers.
    Returns True if signature appears valid.
    """
    if platform.system() == "Windows" and CTYPES_AVAILABLE:
        return _win_verify_trust(file_path)
    elif PEFILE_AVAILABLE:
        return _pe_has_certificate(file_path)
    return False


def _win_verify_trust(file_path: str) -> bool:
    """
    Paper §III-D-1a: "Microsoft Windows WinVerifyTrust API is used."
    Calls wintrust.WinVerifyTrust with WINTRUST_ACTION_GENERIC_VERIFY_V2 GUID.
    """
    try:
        import ctypes
        import ctypes.wintypes

        WINTRUST_ACTION_GENERIC_VERIFY_V2 = (
            "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}"
        )

        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [
                ("cbStruct",       ctypes.wintypes.DWORD),
                ("pcwszFilePath",  ctypes.c_wchar_p),
                ("hFile",          ctypes.wintypes.HANDLE),
                ("pgKnownSubject", ctypes.c_void_p),
            ]

        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [
                ("cbStruct",            ctypes.wintypes.DWORD),
                ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData",      ctypes.c_void_p),
                ("dwUIChoice",          ctypes.wintypes.DWORD),
                ("fdwRevocationChecks", ctypes.wintypes.DWORD),
                ("dwUnionChoice",       ctypes.wintypes.DWORD),
                ("pFile",               ctypes.c_void_p),
                ("dwStateAction",       ctypes.wintypes.DWORD),
                ("hWVTStateData",       ctypes.wintypes.HANDLE),
                ("pwszURLReference",    ctypes.c_wchar_p),
                ("dwProvFlags",         ctypes.wintypes.DWORD),
                ("dwUIContext",         ctypes.wintypes.DWORD),
            ]

        wfi = WINTRUST_FILE_INFO(
            cbStruct=ctypes.sizeof(WINTRUST_FILE_INFO),
            pcwszFilePath=file_path,
            hFile=None,
            pgKnownSubject=None,
        )
        wvt_data = WINTRUST_DATA(
            cbStruct=ctypes.sizeof(WINTRUST_DATA),
            dwUIChoice=2,           # WTD_UI_NONE
            fdwRevocationChecks=0,  # WTD_REVOKE_NONE
            dwUnionChoice=1,        # WTD_CHOICE_FILE
            pFile=ctypes.cast(ctypes.pointer(wfi), ctypes.c_void_p),
            dwStateAction=0,        # WTD_STATEACTION_IGNORE
        )
        guid_str = "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}"
        # parse GUID bytes
        import uuid
        g = uuid.UUID(guid_str)
        guid_bytes = (ctypes.c_byte * 16)(*g.bytes_le)

        result = ctypes.windll.wintrust.WinVerifyTrust(
            None,
            ctypes.byref(guid_bytes),
            ctypes.byref(wvt_data),
        )
        return result == 0   # 0 = TRUST_E_SUBJECT_NOT_TRUSTED means valid cert
    except Exception as e:
        log.debug(f"[StaticLayer] WinVerifyTrust error: {e}")
        return False


def _pe_has_certificate(file_path: str) -> bool:
    """Cross-platform fallback: check if the PE has a certificate directory entry."""
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        )
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        return sec_dir.Size > 0
    except Exception:
        return False


# ════════════════════════════════════════════════════════════════════════════ #
def detect_packer(file_path: str) -> List[dict]:
    """
    Paper §III-D-1b: "Presence of Packers/Cryptors – detection of high
    section Entropy."
    Uses pefile to compute Shannon entropy per PE section.
    Returns list of sections with entropy > threshold.
    """
    if not PEFILE_AVAILABLE:
        log.debug("[StaticLayer] pefile unavailable; skipping packer detection.")
        return []

    suspicious_sections = []
    try:
        pe = pefile.PE(file_path, fast_load=False)
        for section in pe.sections:
            entropy = section.get_entropy()
            if entropy > SECTION_ENTROPY_THRESHOLD:
                name = section.Name.decode(errors="replace").strip("\x00").strip()
                suspicious_sections.append({
                    "name":    name or "(unnamed)",
                    "entropy": round(entropy, 4),
                    "size":    section.SizeOfRawData,
                })
                log.info(
                    f"[StaticLayer] Packed/encrypted section: "
                    f"'{name}' entropy={entropy:.2f}"
                )
        pe.close()
    except Exception as e:
        log.debug(f"[StaticLayer] pefile error for {file_path}: {e}")

    return suspicious_sections


# ════════════════════════════════════════════════════════════════════════════ #
def run_floss(file_path: str) -> List[str]:
    """
    Paper §III-D-1c: "FLOSS is used for extracting embedded strings from
    obfuscated Ransomware binary."
    Tries FLOSS first; falls back to the `strings` utility; then raw scan.
    """
    found = _try_floss(file_path)
    if found is not None:
        return found

    found = _try_strings_tool(file_path)
    if found is not None:
        return found

    return _raw_string_scan(file_path)


def _try_floss(file_path: str) -> Optional[List[str]]:
    """Attempt to run FLOSS binary."""
    floss_bins = ["floss", "floss.exe", "./floss"]
    for floss in floss_bins:
        try:
            result = subprocess.run(
                [floss, file_path],
                capture_output=True, text=True, timeout=60
            )
            return _keyword_scan(result.stdout + result.stderr)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        except Exception as e:
            log.debug(f"[StaticLayer] FLOSS error: {e}")
    return None


def _try_strings_tool(file_path: str) -> Optional[List[str]]:
    """Fallback: use the `strings` CLI tool (Unix/Windows Sysinternals)."""
    for cmd in [["strings", "-n", "6", file_path],
                ["strings.exe", "-n", "6", file_path]]:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            )
            return _keyword_scan(result.stdout)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def _raw_string_scan(file_path: str) -> List[str]:
    """
    Last resort: read the binary and extract printable ASCII sequences ≥6 chars.
    Scan for ransomware-related keywords.
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        # Extract ASCII runs
        text = ""
        for byte in data:
            if 32 <= byte < 127:
                text += chr(byte)
            elif text:
                if len(text) >= 6:
                    pass   # keep accumulating
                text = ""
        return _keyword_scan(text)
    except Exception as e:
        log.debug(f"[StaticLayer] Raw scan error: {e}")
        return []


def _keyword_scan(text: str) -> List[str]:
    """Return list of suspicious keywords found in text (case-insensitive)."""
    lower = text.lower()
    return [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower]


# ════════════════════════════════════════════════════════════════════════════ #
def static_analysis(file_path: str) -> Dict:
    """
    Run all three static analysis checks.
    Returns a combined result dict.
    """
    if not Path(file_path).exists():
        log.warning(f"[StaticLayer] File not found: {file_path}")
        return {
            "signature_valid":    None,
            "packed_sections":    [],
            "suspicious_strings": [],
            "error":              "file_not_found",
        }

    sig_valid       = check_signature(file_path)
    packed_sections = detect_packer(file_path)
    suspicious_strs = run_floss(file_path)

    return {
        "signature_valid":    sig_valid,
        "packed_sections":    packed_sections,
        "suspicious_strings": suspicious_strs,
    }


# ════════════════════════════════════════════════════════════════════════════ #
def run_static_layer(file_path: str) -> Dict:
    """
    Paper §IV-A integration entry point.
    Runs static analysis and prints structured results.
    Returns the result dict (compatible with main.py feature merging).
    """
    result = static_analysis(file_path)

    print("\n=== LAYER 1: STATIC ANALYSIS ===")
    print(f"  File             : {file_path}")
    print(f"  Signature Valid  : {result['signature_valid']}")

    if result["packed_sections"]:
        print(f"  Packed Sections  : {len(result['packed_sections'])} found")
        for sec in result["packed_sections"]:
            print(f"    → {sec['name']:<20} entropy={sec['entropy']}")
    else:
        print("  Packed Sections  : None detected")

    if result["suspicious_strings"]:
        print(f"  Suspicious Strs  : {result['suspicious_strings']}")
    else:
        print("  Suspicious Strs  : None found")

    # Ransomware indicator summary
    score = 0
    if result["signature_valid"] is False:
        score += 2
    if result["packed_sections"]:
        score += len(result["packed_sections"])
    if result["suspicious_strings"]:
        score += len(result["suspicious_strings"])

    verdict = "⚠ SUSPICIOUS" if score >= 2 else "✓ Clean"
    print(f"  Static Score     : {score}  [{verdict}]")
    print("=" * 35)

    return result


# ════════════════════════════════════════════════════════════════════════════ #
if __name__ == "__main__":
    # Quick self-test
    if len(sys.argv) < 2:
        print("Usage: python stat_real.py <executable_path>")
        sys.exit(1)
    run_static_layer(sys.argv[1])