import math
import re

SUSPICIOUS_KEYWORDS = [
    b"ransom", b"bitcoin", b"encrypt", b"crypto"
]

def calculate_entropy(data: bytes) -> float:
    """Compute Shannon entropy"""
    if not data:
        return 0

    entropy = 0
    for i in range(256):
        p_x = data.count(bytes([i])) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)

    return entropy


def extract_strings(data: bytes, min_length=4):
    """Extract ASCII strings"""
    pattern = rb"[ -~]{%d,}" % min_length
    return re.findall(pattern, data)


def find_suspicious_strings(strings):
    """Match ransomware keywords"""
    found = []
    for s in strings:
        s_lower = s.lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in s_lower:
                found.append(s.decode(errors="ignore"))
    return list(set(found))