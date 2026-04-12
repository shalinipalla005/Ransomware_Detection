import pefile
from utils import calculate_entropy, extract_strings, find_suspicious_strings


class StaticAnalyzer:

    def __init__(self, file_path):
        self.file_path = file_path

        with open(file_path, "rb") as f:
            self.data = f.read()

        self.pe = pefile.PE(file_path)

    # -------------------------------
    # 1. Digital Signature Check
    # -------------------------------
    def check_signature(self):
        """
        Approximation of WinVerifyTrust:
        Checks if security directory exists
        """
        try:
            return hasattr(self.pe, 'DIRECTORY_ENTRY_SECURITY')
        except:
            return False

    # -------------------------------
    # 2. Packer Detection (Entropy)
    # -------------------------------
    def detect_packer(self):
        entropy = calculate_entropy(self.data)
        is_packed = entropy > 7.0  # heuristic threshold

        return {
            "entropy": entropy,
            "is_packed": is_packed
        }

    # -------------------------------
    # 3. Suspicious Strings
    # -------------------------------
    def analyze_strings(self):
        strings = extract_strings(self.data)
        suspicious = find_suspicious_strings(strings)

        return {
            "total_strings": len(strings),
            "suspicious_strings": suspicious,
            "count": len(suspicious)
        }

    # -------------------------------
    # Run All
    # -------------------------------
    def run(self):
        result = {
            "signature_valid": self.check_signature(),
            "packer_info": self.detect_packer(),
            "strings_info": self.analyze_strings()
        }
        return result


if __name__ == "__main__":
    analyzer = StaticAnalyzer("dist/ransom.exe")
    res = analyzer.run()

    print("\n=== STATIC ANALYSIS RESULT ===")
    for k, v in res.items():
        print(f"{k}: {v}")