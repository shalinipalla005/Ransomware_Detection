from stat_real import static_analysis

def run_static_layer(file_path):
    print("[*] Layer 1: Static Analysis STARTED")

    result = static_analysis(file_path)

    print("\n--- STATIC ANALYSIS RESULT ---")

    if not result["signature_valid"]:
        print("🚨 [STATIC] Invalid or missing digital signature")

    if result["packed_sections"]:
        print("🚨 [STATIC] Packed sections detected:")
        for sec in result["packed_sections"]:
            print(f"   - {sec['name']} (entropy={sec['entropy']:.2f})")

    if result["suspicious_strings"]:
        print("🚨 [STATIC] Suspicious strings found:")
        for s in result["suspicious_strings"]:
            print(f"   - {s}")

    # Decision (IMPORTANT)
    if (
        not result["signature_valid"] or
        result["packed_sections"] or
        result["suspicious_strings"]
    ):
        print("\n⚠️ [STATIC] File is SUSPICIOUS\n")
        return True
    else:
        print("\n✅ [STATIC] File looks SAFE\n")
        return False