import os
import random

HONEY_DIR = "honey_files"

FAKE_NAMES = [
    "salary_2024.xlsx",
    "bank_details.txt",
    "project_report.docx",
    "tax_info.pdf",
    "passwords.txt"
]

def create_honey_files():
    os.makedirs(HONEY_DIR, exist_ok=True)

    for name in FAKE_NAMES:
        file_path = os.path.join(HONEY_DIR, name)
        with open(file_path, "w") as f:
            f.write("CONFIDENTIAL DATA\n")

    print("[*] Realistic honey files created")