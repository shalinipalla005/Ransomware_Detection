import os
import random
import time

time.sleep(3)

TARGET_DIR = "honey_files"

for root, dirs, files in os.walk(TARGET_DIR):
    for file in files:
        path = os.path.join(root, file)

        try:
            with open(path, "rb") as f:
                data = f.read()

            encrypted = bytearray(random.getrandbits(8) for _ in range(len(data)))

            new_path = path + ".locked"

            with open(new_path, "wb") as f:
                f.write(encrypted)

            os.remove(path)

            print("Encrypted:", new_path)

        except:
            pass