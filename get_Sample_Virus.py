import os
import random

def create_fake_malicious_file(filename="sample_malware.exe", size_kb=100):
    current_dir = os.getcwd()
    random_bytes = os.urandom(size_kb * 1024) 

    file_path = os.path.join(current_dir, filename)

    with open(file_path, "wb") as f:
        f.write(random_bytes)

    print(f"Fake malicious file created at: {file_path}")

create_fake_malicious_file()
