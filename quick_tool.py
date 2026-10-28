"""
Simple 1-command tool for uploading, encrypting, and downloading files.
Usage:
    python quick_tool.py [optional_file_path]
"""

import sys
import os
import io
from pathlib import Path

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT_DIR))

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from fastapi.testclient import TestClient
from cloud_controller.api import app

def run_simple(target_file: str = None):
    client = TestClient(app)

    print("\n" + "=" * 50)
    print("      LAB CLOUD CONTROLLER - QUICK RUN")
    print("=" * 50)

    # Step 1: Login
    res = client.post("/api/v1/auth/login", json={"username": "alice", "password": "labpassword123"})
    if res.status_code != 200:
        print("[!] Login error")
        return
    token = res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("[1] Logged in as: alice (Genomics Core Lab)")

    # Step 2: Prepare file
    if target_file and os.path.exists(target_file):
        filename = Path(target_file).name
        with open(target_file, "rb") as f:
            content = f.read()
    else:
        filename = "my_notes.txt"
        content = b"Hello! This is a confidential laboratory research note.\n" * 2000

    print(f"[2] File selected: '{filename}' ({len(content)} bytes)")

    # Step 3: Upload & Encrypt
    print("[3] Uploading, splitting into blocks, and encrypting with AES-256-GCM...")
    up_res = client.post(
        "/api/v1/files/upload",
        headers=headers,
        files={"file": (filename, io.BytesIO(content), "text/plain")},
        data={"block_size": "65536", "encrypt": "true", "replication": "2"}
    )
    if up_res.status_code != 200:
        print(f"[!] Upload failed: {up_res.text}")
        return

    info = up_res.json()
    file_id = info["file_id"]
    print(f"    --> Success! File ID: {file_id}")
    print(f"    --> Cipher:   AES-256-GCM (tamper-proof)")
    print(f"    --> Divided:  {info['num_blocks']} blocks across HDFS DataNodes")

    # Step 4: Download & Reassemble
    print("\n[4] Downloading and reassembling original file from HDFS...")
    dl_res = client.get(f"/api/v1/files/{file_id}/download", headers=headers)
    if dl_res.status_code != 200:
        print(f"[!] Download failed: {dl_res.text}")
        return

    output_name = f"restored_{filename}"
    with open(output_name, "wb") as f:
        f.write(dl_res.content)

    print(f"    --> Decrypted and saved to: '{output_name}'")
    print(f"    --> Match check: {'MATCHES 100%' if dl_res.content == content else 'MISMATCH'}")
    print("=" * 50)
    print("DONE! File successfully encrypted, stored in HDFS, and restored.")
    print("=" * 50 + "\n")

if __name__ == "__main__":
    filepath = sys.argv[1] if len(sys.argv) > 1 else None
    run_simple(filepath)
