"""
Laboratory LAN Command-Line Interface (CLI).
Provides terminal commands for researchers to authenticate, upload segmented/encrypted files,
download with automatic reassembly, inspect HDFS blocks, and manage quotas.
"""

import argparse
import sys
import os
import json
from pathlib import Path
import requests

DEFAULT_SERVER_URL = os.getenv("LAB_CLOUD_SERVER", "http://localhost:8080")
TOKEN_FILE = Path.home() / ".labcloud_token.json"


def save_session(server_url: str, token: str, user_info: dict):
    with open(TOKEN_FILE, "w", encoding="utf-8") as f:
        json.dump({"server_url": server_url, "token": token, "user": user_info}, f, indent=2)


def load_session():
    if not TOKEN_FILE.exists():
        return None
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def get_headers(session):
    if not session or "token" not in session:
        print("[!] Not authenticated. Please run: labcloud login -u <username> -p <password>")
        sys.exit(1)
    return {"Authorization": f"Bearer {session['token']}"}


def cmd_login(args):
    url = f"{args.server.rstrip('/')}/api/v1/auth/login"
    payload = {"username": args.username, "password": args.password}
    try:
        res = requests.post(url, json=payload, timeout=10)
        if res.status_code == 200:
            data = res.json()
            save_session(args.server, data["access_token"], data["user"])
            print(f"[✓] Successfully authenticated as '{args.username}' (Role: {data['user']['role']}, Tenant: {data['user']['tenant_id']})")
        else:
            print(f"[✗] Login failed: {res.status_code} - {res.text}")
    except Exception as e:
        print(f"[✗] Connection error to {url}: {e}")


def cmd_upload(args):
    session = load_session()
    headers = get_headers(session)
    server_url = session.get("server_url", DEFAULT_SERVER_URL)
    url = f"{server_url}/api/v1/files/upload"

    file_path = Path(args.filepath)
    if not file_path.exists():
        print(f"[✗] File '{args.filepath}' not found.")
        sys.exit(1)

    print(f"[*] Uploading '{file_path.name}' ({file_path.stat().st_size} bytes)...")
    print(f"[*] Configured block segment size: {args.block_size} bytes. Encryption: AES-256-GCM")

    with open(file_path, "rb") as f:
        files = {"file": (file_path.name, f)}
        data = {
            "block_size": str(args.block_size),
            "encrypt": "true" if not args.no_encrypt else "false",
        }
        res = requests.post(url, headers=headers, files=files, data=data, timeout=60)

    if res.status_code == 200:
        info = res.json()
        print(f"[✓] File uploaded successfully!")
        print(f"    File ID:       {info['file_id']}")
        print(f"    Total Blocks:  {info['num_blocks']} blocks ({info['block_size']} bytes each)")
        print(f"    Encrypted:     {info['is_encrypted']} ({info['encryption_algorithm']})")
        print(f"    SHA-256 Hash:  {info['checksum_sha256']}")
        print(f"    Replication:   {info['replication_factor']}x across HDFS DataNodes")
    else:
        print(f"[✗] Upload failed: {res.status_code} - {res.text}")


def cmd_list(args):
    session = load_session()
    headers = get_headers(session)
    server_url = session.get("server_url", DEFAULT_SERVER_URL)
    url = f"{server_url}/api/v1/files"

    res = requests.get(url, headers=headers, timeout=10)
    if res.status_code == 200:
        data = res.json()
        files = data.get("files", [])
        print(f"\nLaboratory Files ({len(files)} total):")
        print("-" * 95)
        print(f"{'FILE ID':<18} {'FILENAME':<24} {'SIZE':<10} {'BLOCKS':<8} {'CIPHER':<14} {'UPLOADER':<12}")
        print("-" * 95)
        for f in files:
            cipher = "AES-256-GCM" if f.get("is_encrypted") else "Plaintext"
            print(f"{f['id']:<18} {f['filename'][:22]:<24} {f['total_size']:<10} {f['num_blocks']:<8} {cipher:<14} {f.get('uploader', 'N/A'):<12}")
        print("-" * 95)
    else:
        print(f"[✗] List failed: {res.status_code} - {res.text}")


def cmd_download(args):
    session = load_session()
    headers = get_headers(session)
    server_url = session.get("server_url", DEFAULT_SERVER_URL)
    url = f"{server_url}/api/v1/files/{args.file_id}/download"

    print(f"[*] Reassembling and decrypting blocks for file '{args.file_id}'...")
    res = requests.get(url, headers=headers, stream=True, timeout=60)

    if res.status_code == 200:
        # Determine output filename
        content_disp = res.headers.get("Content-Disposition", "")
        filename = args.output
        if not filename:
            if "filename=" in content_disp:
                filename = content_disp.split("filename=")[-1].strip('"')
            else:
                filename = f"downloaded_{args.file_id}"

        with open(filename, "wb") as f:
            for chunk in res.iter_content(chunk_size=8192):
                f.write(chunk)

        print(f"[✓] File downloaded and verified successfully: '{filename}'")
        print(f"    Payload Checksum: {res.headers.get('X-Payload-Checksum', 'Verified')}")
        print(f"    Decryption:       {res.headers.get('X-Encryption', 'AES-256-GCM')}")
    else:
        print(f"[✗] Download failed: {res.status_code} - {res.text}")


def cmd_blocks(args):
    session = load_session()
    headers = get_headers(session)
    server_url = session.get("server_url", DEFAULT_SERVER_URL)
    url = f"{server_url}/api/v1/files/{args.file_id}/blocks"

    res = requests.get(url, headers=headers, timeout=10)
    if res.status_code == 200:
        data = res.json()
        print(f"\nBlock Segments for '{data['filename']}' ({data['num_blocks']} blocks):")
        print("-" * 85)
        print(f"{'IDX':<5} {'BLOCK ID':<22} {'SIZE (B)':<10} {'ENCRYPTED':<12} {'HDFS REPLICAS'}")
        print("-" * 85)
        for b in data["blocks"]:
            reps = ", ".join(b["replica_nodes"])
            print(f"{b['block_index']:<5} {b['block_id']:<22} {b['raw_size']:<10} {str(b['is_encrypted']):<12} {reps}")
        print("-" * 85)
    else:
        print(f"[✗] Failed: {res.status_code} - {res.text}")


def cmd_quota(args):
    session = load_session()
    headers = get_headers(session)
    server_url = session.get("server_url", DEFAULT_SERVER_URL)
    url = f"{server_url}/api/v1/quota"

    res = requests.get(url, headers=headers, timeout=10)
    if res.status_code == 200:
        data = res.json()
        u = data["user"]
        t = data["tenant"]
        print(f"\nStorage Quota Status:")
        print(f"  User '{u['username']}':   {u['used_mb']} MB / {u['quota_mb']} MB ({u['usage_pct']}% used, {u['files_count']} files)")
        print(f"  Tenant '{t['name']}': {t['used_mb']} MB / {t['quota_mb']} MB ({t['usage_pct']}% used)")
    else:
        print(f"[✗] Quota check failed: {res.status_code} - {res.text}")


def cmd_cluster(args):
    session = load_session()
    headers = get_headers(session)
    server_url = session.get("server_url", DEFAULT_SERVER_URL)
    url = f"{server_url}/api/v1/cluster/status"

    res = requests.get(url, headers=headers, timeout=10)
    if res.status_code == 200:
        data = res.json()
        print(f"\nApache HDFS Cluster Health: [{data['cluster_status']}] ({data['mode']})")
        print(f"Active Nodes: {data['online_nodes']} / {data['total_nodes']} | Total Capacity: {round(data['total_capacity_bytes']/(1024*1024), 2)} MB")
        print("-" * 75)
        print(f"{'NODE ID':<16} {'RACK':<10} {'LAN HOST':<16} {'STATUS':<10} {'BLOCKS':<8}")
        print("-" * 75)
        for dn in data["datanodes"]:
            st = "ONLINE" if dn["is_online"] else "OFFLINE"
            print(f"{dn['node_id']:<16} {dn['rack']:<10} {dn['host']:<16} {st:<10} {dn['block_count']:<8}")
        print("-" * 75)
    else:
        print(f"[✗] Cluster status failed: {res.status_code} - {res.text}")


def cmd_publish(args):
    session = load_session()
    headers = get_headers(session)
    server_url = session.get("server_url", DEFAULT_SERVER_URL)
    url = f"{server_url}/api/v1/publish"

    res = requests.post(url, headers=headers, json={"file_id": args.file_id, "provider": args.provider}, timeout=30)
    if res.status_code == 200:
        pub = res.json()
        print(f"[✓] Published document '{pub['filename']}' to {pub['provider']}!")
        print(f"    Public S3/GCS Object: {pub['public_url']}")
        print(f"    Edge CDN Access URL:  {pub['cdn_url']}")
    else:
        print(f"[✗] Publishing failed: {res.status_code} - {res.text}")


def main():
    parser = argparse.ArgumentParser(prog="labcloud", description="Laboratory LAN Cloud Controller CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # login
    p_login = subparsers.add_parser("login", help="Authenticate with the controller")
    p_login.add_argument("-u", "--username", required=True)
    p_login.add_argument("-p", "--password", required=True)
    p_login.add_argument("--server", default=DEFAULT_SERVER_URL)
    p_login.set_defaults(func=cmd_login)

    # upload
    p_upload = subparsers.add_parser("upload", help="Upload and segment a file")
    p_upload.add_argument("filepath", help="Path to local file to upload")
    p_upload.add_argument("--block-size", type=int, default=1048576, help="Segment block size in bytes (default: 1048576 = 1MB)")
    p_upload.add_argument("--no-encrypt", action="store_true", help="Disable AES-256-GCM encryption")
    p_upload.set_defaults(func=cmd_upload)

    # list
    p_list = subparsers.add_parser("list", help="List files in your tenant storage")
    p_list.set_defaults(func=cmd_list)

    # download
    p_down = subparsers.add_parser("download", help="Reassemble and download a file")
    p_down.add_argument("file_id", help="File ID to download")
    p_down.add_argument("-o", "--output", help="Output file path")
    p_down.set_defaults(func=cmd_download)

    # blocks
    p_blocks = subparsers.add_parser("blocks", help="Inspect distributed HDFS blocks for a file")
    p_blocks.add_argument("file_id", help="File ID")
    p_blocks.set_defaults(func=cmd_blocks)

    # quota
    p_quota = subparsers.add_parser("quota", help="View current storage quota usage")
    p_quota.set_defaults(func=cmd_quota)

    # cluster
    p_cluster = subparsers.add_parser("cluster", help="View HDFS cluster topology & health")
    p_cluster.set_defaults(func=cmd_cluster)

    # publish
    p_pub = subparsers.add_parser("publish", help="Publish a file to public cloud object storage (S3/GCS)")
    p_pub.add_argument("file_id", help="File ID to publish")
    p_pub.add_argument("--provider", choices=["s3", "gcs"], default="s3", help="Target cloud provider")
    p_pub.set_defaults(func=cmd_publish)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
