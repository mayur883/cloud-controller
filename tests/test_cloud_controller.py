"""
Comprehensive Test Suite for Laboratory Cloud Controller.
Covers:
1. AES-256-GCM authenticated encryption and tamper detection.
2. Configurable block segmentation and transparent stream reassembly.
3. Apache HDFS multi-node distributed storage, rack-aware replication, and node failover.
4. Multi-tenant isolation and tenant boundary enforcement.
5. Per-user and per-organization storage quota enforcement.
6. Hybrid cloud publishing (S3/GCS) with global CDN edge delivery.
"""

import pytest
import os
import io
import uuid
from fastapi.testclient import TestClient

from cloud_controller.crypto import (
    encrypt_aes_256_gcm,
    decrypt_aes_256_gcm,
    derive_key,
    IntegrityError,
    get_tenant_key,
)
from cloud_controller.segmentation import (
    segment_data,
    reassemble_data,
    compute_sha256,
)
from cloud_controller.hdfs_engine import (
    DistributedLANHDFSEngine,
    get_hdfs_engine,
)
from cloud_controller.api import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def alice_token(client):
    res = client.post("/api/v1/auth/login", json={"username": "alice", "password": "labpassword123"})
    assert res.status_code == 200
    return res.json()["access_token"]


@pytest.fixture
def charlie_token(client):
    res = client.post("/api/v1/auth/login", json={"username": "charlie", "password": "labpassword123"})
    assert res.status_code == 200
    return res.json()["access_token"]


# =========================================================================
# 1. Cryptographic AES-256-GCM & Tamper Detection Tests
# =========================================================================

def test_aes_256_gcm_roundtrip():
    secret = "lab-super-key-2026"
    salt = os.urandom(16)
    key = derive_key(secret, salt)
    plaintext = b"Highly confidential genomic sequencing dataset for CRISPR-Cas9 assay"
    aad = b"tenant:genomics:file:sample_001"

    ct_with_tag, nonce, salt_out = encrypt_aes_256_gcm(plaintext, key=key, associated_data=aad, salt=salt)
    assert ct_with_tag != plaintext
    assert len(nonce) == 12

    recovered = decrypt_aes_256_gcm(ct_with_tag, nonce=nonce, key=key, associated_data=aad)
    assert recovered == plaintext


def test_aes_256_gcm_tamper_detection():
    secret = "lab-super-key-2026"
    salt = os.urandom(16)
    key = derive_key(secret, salt)
    plaintext = b"Original scientific experiment metrics"
    aad = b"dataset:1"

    ct_with_tag, nonce, _ = encrypt_aes_256_gcm(plaintext, key=key, associated_data=aad, salt=salt)

    # Tamper with a single byte in ciphertext
    tampered_bytes = bytearray(ct_with_tag)
    tampered_bytes[5] ^= 0xFF  # Flip bit

    # Decryption MUST raise IntegrityError due to authentication tag mismatch
    with pytest.raises(IntegrityError):
        decrypt_aes_256_gcm(bytes(tampered_bytes), nonce=nonce, key=key, associated_data=aad)


# =========================================================================
# 2. Block Segmentation and Transparent Reassembly Tests
# =========================================================================

def test_block_segmentation_and_reassembly():
    # 250 KB data with 64 KB block size -> 4 blocks (3 full 64KB, 1 remainder 58KB)
    raw_data = os.urandom(250 * 1024)
    block_size = 64 * 1024
    tenant_id = "genomics-lab"
    file_id = "test_file_001"

    segments = segment_data(
        data=raw_data,
        block_size=block_size,
        file_id=file_id,
        tenant_id=tenant_id,
        encrypt=True,
    )

    assert len(segments) == 4
    for idx, (meta, block_bytes) in enumerate(segments):
        assert meta.block_index == idx
        assert meta.is_encrypted is True
        assert meta.raw_size == (64 * 1024 if idx < 3 else (250 - 3 * 64) * 1024)
        assert meta.nonce_hex is not None

    # Transparent reassembly
    recovered = reassemble_data(segments, tenant_id=tenant_id, file_id=file_id)
    assert recovered == raw_data
    assert compute_sha256(recovered) == compute_sha256(raw_data)


# =========================================================================
# 3. Apache HDFS Distributed Storage, Replication & Failover Tests
# =========================================================================

def test_hdfs_rack_aware_replication_and_failover():
    hdfs = get_hdfs_engine()
    block_path = f"test_tenant/test_file/blk_{uuid.uuid4().hex[:8]}.blk"
    data = b"Distributed block payload for HDFS resilience test"

    # Write with replication = 2
    nodes = hdfs.write_block(block_path, data, replication_factor=2)
    assert len(nodes) == 2
    # Ensure rack awareness (Node 1 and Node 2 or Node 3)
    racks = [hdfs.datanodes[nid].rack for nid in nodes]
    assert len(set(racks)) == 2, "Replication must be rack-aware (spanning 2 distinct racks)"

    # Verify standard read
    read_data = hdfs.read_block(block_path, nodes)
    assert read_data == data

    # Simulate node failure: Take first node holding replica offline!
    failed_node = nodes[0]
    hdfs.toggle_node(failed_node, online=False)

    try:
        # Read should seamlessly fail over to the second healthy replica on the other rack!
        survived_data = hdfs.read_block(block_path, nodes)
        assert survived_data == data
    finally:
        # Restore node online
        hdfs.toggle_node(failed_node, online=True)


# =========================================================================
# 4. Multi-Tenant Isolation Tests
# =========================================================================

def test_multi_tenant_isolation(client, alice_token, charlie_token):
    # Alice (Genomics Lab) uploads a file
    alice_content = b"Confidential human DNA sequence data for Genomics Lab only"
    upload_res = client.post(
        "/api/v1/files/upload",
        headers={"Authorization": f"Bearer {alice_token}"},
        files={"file": ("dna_seq.fasta", io.BytesIO(alice_content), "text/plain")},
        data={"block_size": "65536", "encrypt": "true"},
    )
    assert upload_res.status_code == 200
    file_id = upload_res.json()["file_id"]

    # Alice can download her file
    alice_dl = client.get(
        f"/api/v1/files/{file_id}/download",
        headers={"Authorization": f"Bearer {alice_token}"},
    )
    assert alice_dl.status_code == 200
    assert alice_dl.content == alice_content

    # Charlie (Quantum Lab) attempts to access Alice's file -> MUST be denied with 403 Forbidden!
    charlie_dl = client.get(
        f"/api/v1/files/{file_id}/download",
        headers={"Authorization": f"Bearer {charlie_token}"},
    )
    assert charlie_dl.status_code == 403

    # Charlie lists files -> Alice's file must NOT appear in Charlie's file listing
    charlie_list = client.get(
        "/api/v1/files",
        headers={"Authorization": f"Bearer {charlie_token}"},
    )
    assert charlie_list.status_code == 200
    charlie_file_ids = [f["id"] for f in charlie_list.json()["files"]]
    assert file_id not in charlie_file_ids


# =========================================================================
# 5. Storage Quota Enforcement Tests
# =========================================================================

def test_quota_enforcement(client, alice_token):
    # Check current quota
    quota_res = client.get("/api/v1/quota", headers={"Authorization": f"Bearer {alice_token}"})
    assert quota_res.status_code == 200
    user_quota = quota_res.json()["user"]["quota_bytes"]

    # Attempt to upload a file larger than total quota (e.g., quota + 1 MB)
    huge_size = user_quota + (1024 * 1024)
    # Generate empty/dummy stream of huge size without consuming RAM
    dummy_payload = b"0" * min(huge_size, 30 * 1024 * 1024)

    # If dummy payload is smaller than user_quota (25MB), let's set quota temporarily lower to test
    # Set quota to 100 KB for testing
    client.post(
        "/api/v1/admin/quotas",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"user_id": quota_res.json()["user"]["id"], "quota_mb": 1},  # 1 MB
    )

    # Now upload 2 MB file -> should fail with 413
    oversized_data = b"X" * (2 * 1024 * 1024)
    res = client.post(
        "/api/v1/files/upload",
        headers={"Authorization": f"Bearer {alice_token}"},
        files={"file": ("too_big.dat", io.BytesIO(oversized_data), "application/octet-stream")},
        data={"block_size": "65536", "encrypt": "true"},
    )
    assert res.status_code == 413
    assert "quota exceeded" in res.json()["detail"].lower()

    # Reset quota back to 25 MB
    client.post(
        "/api/v1/admin/quotas",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"user_id": quota_res.json()["user"]["id"], "quota_mb": 25},
    )


# =========================================================================
# 6. Hybrid Cloud Publishing (S3/GCS) & Global CDN Tests
# =========================================================================

def test_hybrid_cloud_publishing_and_cdn(client, alice_token):
    # Upload documentation file
    doc_content = b"# Genomics Research Protocol v2.1\n\nStandard operating procedure for sequence alignment."
    upload_res = client.post(
        "/api/v1/files/upload",
        headers={"Authorization": f"Bearer {alice_token}"},
        files={"file": ("protocol.md", io.BytesIO(doc_content), "text/markdown")},
        data={"block_size": "65536", "encrypt": "true"},
    )
    assert upload_res.status_code == 200
    file_id = upload_res.json()["file_id"]

    # Publish to AWS S3
    pub_res = client.post(
        "/api/v1/publish",
        headers={"Authorization": f"Bearer {alice_token}"},
        json={"file_id": file_id, "provider": "s3"},
    )
    assert pub_res.status_code == 200
    pub_data = pub_res.json()
    assert pub_data["provider"] == "S3"
    assert "amazonaws.com" in pub_data["public_url"]
    assert "/cdn/s3/" in pub_data["cdn_url"]

    # Fetch document via Global CDN edge URL
    cdn_path = pub_data["cdn_url"].split("/cdn/")[-1]
    cdn_res = client.get(f"/cdn/{cdn_path}")
    assert cdn_res.status_code == 200
    assert cdn_res.content == doc_content
    assert "public, max-age=" in cdn_res.headers.get("Cache-Control", "")
    assert cdn_res.headers.get("CDN-Cache-Status") == "HIT"
