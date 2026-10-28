"""
Populates the Cloud Controller with realistic sample laboratory research files
and published research documents to demonstrate block segmentation and hybrid CDN.
"""

import io
from fastapi.testclient import TestClient
from cloud_controller.api import app

def seed_sample_lab_data():
    client = TestClient(app)
    
    # 1. Login Alice
    alice_res = client.post("/api/v1/auth/login", json={"username": "alice", "password": "labpassword123"})
    alice_token = alice_res.json()["access_token"]
    alice_headers = {"Authorization": f"Bearer {alice_token}"}

    # Check if files already seeded
    files_res = client.get("/api/v1/files", headers=alice_headers)
    if files_res.status_code == 200 and len(files_res.json().get("files", [])) > 0:
        print("[*] Sample laboratory data already seeded.")
        return

    print("[*] Seeding sample laboratory research files...")

    # Sample File 1: CRISPR Gene Sequencing FASTA (Multi-block, encrypted)
    fasta_content = b">Homo_sapiens_BRCA1_exon11\n" + (b"ATGCGATCGATCGATCGATCGATCGATCGA" * 3500)
    client.post(
        "/api/v1/files/upload",
        headers=alice_headers,
        files={"file": ("CRISPR_Cas9_Target_BRCA1.fasta", io.BytesIO(fasta_content), "text/plain")},
        data={"block_size": "32768", "encrypt": "true"},  # 32KB blocks
    )

    # Sample File 2: Lab SOP Documentation (Markdown)
    sop_content = b"""# Laboratory Standard Operating Procedure (SOP)
## Next-Generation Sequencing & HDFS Replication Protocol
- Version: 3.4.1
- Classification: Confidential Research
- Storage: 2x Cross-Rack HDFS Replicas
- Cryptography: AES-256-GCM

### Procedure:
1. Extract high-molecular-weight genomic DNA.
2. Segment files into 1MB blocks with SHA-256 integrity verification.
3. Distribute blocks across Rack-1 and Rack-2 DataNodes.
"""
    sop_res = client.post(
        "/api/v1/files/upload",
        headers=alice_headers,
        files={"file": ("SOP_Genomics_Sequencing_v3.4.md", io.BytesIO(sop_content), "text/markdown")},
        data={"block_size": "65536", "encrypt": "true"},
    )

    # Publish SOP to AWS S3 + Global CDN
    if sop_res.status_code == 200:
        file_id = sop_res.json()["file_id"]
        client.post(
            "/api/v1/publish",
            headers=alice_headers,
            json={"file_id": file_id, "provider": "s3"},
        )

    # Charlie (Quantum Optics Lab)
    charlie_res = client.post("/api/v1/auth/login", json={"username": "charlie", "password": "labpassword123"})
    charlie_token = charlie_res.json()["access_token"]
    charlie_headers = {"Authorization": f"Bearer {charlie_token}"}

    quantum_data = b"Photon_Entanglement_Telemetry_Run_402,Timestamp,CoincidenceCount\n" + (b"402.01,1729600000,9421\n" * 1500)
    client.post(
        "/api/v1/files/upload",
        headers=charlie_headers,
        files={"file": ("Photon_Entanglement_Run402.csv", io.BytesIO(quantum_data), "text/csv")},
        data={"block_size": "16384", "encrypt": "true"},
    )

    print("[✓] Seed completed successfully.")

if __name__ == "__main__":
    seed_sample_lab_data()
