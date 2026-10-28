# Lightweight Laboratory Cloud Controller
### Multi-Tenant LAN Storage with Apache HDFS, AES-256-GCM & Hybrid S3/GCS CDN

A high-performance, lightweight Cloud Controller engineered for laboratory local area networks (LAN). It provides secure multi-tenant storage, automatic block segmentation, transparent stream reassembly, Apache HDFS distributed fault-tolerance, AES-256-GCM authenticated encryption, per-user storage quotas, an interactive Web Dashboard, and hybrid cloud publishing to public object storage (S3/GCS) with global CDN delivery.

---

## Key Features

1. **Laboratory LAN Multi-Tenancy & Access Control**:
   - Strict tenant organizational boundaries (e.g. `Genomics Core Laboratory`, `Quantum Optics Lab`).
   - Role-Based Access Control (RBAC): `superadmin`, `admin`, `researcher`, `auditor`.
   - JWT-based authentication with secure session handling.

2. **Apache HDFS Distributed Storage Integration**:
   - Standard **WebHDFS REST API** RFC compliance (`/webhdfs/v1/`).
   - Built-in **Fault-Tolerant LAN HDFS Cluster Engine** simulating multi-DataNode racks (`/rack-1`, `/rack-2`).
   - **Rack-Aware 2x/3x Replica Placement**: Primary blocks and redundant replicas are distributed across distinct racks to withstand hardware failures.
   - **Automated Replica Failover**: If a DataNode goes offline or a drive fails, reads seamlessly fall back to secondary replicas with zero downtime.

3. **Automatic Block Segmentation & Transparent Reassembly**:
   - Configurable block sizes (64KB, 256KB, 512KB, 1MB, 2MB, 4MB, up to 64MB).
   - Files are automatically sliced into indexed block segments during upload.
   - SHA-256 block-level and payload-level integrity hashes.
   - Transparent stream reassembly during file download.

4. **AES-256-GCM Authenticated Encryption**:
   - Confidentiality in transit and at rest.
   - Per-tenant 256-bit derived keys via HKDF-SHA256.
   - 96-bit random cryptographic nonces + 128-bit authentication tags.
   - Tamper-evident: any bit flip or payload alteration triggers an immediate `IntegrityError`.

5. **Atomic Per-User & Per-Tenant Quotas**:
   - Dual-tier storage quota enforcement (per-user and per-organization).
   - Rejects uploads exceeding limits with `413 Request Entity Too Large`.
   - Real-time quota metrics and visualization in the web dashboard.
   - Immediate quota release on file deletion.

6. **Modern Web Dashboard & REST API**:
   - Responsive, dark-themed laboratory UI with real-time quota gauges.
   - Drag-and-drop file uploader with configurable block size and encryption toggle.
   - Interactive **Block Segments Inspector** (view UUIDs, sizes, checksums, and DataNode allocations).
   - **HDFS Topology Visualizer & Fault Tolerance Simulator** (interactively toggle DataNodes offline/online).
   - Interactive Swagger API Documentation at `/docs`.

7. **Hybrid Cloud Publishing (S3/GCS + Global CDN)**:
   - One-click publishing of research papers, documentation, or dataset manifests to AWS S3 or Google Cloud Storage.
   - Generates global CDN URLs (`/cdn/s3/...`, `/cdn/gcs/...`) with HTTP Edge `Cache-Control: public, max-age=86400`.

8. **Terminal CLI Client (`labcloud`)**:
   - Native command-line interface for researchers on laboratory workstations (`login`, `upload`, `list`, `download`, `blocks`, `quota`, `cluster`, `publish`).

---

## Pre-Configured Test Accounts

| Username | Password | Organization / Tenant | Role | Quota |
| :--- | :--- | :--- | :--- | :--- |
| `alice` | `labpassword123` | Genomics Core Laboratory (`genomics-lab`) | Tenant Admin | 25 MB |
| `bob` | `labpassword123` | Genomics Core Laboratory (`genomics-lab`) | Researcher | 20 MB |
| `charlie` | `labpassword123` | Quantum Optics Laboratory (`quantum-lab`) | Researcher | 15 MB |
| `superadmin` | `labadmin2026` | System Administration (`system`) | Superadmin | 1000 MB |

---

## Directory Architecture

```
cloud-controller/
├── cloud_controller/
│   ├── __init__.py
│   ├── __main__.py          # Controller startup entrypoint
│   ├── config.py            # LAN host, block sizes, crypto, quotas, HDFS settings
│   ├── crypto.py            # AES-256-GCM authenticated cipher engine (HKDF key derivation)
│   ├── segmentation.py      # Block slicer & transparent reassembly engine
│   ├── hdfs_engine.py       # Apache HDFS & LAN Distributed Multi-DataNode engine
│   ├── database.py          # SQLite metadata catalog (tenants, users, blocks, quotas)
│   ├── auth.py              # JWT authentication & RBAC authorization
│   ├── tenancy.py           # Multi-tenant isolation & storage quota manager
│   ├── hybrid_cloud.py      # S3/GCS Object storage publisher & Global CDN edge
│   ├── api.py               # FastAPI REST router & static mount
│   ├── cli.py               # Laboratory LAN terminal CLI (`labcloud`)
│   └── static/
│       └── index.html       # Single-Page Web Dashboard (Tailwind CSS, glassmorphism)
├── data/                    # Persistent storage (SQLite DB, HDFS DataNodes, CDN cache)
│   ├── controller_metadata.db
│   ├── hdfs_datanodes/      # Physical DataNode directories (dn-rack1-01, dn-rack1-02, dn-rack2-01)
│   └── public_object_store/ # Hybrid cloud S3/GCS buckets
├── tests/                   # Comprehensive automated test suite
│   ├── test_cloud_controller.py
│   └── test_cli.py
└── README.md
```

---

## Quick Start

### 1. Launch the Cloud Controller Server

```powershell
# In PowerShell:
$env:PYTHONPATH = "C:\Users\<system name>\.gemini\antigravity\scratch\cloud-controller"
python -m cloud_controller
```

Output:
```
===============================================================
Starting Laboratory Cloud Controller on http://0.0.0.0:8080
Multi-Tenant Storage • Apache HDFS • AES-256-GCM • S3/GCS CDN
Web Dashboard: http://localhost:8080
Swagger API Docs: http://localhost:8080/docs
===============================================================
```

### 2. Access the Interactive Web Dashboard
Open your browser to:
[http://localhost:8080](http://localhost:8080)

Use the top-right **Switch User** bar to instantly switch between **Alice (Genomics)**, **Charlie (Quantum)**, or **Superadmin** to observe strict tenant isolation and independent quotas.

---

## CLI Usage (`labcloud`)

Researchers can interact directly with the controller from laboratory terminal workstations:

```powershell
$env:PYTHONPATH = "C:\Users\<system name>\.gemini\antigravity\scratch\cloud-controller"

# 1. Login
python -m cloud_controller.cli login -u alice -p labpassword123

# 2. Check Storage Quota
python -m cloud_controller.cli quota

# 3. Upload a file with 1MB blocks and AES-256-GCM encryption
python -m cloud_controller.cli upload experiment_data.csv --block-size 1048576

# 4. List Tenant Files
python -m cloud_controller.cli list

# 5. Inspect Distributed HDFS Block Replicas
python -m cloud_controller.cli blocks fil_abc123456789

# 6. Check HDFS Cluster Health and Topology
python -m cloud_controller.cli cluster

# 7. Download and Transparently Reassemble
python -m cloud_controller.cli download fil_abc123456789 -o restored_data.csv

# 8. Publish Project Documentation to S3 with CDN URL
python -m cloud_controller.cli publish fil_abc123456789 --provider s3
```

---

## Running the Automated Test Suite

Run all tests via pytest:

```powershell
$env:PYTHONPATH = "C:\Users\<system name>\.gemini\antigravity\scratch\cloud-controller"
pytest tests -v
```

All 8 tests will run and pass:
- `test_aes_256_gcm_roundtrip`: Verifies authenticated encryption and decryption.
- `test_aes_256_gcm_tamper_detection`: Verifies tamper detection when single bits are flipped.
- `test_block_segmentation_and_reassembly`: Tests block slicing and SHA-256 verification.
- `test_hdfs_rack_aware_replication_and_failover`: Simulates DataNode hardware crash and verifies failover to alternate rack replica.
- `test_multi_tenant_isolation`: Confirms Charlie (Quantum Lab) cannot access Alice's (Genomics Lab) files.
- `test_quota_enforcement`: Tests 413 rejection when upload exceeds quota.
- `test_hybrid_cloud_publishing_and_cdn`: Tests S3/GCS publishing and CDN edge cache delivery.
- `test_cli_lifecycle_end_to_end`: Tests terminal CLI lifecycle.
