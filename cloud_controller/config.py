"""
Configuration module for the Lightweight Laboratory Cloud Controller.
Handles LAN endpoints, HDFS storage parameters, AES-256-GCM crypto settings,
multi-tenant quotas, and hybrid cloud publishing endpoints.
"""

from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Database
DB_PATH = DATA_DIR / "controller_metadata.db"

# HDFS Cluster Simulation & Storage
HDFS_MODE = os.getenv("HDFS_MODE", "cluster")  # 'cluster' (built-in distributed) or 'webhdfs' (live external)
WEBHDFS_URL = os.getenv("WEBHDFS_URL", "http://localhost:9870/webhdfs/v1")
WEBHDFS_USER = os.getenv("WEBHDFS_USER", "labuser")

# DataNode storage paths for distributed LAN cluster
HDFS_STORAGE_ROOT = DATA_DIR / "hdfs_datanodes"
HDFS_STORAGE_ROOT.mkdir(parents=True, exist_ok=True)

DATANODE_CONFIGS = [
    {"id": "dn-rack1-01", "rack": "/rack-1", "host": "192.168.1.101", "capacity_bytes": 100 * 1024 * 1024},  # 100MB
    {"id": "dn-rack1-02", "rack": "/rack-1", "host": "192.168.1.102", "capacity_bytes": 100 * 1024 * 1024},  # 100MB
    {"id": "dn-rack2-01", "rack": "/rack-2", "host": "192.168.1.201", "capacity_bytes": 100 * 1024 * 1024},  # 100MB
]

# Block Segmentation Defaults
DEFAULT_BLOCK_SIZE = int(os.getenv("DEFAULT_BLOCK_SIZE", 1024 * 1024))  # 1 MB
MIN_BLOCK_SIZE = 64 * 1024  # 64 KB
MAX_BLOCK_SIZE = 64 * 1024 * 1024  # 64 MB
DEFAULT_REPLICATION_FACTOR = int(os.getenv("DEFAULT_REPLICATION_FACTOR", 2))

# Cryptography - AES-256-GCM
AES_MASTER_KEY_SECRET = os.getenv("AES_MASTER_KEY_SECRET", "super-secret-lab-aes-master-key-32b-length!!")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "jwt-lab-cloud-controller-secret-key-2026")
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

# Default Quotas
DEFAULT_USER_QUOTA = 20 * 1024 * 1024  # 20 MB per user
DEFAULT_TENANT_QUOTA = 100 * 1024 * 1024  # 100 MB per lab tenant

# Hybrid Cloud (S3 / GCS / CDN)
HYBRID_STORAGE_ROOT = DATA_DIR / "public_object_store"
HYBRID_STORAGE_ROOT.mkdir(parents=True, exist_ok=True)

AWS_S3_BUCKET = os.getenv("AWS_S3_BUCKET", "lab-genomics-public-docs")
GCS_BUCKET = os.getenv("GCS_BUCKET", "lab-quantum-public-archive")
CDN_BASE_URL = os.getenv("CDN_BASE_URL", "http://localhost:8080/cdn")

# Server binding
CONTROLLER_HOST = os.getenv("CONTROLLER_HOST", "0.0.0.0")
CONTROLLER_PORT = int(os.getenv("CONTROLLER_PORT", 8080))
