"""
Metadata Database and Tenancy Catalog.
Provides thread-safe SQLite persistence for tenants, users, file catalogs,
block segment tracking, replication records, and storage quotas.
"""

import sqlite3
import hashlib
import json
import time
from typing import Dict, List, Optional, Any
from pathlib import Path
from cloud_controller.config import DB_PATH, DEFAULT_USER_QUOTA, DEFAULT_TENANT_QUOTA


def get_db_connection():
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    """Hashes password with SHA-256 + salt for secure storage."""
    salt = "lab_controller_salt_2026"
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


def verify_password(plain: str, hashed: str) -> bool:
    return hash_password(plain) == hashed


def init_db():
    """Initializes tables and seeds default tenants and users."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS tenants (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        quota_bytes INTEGER NOT NULL,
        created_at REAL NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL, -- 'superadmin', 'admin', 'researcher', 'auditor'
        quota_bytes INTEGER NOT NULL,
        created_at REAL NOT NULL,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS files (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        filename TEXT NOT NULL,
        content_type TEXT NOT NULL,
        total_size INTEGER NOT NULL,
        block_size INTEGER NOT NULL,
        num_blocks INTEGER NOT NULL,
        is_encrypted INTEGER NOT NULL,
        checksum TEXT NOT NULL,
        created_at REAL NOT NULL,
        FOREIGN KEY (tenant_id) REFERENCES tenants(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS blocks (
        id TEXT PRIMARY KEY,
        file_id TEXT NOT NULL,
        block_index INTEGER NOT NULL,
        block_id TEXT NOT NULL,
        offset INTEGER NOT NULL,
        raw_size INTEGER NOT NULL,
        stored_size INTEGER NOT NULL,
        checksum_sha256 TEXT NOT NULL,
        is_encrypted INTEGER NOT NULL,
        nonce_hex TEXT,
        salt_hex TEXT,
        replica_nodes TEXT NOT NULL, -- JSON array of node IDs
        created_at REAL NOT NULL,
        FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS published_docs (
        id TEXT PRIMARY KEY,
        file_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        filename TEXT NOT NULL,
        provider TEXT NOT NULL, -- 's3' or 'gcs'
        bucket TEXT NOT NULL,
        object_key TEXT NOT NULL,
        public_url TEXT NOT NULL,
        cdn_url TEXT NOT NULL,
        published_at REAL NOT NULL,
        FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
    )
    """)

    conn.commit()

    # Seed default tenants if table is empty
    cursor.execute("SELECT COUNT(*) FROM tenants")
    if cursor.fetchone()[0] == 0:
        now = time.time()
        tenants = [
            ("system", "System Administration", 10 * 1024 * 1024 * 1024, now),
            ("genomics-lab", "Genomics Core Laboratory", 50 * 1024 * 1024, now),
            ("quantum-lab", "Quantum Optics Laboratory", 30 * 1024 * 1024, now),
        ]
        cursor.executemany("INSERT INTO tenants VALUES (?, ?, ?, ?)", tenants)

        users = [
            ("usr_superadmin", "system", "superadmin", hash_password("labadmin2026"), "superadmin", 1024 * 1024 * 1024, now),
            ("usr_alice", "genomics-lab", "alice", hash_password("labpassword123"), "admin", 25 * 1024 * 1024, now),
            ("usr_bob", "genomics-lab", "bob", hash_password("labpassword123"), "researcher", 20 * 1024 * 1024, now),
            ("usr_charlie", "quantum-lab", "charlie", hash_password("labpassword123"), "researcher", 15 * 1024 * 1024, now),
        ]
        cursor.executemany("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?)", users)
        conn.commit()

    conn.close()


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def get_tenant_by_id(tenant_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM tenants WHERE id = ?", (tenant_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_storage_usage(user_id: str) -> int:
    """Calculates sum of raw total_size of all files owned by user."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT COALESCE(SUM(total_size), 0) FROM files WHERE user_id = ?", (user_id,))
    usage = cur.fetchone()[0]
    conn.close()
    return int(usage)


def get_tenant_storage_usage(tenant_id: str) -> int:
    """Calculates sum of raw total_size of all files in tenant."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT COALESCE(SUM(total_size), 0) FROM files WHERE tenant_id = ?", (tenant_id,))
    usage = cur.fetchone()[0]
    conn.close()
    return int(usage)


def get_file_count(tenant_id: str, user_id: Optional[str] = None) -> int:
    conn = get_db_connection()
    cur = conn.cursor()
    if user_id:
        cur.execute("SELECT COUNT(*) FROM files WHERE tenant_id = ? AND user_id = ?", (tenant_id, user_id))
    else:
        cur.execute("SELECT COUNT(*) FROM files WHERE tenant_id = ?", (tenant_id,))
    count = cur.fetchone()[0]
    conn.close()
    return int(count)


# Initialize DB immediately upon load
init_db()
