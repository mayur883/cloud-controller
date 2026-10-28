"""
REST API Router and FastAPI Application for the Cloud Controller.
Implements file upload/download/list/delete with automatic block segmentation,
AES-256-GCM authenticated encryption, multi-tenant isolation, HDFS clustering,
per-user storage quotas, and hybrid cloud publishing.
"""

from typing import Optional, List, Dict, Any
from pathlib import Path
import os
import uuid
import time
import json
import mimetypes

from fastapi import (
    FastAPI,
    UploadFile,
    File,
    Form,
    Depends,
    HTTPException,
    status,
    Response,
    Query,
)
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from cloud_controller.config import (
    DEFAULT_BLOCK_SIZE,
    DEFAULT_REPLICATION_FACTOR,
    MIN_BLOCK_SIZE,
    MAX_BLOCK_SIZE,
)
from cloud_controller.database import (
    get_db_connection,
    get_user_by_username,
    verify_password,
    get_user_storage_usage,
    get_tenant_storage_usage,
)
from cloud_controller.auth import (
    create_access_token,
    get_current_user,
    require_role,
)
from cloud_controller.segmentation import (
    segment_data,
    reassemble_data,
    SegmentMetadata,
    compute_sha256,
)
from cloud_controller.hdfs_engine import get_hdfs_engine
from cloud_controller.tenancy import (
    check_quota_available,
    get_quota_summary,
    validate_tenant_file_access,
)
from cloud_controller.hybrid_cloud import get_publisher

app = FastAPI(
    title="Lightweight Laboratory Cloud Controller",
    description="Multi-tenant LAN file storage controller with Apache HDFS, AES-256-GCM, and Hybrid S3/GCS CDN.",
    version="1.0.0",
)

# CORS Middleware for LAN access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class LoginRequest(BaseModel):
    username: str
    password: str


class PublishRequest(BaseModel):
    file_id: str
    provider: str = "s3"  # 's3' or 'gcs'


class QuotaUpdateRequest(BaseModel):
    user_id: Optional[str] = None
    tenant_id: Optional[str] = None
    quota_mb: int


class NodeToggleRequest(BaseModel):
    online: bool


# ==========================================
# Authentication Endpoints
# ==========================================

@app.post("/api/v1/auth/login")
async def login(req: LoginRequest, response: Response):
    user = get_user_by_username(req.username)
    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    token = create_access_token(user)
    # Set HTTP-only cookie for easy browser UI access
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=86400,
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "tenant_id": user["tenant_id"],
        },
    }


@app.post("/api/v1/auth/logout")
async def logout(response: Response):
    response.delete_cookie(key="access_token")
    return {"message": "Logged out successfully"}


@app.get("/api/v1/auth/me")
async def get_me(user: Dict[str, Any] = Depends(get_current_user)):
    quota_info = get_quota_summary(user)
    return {
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "tenant_id": user["tenant_id"],
        },
        "quota": quota_info,
    }


# ==========================================
# File Storage Endpoints (Upload/List/Get/Delete)
# ==========================================

@app.post("/api/v1/files/upload")
async def upload_file(
    file: UploadFile = File(...),
    block_size: int = Form(DEFAULT_BLOCK_SIZE),
    encrypt: bool = Form(True),
    replication: int = Form(DEFAULT_REPLICATION_FACTOR),
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Uploads a file to the Cloud Controller.
    1. Enforces tenant and per-user storage quotas.
    2. Divides payload into configurable blocks.
    3. Encrypts blocks with AES-256-GCM (tamper-evident).
    4. Distributes blocks across HDFS DataNodes with replication.
    5. Records metadata in SQLite catalog.
    """
    if block_size < MIN_BLOCK_SIZE or block_size > MAX_BLOCK_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Block size must be between {MIN_BLOCK_SIZE} bytes (64KB) and {MAX_BLOCK_SIZE} bytes (64MB)",
        )

    content = await file.read()
    file_size = len(content)

    # 1. Quota Enforcement
    allowed, reason = check_quota_available(user, file_size)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=reason,
        )

    file_id = f"fil_{uuid.uuid4().hex[:12]}"
    tenant_id = user["tenant_id"]
    content_type = file.content_type or "application/octet-stream"
    overall_checksum = compute_sha256(content)

    # 2. Block Segmentation & AES-256-GCM Encryption
    try:
        segments = segment_data(
            data=content,
            block_size=block_size,
            file_id=file_id,
            tenant_id=tenant_id,
            encrypt=encrypt,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Segmentation failed: {str(e)}",
        )

    # 3. Distributed HDFS Block Placement
    hdfs = get_hdfs_engine()
    block_records = []
    
    for meta, block_bytes in segments:
        hdfs_rel_path = f"{tenant_id}/{file_id}/{meta.block_id}.blk"
        try:
            replica_nodes = hdfs.write_block(
                block_rel_path=hdfs_rel_path,
                data=block_bytes,
                replication_factor=replication,
            )
        except Exception as e:
            # Clean up previously written blocks if failure occurs
            for prev_meta, _ in segments[:meta.block_index]:
                prev_path = f"{tenant_id}/{file_id}/{prev_meta.block_id}.blk"
                hdfs.delete_block(prev_path)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"HDFS block distribution failed: {str(e)}",
            )

        block_records.append((
            str(uuid.uuid4()),
            file_id,
            meta.block_index,
            meta.block_id,
            meta.offset,
            meta.raw_size,
            meta.stored_size,
            meta.checksum_sha256,
            1 if meta.is_encrypted else 0,
            meta.nonce_hex,
            meta.salt_hex,
            json.dumps(replica_nodes),
            time.time(),
        ))

    # 4. Save file & block catalog to Database
    now = time.time()
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO files (id, tenant_id, user_id, filename, content_type, total_size, block_size, num_blocks, is_encrypted, checksum, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            file_id,
            tenant_id,
            user["id"],
            file.filename,
            content_type,
            file_size,
            block_size,
            len(segments),
            1 if encrypt else 0,
            overall_checksum,
            now,
        ),
    )

    cur.executemany(
        """
        INSERT INTO blocks (id, file_id, block_index, block_id, offset, raw_size, stored_size, checksum_sha256, is_encrypted, nonce_hex, salt_hex, replica_nodes, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        block_records,
    )
    conn.commit()
    conn.close()

    return {
        "file_id": file_id,
        "filename": file.filename,
        "size_bytes": file_size,
        "block_size": block_size,
        "num_blocks": len(segments),
        "is_encrypted": encrypt,
        "encryption_algorithm": "AES-256-GCM" if encrypt else "None",
        "replication_factor": replication,
        "checksum_sha256": overall_checksum,
        "created_at": now,
    }


@app.get("/api/v1/files")
async def list_files(user: Dict[str, Any] = Depends(get_current_user)):
    """
    Lists all files belonging to the authenticated tenant organization.
    Superadmin sees all files across tenants.
    """
    conn = get_db_connection()
    cur = conn.cursor()

    if user["role"] == "superadmin":
        cur.execute("SELECT f.*, u.username as uploader FROM files f JOIN users u ON f.user_id = u.id ORDER BY f.created_at DESC")
    else:
        cur.execute(
            "SELECT f.*, u.username as uploader FROM files f JOIN users u ON f.user_id = u.id WHERE f.tenant_id = ? ORDER BY f.created_at DESC",
            (user["tenant_id"],),
        )
    rows = cur.fetchall()
    conn.close()

    files = []
    for r in rows:
        d = dict(r)
        d["is_encrypted"] = bool(d["is_encrypted"])
        files.append(d)

    return {"files": files, "count": len(files)}


@app.get("/api/v1/files/{file_id}/download")
async def download_file(
    file_id: str,
    delivery: str = Query("decrypted", pattern="^(decrypted|encrypted_envelope)$"),
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Downloads and transparently reassembles file blocks from HDFS.
    Verifies AES-256-GCM authentication tags and SHA-256 block checksums.
    Fails over automatically across healthy DataNode replicas if a node is down.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM files WHERE id = ?", (file_id,))
    f_row = cur.fetchone()

    if not f_row:
        conn.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")

    file_record = dict(f_row)
    validate_tenant_file_access(user, file_record)

    cur.execute("SELECT * FROM blocks WHERE file_id = ? ORDER BY block_index ASC", (file_id,))
    block_rows = cur.fetchall()
    conn.close()

    hdfs = get_hdfs_engine()
    segments_to_reassemble = []

    for b in block_rows:
        b_dict = dict(b)
        replica_nodes = json.loads(b_dict["replica_nodes"])
        hdfs_rel_path = f"{file_record['tenant_id']}/{file_id}/{b_dict['block_id']}.blk"

        try:
            block_data = hdfs.read_block(hdfs_rel_path, replica_nodes)
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to read block {b_dict['block_id']} from HDFS replicas: {str(e)}",
            )

        meta = SegmentMetadata(
            block_id=b_dict["block_id"],
            block_index=b_dict["block_index"],
            offset=b_dict["offset"],
            raw_size=b_dict["raw_size"],
            stored_size=b_dict["stored_size"],
            checksum_sha256=b_dict["checksum_sha256"],
            is_encrypted=bool(b_dict["is_encrypted"]),
            nonce_hex=b_dict["nonce_hex"],
            salt_hex=b_dict["salt_hex"],
        )
        segments_to_reassemble.append((meta, block_data))

    try:
        reassembled_data = reassemble_data(
            segments_to_reassemble,
            tenant_id=file_record["tenant_id"],
            file_id=file_id,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Data integrity or decryption error during reassembly: {str(e)}",
        )

    # Deliver file
    return Response(
        content=reassembled_data,
        media_type=file_record["content_type"],
        headers={
            "Content-Disposition": f'attachment; filename="{file_record["filename"]}"',
            "X-Payload-Checksum": file_record["checksum"],
            "X-Encryption": "AES-256-GCM" if file_record["is_encrypted"] else "None",
        },
    )


@app.get("/api/v1/files/{file_id}/blocks")
async def get_file_blocks(file_id: str, user: Dict[str, Any] = Depends(get_current_user)):
    """
    Returns structural block segments, checksums, and HDFS DataNode allocations for a file.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM files WHERE id = ?", (file_id,))
    f_row = cur.fetchone()
    if not f_row:
        conn.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")

    file_record = dict(f_row)
    validate_tenant_file_access(user, file_record)

    cur.execute("SELECT * FROM blocks WHERE file_id = ? ORDER BY block_index ASC", (file_id,))
    block_rows = cur.fetchall()
    conn.close()

    blocks = []
    for r in block_rows:
        b = dict(r)
        b["replica_nodes"] = json.loads(b["replica_nodes"])
        b["is_encrypted"] = bool(b["is_encrypted"])
        blocks.append(b)

    return {
        "file_id": file_id,
        "filename": file_record["filename"],
        "num_blocks": file_record["num_blocks"],
        "block_size": file_record["block_size"],
        "total_size": file_record["total_size"],
        "blocks": blocks,
    }


@app.delete("/api/v1/files/{file_id}")
async def delete_file(file_id: str, user: Dict[str, Any] = Depends(get_current_user)):
    """
    Deletes a file and all distributed block replicas across HDFS DataNodes, releasing storage quota.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM files WHERE id = ?", (file_id,))
    f_row = cur.fetchone()
    if not f_row:
        conn.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")

    file_record = dict(f_row)
    validate_tenant_file_access(user, file_record)

    # Fetch blocks to delete from HDFS
    cur.execute("SELECT block_id, replica_nodes FROM blocks WHERE file_id = ?", (file_id,))
    blocks = cur.fetchall()

    hdfs = get_hdfs_engine()
    for b in blocks:
        block_id = b["block_id"]
        replica_nodes = json.loads(b["replica_nodes"])
        hdfs_rel_path = f"{file_record['tenant_id']}/{file_id}/{block_id}.blk"
        try:
            hdfs.delete_block(hdfs_rel_path, replica_nodes)
        except Exception:
            pass

    cur.execute("DELETE FROM files WHERE id = ?", (file_id,))
    cur.execute("DELETE FROM blocks WHERE file_id = ?", (file_id,))
    cur.execute("DELETE FROM published_docs WHERE file_id = ?", (file_id,))
    conn.commit()
    conn.close()

    return {"message": f"File {file_record['filename']} and all HDFS blocks deleted successfully."}


# ==========================================
# Quota & Storage Analytics
# ==========================================

@app.get("/api/v1/quota")
async def get_quota(user: Dict[str, Any] = Depends(get_current_user)):
    return get_quota_summary(user)


# ==========================================
# HDFS Cluster Health & Fault Simulation
# ==========================================

@app.get("/api/v1/cluster/status")
async def cluster_status(user: Dict[str, Any] = Depends(get_current_user)):
    hdfs = get_hdfs_engine()
    return hdfs.get_cluster_status()


@app.post("/api/v1/cluster/nodes/{node_id}/toggle")
async def toggle_node(
    node_id: str,
    req: NodeToggleRequest,
    user: Dict[str, Any] = Depends(require_role(["superadmin", "admin"])),
):
    """
    Simulates taking an HDFS DataNode offline or bringing it back online.
    Allows testing transparent replica failover.
    """
    hdfs = get_hdfs_engine()
    if hasattr(hdfs, "toggle_node"):
        res = hdfs.toggle_node(node_id, req.online)
        return {"message": f"Node {node_id} state set to {'online' if req.online else 'offline'}", "node": res}
    raise HTTPException(status_code=400, detail="Cluster node toggle not supported in this mode.")


# ==========================================
# Hybrid Cloud Publishing & CDN Endpoints
# ==========================================

@app.post("/api/v1/publish")
async def publish_file_to_cloud(
    req: PublishRequest,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Publishes a project file or research document from HDFS to public cloud object storage (S3/GCS)
    and generates global CDN access links.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM files WHERE id = ?", (req.file_id,))
    f_row = cur.fetchone()
    if not f_row:
        conn.close()
        raise HTTPException(status_code=404, detail="File not found")

    file_record = dict(f_row)
    validate_tenant_file_access(user, file_record)

    # Reassemble file data from HDFS
    cur.execute("SELECT * FROM blocks WHERE file_id = ? ORDER BY block_index ASC", (req.file_id,))
    block_rows = cur.fetchall()
    conn.close()

    hdfs = get_hdfs_engine()
    segments = []
    for b in block_rows:
        b_dict = dict(b)
        replica_nodes = json.loads(b_dict["replica_nodes"])
        hdfs_rel_path = f"{file_record['tenant_id']}/{req.file_id}/{b_dict['block_id']}.blk"
        data = hdfs.read_block(hdfs_rel_path, replica_nodes)
        meta = SegmentMetadata(
            block_id=b_dict["block_id"],
            block_index=b_dict["block_index"],
            offset=b_dict["offset"],
            raw_size=b_dict["raw_size"],
            stored_size=b_dict["stored_size"],
            checksum_sha256=b_dict["checksum_sha256"],
            is_encrypted=bool(b_dict["is_encrypted"]),
            nonce_hex=b_dict["nonce_hex"],
            salt_hex=b_dict["salt_hex"],
        )
        segments.append((meta, data))

    content = reassemble_data(segments, tenant_id=file_record["tenant_id"], file_id=req.file_id)

    # Publish to S3 or GCS
    pub = get_publisher()
    result = pub.publish_file(
        file_id=req.file_id,
        filename=file_record["filename"],
        content=content,
        content_type=file_record["content_type"],
        tenant_id=file_record["tenant_id"],
        user_id=user["id"],
        provider=req.provider,
    )
    return result


@app.get("/api/v1/published")
async def list_published(user: Dict[str, Any] = Depends(get_current_user)):
    pub = get_publisher()
    tenant_filter = None if user["role"] == "superadmin" else user["tenant_id"]
    return {"published_docs": pub.list_published(tenant_filter)}


@app.get("/cdn/{provider}/{object_key:path}")
async def cdn_edge_delivery(provider: str, object_key: str):
    """
    Public CDN endpoint delivering cached project documentation with Edge Cache-Control headers.
    """
    pub = get_publisher()
    item = pub.get_published_object(provider, object_key)
    if not item:
        raise HTTPException(status_code=404, detail="Document not found on CDN edge")

    content, content_type = item
    return Response(
        content=content,
        media_type=content_type,
        headers={
            "Cache-Control": "public, max-age=86400, stale-while-revalidate=3600",
            "CDN-Cache-Status": "HIT",
            "Access-Control-Allow-Origin": "*",
        },
    )


# ==========================================
# Admin Endpoints
# ==========================================

@app.get("/api/v1/admin/tenants")
async def list_tenants(user: Dict[str, Any] = Depends(require_role(["superadmin"]))):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM tenants")
    tenants = [dict(r) for r in cur.fetchall()]
    for t in tenants:
        t["used_bytes"] = get_tenant_storage_usage(t["id"])
    conn.close()
    return {"tenants": tenants}


@app.post("/api/v1/admin/quotas")
async def update_quota(
    req: QuotaUpdateRequest,
    user: Dict[str, Any] = Depends(require_role(["superadmin", "admin"])),
):
    conn = get_db_connection()
    cur = conn.cursor()
    new_bytes = req.quota_mb * 1024 * 1024

    if req.user_id:
        cur.execute("UPDATE users SET quota_bytes = ? WHERE id = ?", (new_bytes, req.user_id))
    elif req.tenant_id:
        if user["role"] != "superadmin":
            conn.close()
            raise HTTPException(status_code=403, detail="Only superadmin can update tenant quotas")
        cur.execute("UPDATE tenants SET quota_bytes = ? WHERE id = ?", (new_bytes, req.tenant_id))

    conn.commit()
    conn.close()
    return {"message": "Quota updated successfully", "quota_mb": req.quota_mb}


# ==========================================
# Web Dashboard Frontend
# ==========================================

STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Cloud Controller Dashboard</h1><p>static/index.html not found</p>"
