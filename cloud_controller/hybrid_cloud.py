"""
Hybrid Cloud Publishing Engine (S3 / GCS / CDN).
Enables researchers to publish project documentation, research manuscripts,
and dataset descriptors from local laboratory HDFS storage to public object
storage (AWS S3 / Google Cloud Storage) with global CDN edge delivery URLs.
"""

from typing import Dict, Any, List, Optional
from pathlib import Path
import os
import time
import uuid
import mimetypes

from cloud_controller.config import (
    HYBRID_STORAGE_ROOT,
    AWS_S3_BUCKET,
    GCS_BUCKET,
    CDN_BASE_URL,
)
from cloud_controller.database import get_db_connection


class HybridPublishError(Exception):
    pass


class HybridCloudPublisher:
    """
    Manages hybrid publishing of lab files to public cloud storage (S3/GCS)
    and exposes them through a public CDN caching layer.
    """
    def __init__(self, root_dir: Path = HYBRID_STORAGE_ROOT):
        self.root_dir = root_dir
        self.s3_dir = self.root_dir / "s3"
        self.gcs_dir = self.root_dir / "gcs"
        self.s3_dir.mkdir(parents=True, exist_ok=True)
        self.gcs_dir.mkdir(parents=True, exist_ok=True)

    def publish_file(
        self,
        file_id: str,
        filename: str,
        content: bytes,
        content_type: str,
        tenant_id: str,
        user_id: str,
        provider: str = "s3",  # 's3' or 'gcs'
    ) -> Dict[str, Any]:
        """
        Publishes a file to public object storage (S3 or GCS) with global CDN delivery URL.
        """
        provider = provider.lower()
        if provider not in ("s3", "gcs"):
            raise HybridPublishError("Provider must be either 's3' or 'gcs'")

        bucket = AWS_S3_BUCKET if provider == "s3" else GCS_BUCKET
        object_key = f"{tenant_id}/docs/{uuid.uuid4().hex[:8]}_{filename}"

        # Store in public storage directory
        target_dir = self.s3_dir if provider == "s3" else self.gcs_dir
        file_path = target_dir / object_key
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(file_path, "wb") as f:
            f.write(content)

        # Generate URLs
        if provider == "s3":
            public_url = f"https://{bucket}.s3.amazonaws.com/{object_key}"
        else:
            public_url = f"https://storage.googleapis.com/{bucket}/{object_key}"

        cdn_url = f"{CDN_BASE_URL.rstrip('/')}/{provider}/{object_key}"
        now = time.time()
        pub_id = f"pub_{uuid.uuid4().hex[:12]}"

        # Record publication in database
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO published_docs (id, file_id, tenant_id, user_id, filename, provider, bucket, object_key, public_url, cdn_url, published_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (pub_id, file_id, tenant_id, user_id, filename, provider, bucket, object_key, public_url, cdn_url, now),
        )
        conn.commit()
        conn.close()

        return {
            "id": pub_id,
            "file_id": file_id,
            "filename": filename,
            "provider": provider.upper(),
            "bucket": bucket,
            "object_key": object_key,
            "public_url": public_url,
            "cdn_url": cdn_url,
            "content_type": content_type,
            "size_bytes": len(content),
            "published_at": now,
        }

    def get_published_object(self, provider: str, object_key: str) -> Optional[tuple[bytes, str]]:
        """
        Retrieves published object bytes and guessed MIME type for CDN edge delivery.
        """
        target_dir = self.s3_dir if provider == "s3" else self.gcs_dir
        file_path = target_dir / object_key
        if not file_path.exists():
            return None
        
        content_type, _ = mimetypes.guess_type(file_path.name)
        if not content_type:
            content_type = "application/octet-stream"
            
        with open(file_path, "rb") as f:
            return f.read(), content_type

    def list_published(self, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cur = conn.cursor()
        if tenant_id:
            cur.execute("SELECT * FROM published_docs WHERE tenant_id = ? ORDER BY published_at DESC", (tenant_id,))
        else:
            cur.execute("SELECT * FROM published_docs ORDER BY published_at DESC")
        rows = cur.fetchall()
        conn.close()
        return [dict(r) for r in rows]


_publisher_instance = None


def get_publisher() -> HybridCloudPublisher:
    global _publisher_instance
    if _publisher_instance is None:
        _publisher_instance = HybridCloudPublisher()
    return _publisher_instance
