"""
Multi-Tenant Isolation and Storage Quota Management.
Enforces strict tenant boundary isolation, calculates storage usage,
and enforces atomic per-user and per-organization storage quotas.
"""

from typing import Dict, Any, Tuple
from fastapi import HTTPException, status

from cloud_controller.database import (
    get_user_storage_usage,
    get_tenant_storage_usage,
    get_tenant_by_id,
    get_file_count,
)


class QuotaExceededError(Exception):
    pass


def check_quota_available(user: Dict[str, Any], additional_bytes: int) -> Tuple[bool, str]:
    """
    Validates if adding additional_bytes would breach either the user quota or tenant quota.
    """
    user_id = user["id"]
    tenant_id = user["tenant_id"]
    user_quota = user["quota_bytes"]

    # 1. Check per-user quota
    current_user_usage = get_user_storage_usage(user_id)
    if current_user_usage + additional_bytes > user_quota:
        limit_mb = round(user_quota / (1024 * 1024), 2)
        curr_mb = round(current_user_usage / (1024 * 1024), 2)
        req_mb = round(additional_bytes / (1024 * 1024), 2)
        return False, (
            f"User storage quota exceeded. Current: {curr_mb}MB, "
            f"Uploading: {req_mb}MB, Limit: {limit_mb}MB"
        )

    # 2. Check per-tenant quota
    tenant = get_tenant_by_id(tenant_id)
    if tenant:
        tenant_quota = tenant["quota_bytes"]
        current_tenant_usage = get_tenant_storage_usage(tenant_id)
        if current_tenant_usage + additional_bytes > tenant_quota:
            limit_mb = round(tenant_quota / (1024 * 1024), 2)
            curr_mb = round(current_tenant_usage / (1024 * 1024), 2)
            req_mb = round(additional_bytes / (1024 * 1024), 2)
            return False, (
                f"Tenant organization '{tenant['name']}' storage quota exceeded. "
                f"Current: {curr_mb}MB, Uploading: {req_mb}MB, Limit: {limit_mb}MB"
            )

    return True, "OK"


def get_quota_summary(user: Dict[str, Any]) -> Dict[str, Any]:
    """
    Retrieves a comprehensive snapshot of quota consumption for the current user and tenant.
    """
    user_id = user["id"]
    tenant_id = user["tenant_id"]
    tenant = get_tenant_by_id(tenant_id)

    user_usage = get_user_storage_usage(user_id)
    user_quota = user["quota_bytes"]
    user_pct = round((user_usage / user_quota) * 100, 2) if user_quota > 0 else 0

    tenant_usage = get_tenant_storage_usage(tenant_id)
    tenant_quota = tenant["quota_bytes"] if tenant else 0
    tenant_pct = round((tenant_usage / tenant_quota) * 100, 2) if tenant_quota > 0 else 0

    file_count = get_file_count(tenant_id, user_id)

    return {
        "user": {
            "id": user_id,
            "username": user["username"],
            "role": user["role"],
            "used_bytes": user_usage,
            "quota_bytes": user_quota,
            "free_bytes": max(0, user_quota - user_usage),
            "usage_pct": user_pct,
            "quota_mb": round(user_quota / (1024 * 1024), 2),
            "used_mb": round(user_usage / (1024 * 1024), 2),
            "files_count": file_count,
        },
        "tenant": {
            "id": tenant_id,
            "name": tenant["name"] if tenant else "Unknown",
            "used_bytes": tenant_usage,
            "quota_bytes": tenant_quota,
            "free_bytes": max(0, tenant_quota - tenant_usage),
            "usage_pct": tenant_pct,
            "quota_mb": round(tenant_quota / (1024 * 1024), 2),
            "used_mb": round(tenant_usage / (1024 * 1024), 2),
            "total_tenant_files": get_file_count(tenant_id),
        }
    }


def validate_tenant_file_access(user: Dict[str, Any], file_record: Dict[str, Any]):
    """
    Ensures that a user can only access, download, or delete files belonging to their tenant.
    """
    if user["role"] == "superadmin":
        return
    if file_record["tenant_id"] != user["tenant_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: file belongs to another tenant organization",
        )
