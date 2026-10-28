"""
Block Segmentation and Reassembly Engine.
Handles automatic division of files into configurable size blocks during upload,
calculates block-level SHA-256 checksums, integrates AES-256-GCM encryption,
and performs transparent stream reassembly on download.
"""

from typing import List, Tuple, Generator, BinaryIO, Optional
from dataclasses import dataclass, asdict
import hashlib
import uuid
import io

from cloud_controller.crypto import (
    encrypt_aes_256_gcm,
    decrypt_aes_256_gcm,
    get_tenant_key,
    IntegrityError,
)
from cloud_controller.config import DEFAULT_BLOCK_SIZE


@dataclass
class SegmentMetadata:
    block_id: str
    block_index: int
    offset: int
    raw_size: int
    stored_size: int
    checksum_sha256: str
    is_encrypted: bool
    nonce_hex: Optional[str] = None
    salt_hex: Optional[str] = None

    def to_dict(self):
        return asdict(self)


class SegmentationError(Exception):
    pass


def compute_sha256(data: bytes) -> str:
    """Computes SHA-256 hex digest of data."""
    return hashlib.sha256(data).hexdigest()


def segment_data(
    data: bytes,
    block_size: int = DEFAULT_BLOCK_SIZE,
    file_id: Optional[str] = None,
    tenant_id: str = "default",
    encrypt: bool = True,
) -> List[Tuple[SegmentMetadata, bytes]]:
    """
    Divides in-memory bytes into discrete blocks.
    Optionally encrypts each block using AES-256-GCM with per-tenant derived key.
    
    Returns:
        List of (SegmentMetadata, block_bytes_to_store)
    """
    if block_size <= 0:
        raise SegmentationError(f"Invalid block size: {block_size}")

    if not file_id:
        file_id = str(uuid.uuid4())

    total_len = len(data)
    segments = []
    offset = 0
    block_index = 0

    # Special case: empty file creates 1 empty block
    if total_len == 0:
        raw_chunk = b""
        chunk_hash = compute_sha256(raw_chunk)
        block_id = f"blk_{file_id}_{block_index:04d}"
        
        if encrypt:
            aad = f"{tenant_id}:{file_id}:{block_index}".encode("utf-8")
            ct_with_tag, nonce, salt = encrypt_aes_256_gcm(
                raw_chunk,
                key=None,
                associated_data=aad,
            )
            # Use tenant key
            t_key = get_tenant_key(tenant_id, salt)
            ct_with_tag, nonce, salt = encrypt_aes_256_gcm(
                raw_chunk,
                key=t_key,
                associated_data=aad,
                salt=salt
            )
            meta = SegmentMetadata(
                block_id=block_id,
                block_index=block_index,
                offset=0,
                raw_size=0,
                stored_size=len(ct_with_tag),
                checksum_sha256=chunk_hash,
                is_encrypted=True,
                nonce_hex=nonce.hex(),
                salt_hex=salt.hex(),
            )
            return [(meta, ct_with_tag)]
        else:
            meta = SegmentMetadata(
                block_id=block_id,
                block_index=block_index,
                offset=0,
                raw_size=0,
                stored_size=0,
                checksum_sha256=chunk_hash,
                is_encrypted=False,
            )
            return [(meta, raw_chunk)]

    while offset < total_len:
        raw_chunk = data[offset : offset + block_size]
        raw_size = len(raw_chunk)
        chunk_hash = compute_sha256(raw_chunk)
        block_id = f"blk_{file_id}_{block_index:04d}"

        if encrypt:
            aad = f"{tenant_id}:{file_id}:{block_index}".encode("utf-8")
            import os
            salt = os.urandom(16)
            t_key = get_tenant_key(tenant_id, salt)
            ct_with_tag, nonce, salt = encrypt_aes_256_gcm(
                raw_chunk,
                key=t_key,
                associated_data=aad,
                salt=salt
            )
            stored_chunk = ct_with_tag
            stored_size = len(stored_chunk)
            meta = SegmentMetadata(
                block_id=block_id,
                block_index=block_index,
                offset=offset,
                raw_size=raw_size,
                stored_size=stored_size,
                checksum_sha256=chunk_hash,
                is_encrypted=True,
                nonce_hex=nonce.hex(),
                salt_hex=salt.hex(),
            )
        else:
            stored_chunk = raw_chunk
            stored_size = raw_size
            meta = SegmentMetadata(
                block_id=block_id,
                block_index=block_index,
                offset=offset,
                raw_size=raw_size,
                stored_size=stored_size,
                checksum_sha256=chunk_hash,
                is_encrypted=False,
            )

        segments.append((meta, stored_chunk))
        offset += raw_size
        block_index += 1

    return segments


def reassemble_data(
    segments: List[Tuple[SegmentMetadata, bytes]],
    tenant_id: str = "default",
    file_id: Optional[str] = None,
) -> bytes:
    """
    Reassembles stored blocks in sequential order into the original file content.
    Transparently decrypts AES-256-GCM blocks and verifies cryptographic authentication tags
    and SHA-256 content hashes.
    """
    # Sort by block_index
    sorted_segments = sorted(segments, key=lambda x: x[0].block_index)
    output = bytearray()

    for idx, (meta, block_data) in enumerate(sorted_segments):
        if meta.block_index != idx:
            raise SegmentationError(f"Missing block at index {idx}; found index {meta.block_index}")

        if meta.is_encrypted:
            if not meta.nonce_hex or not meta.salt_hex:
                raise SegmentationError(f"Block {meta.block_id} is marked encrypted but missing nonce/salt")
            
            nonce = bytes.fromhex(meta.nonce_hex)
            salt = bytes.fromhex(meta.salt_hex)
            t_key = get_tenant_key(tenant_id, salt)
            
            f_id = file_id if file_id else (meta.block_id.split("_")[1] if "_" in meta.block_id else "")
            aad = f"{tenant_id}:{f_id}:{meta.block_index}".encode("utf-8")
            
            try:
                decrypted_chunk = decrypt_aes_256_gcm(
                    ciphertext_with_tag=block_data,
                    nonce=nonce,
                    key=t_key,
                    associated_data=aad,
                )
            except IntegrityError as exc:
                raise IntegrityError(
                    f"Integrity check failed for block {meta.block_id} (index {meta.block_index}): {str(exc)}"
                ) from exc
            
            # Verify SHA-256 checksum of recovered plaintext
            recovered_hash = compute_sha256(decrypted_chunk)
            if recovered_hash != meta.checksum_sha256:
                raise IntegrityError(
                    f"Checksum mismatch for block {meta.block_id}: expected {meta.checksum_sha256}, got {recovered_hash}"
                )
            
            output.extend(decrypted_chunk)
        else:
            # Unencrypted block - verify SHA-256 checksum
            current_hash = compute_sha256(block_data)
            if current_hash != meta.checksum_sha256:
                raise IntegrityError(
                    f"Checksum mismatch for unencrypted block {meta.block_id}: expected {meta.checksum_sha256}, got {current_hash}"
                )
            output.extend(block_data)

    return bytes(output)
