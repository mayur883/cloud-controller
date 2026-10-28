"""
Cryptographic Engine for the Cloud Controller.
Implements AES-256-GCM authenticated encryption and decryption for data in transit
and at rest, with HKDF key derivation and tamper-evident authentication tags.
"""

from typing import Tuple, Optional
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from cloud_controller.config import AES_MASTER_KEY_SECRET

NONCE_SIZE_BYTES = 12  # Standard 96-bit nonce for AES-GCM
KEY_SIZE_BYTES = 32    # 256-bit AES key
SALT_SIZE_BYTES = 16   # 128-bit salt for HKDF
TAG_SIZE_BYTES = 16    # 128-bit authentication tag


class CryptoError(Exception):
    """Raised when cryptographic operations or integrity checks fail."""
    pass


class IntegrityError(CryptoError):
    """Raised when an authentication tag fails verification (tamper detection)."""
    pass


def derive_key(secret: str, salt: bytes, context_info: bytes = b"lab-cloud-controller-aes-gcm") -> bytes:
    """
    Derives a 256-bit AES key from a passphrase/master secret and salt using HKDF-SHA256.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE_BYTES,
        salt=salt,
        info=context_info,
    )
    return hkdf.derive(secret.encode("utf-8") if isinstance(secret, str) else secret)


def get_tenant_key(tenant_id: str, salt: bytes) -> bytes:
    """
    Derives a per-tenant 256-bit key mixing the master secret with tenant isolation salt.
    """
    context = f"tenant:{tenant_id}".encode("utf-8")
    return derive_key(AES_MASTER_KEY_SECRET, salt=salt, context_info=context)


def encrypt_aes_256_gcm(
    plaintext: bytes,
    key: Optional[bytes] = None,
    associated_data: Optional[bytes] = None,
    salt: Optional[bytes] = None,
) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypts plaintext using AES-256-GCM.
    
    Returns:
        (ciphertext_with_tag, nonce, salt)
    """
    if salt is None:
        salt = os.urandom(SALT_SIZE_BYTES)
    
    if key is None:
        key = derive_key(AES_MASTER_KEY_SECRET, salt)

    nonce = os.urandom(NONCE_SIZE_BYTES)
    aesgcm = AESGCM(key)
    
    # AESGCM.encrypt appends the 16-byte tag to the end of ciphertext
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    
    return ciphertext_with_tag, nonce, salt


def decrypt_aes_256_gcm(
    ciphertext_with_tag: bytes,
    nonce: bytes,
    key: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """
    Decrypts ciphertext and verifies the 128-bit authentication tag using AES-256-GCM.
    Raises IntegrityError if payload has been modified or corrupted in transit/at rest.
    """
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        return plaintext
    except InvalidTag as exc:
        raise IntegrityError("AES-256-GCM authentication tag verification failed. Data corrupted or tampered with.") from exc
    except Exception as exc:
        raise CryptoError(f"Decryption failed: {str(exc)}") from exc


def pack_encrypted_payload(ciphertext_with_tag: bytes, nonce: bytes, salt: bytes) -> bytes:
    """
    Packs salt (16B) + nonce (12B) + ciphertext_with_tag into a single binary envelope.
    """
    return salt + nonce + ciphertext_with_tag


def unpack_encrypted_payload(packed: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Unpacks binary envelope into (ciphertext_with_tag, nonce, salt).
    """
    if len(packed) < SALT_SIZE_BYTES + NONCE_SIZE_BYTES + TAG_SIZE_BYTES:
        raise CryptoError("Encrypted payload too short to contain valid headers and tag.")
    
    salt = packed[:SALT_SIZE_BYTES]
    nonce = packed[SALT_SIZE_BYTES:SALT_SIZE_BYTES + NONCE_SIZE_BYTES]
    ciphertext_with_tag = packed[SALT_SIZE_BYTES + NONCE_SIZE_BYTES:]
    return ciphertext_with_tag, nonce, salt
