# utils/crypto_utils.py
# --------------------------------------------------------
# Handles key derivation, encryption, and decryption
# for stored site passwords using AES-GCM.
# --------------------------------------------------------

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
import base64

PBKDF2_ITERATIONS = 1_000_000


def computeMasterKey(master_password: str, device_secret: str) -> bytes:
    """Derive a 32-byte AES key from master password and device secret."""
    if not master_password or not device_secret:
        raise ValueError("Master password and device secret must not be empty.")
    password = master_password.encode("utf-8")
    salt = device_secret.encode("utf-8")
    key = PBKDF2(password, salt, 32, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA512)
    return key


def encrypt_password(master_key: bytes, plaintext_password: str) -> str:
    """
    Encrypt plaintext password using AES-GCM.
    Returns a single base64 string: nonce_b64:tag_b64:ciphertext_b64
    """
    cipher = AES.new(master_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_password.encode("utf-8"))
    return f"{base64.b64encode(cipher.nonce).decode()}:{base64.b64encode(tag).decode()}:{base64.b64encode(ciphertext).decode()}"


def decrypt_password(master_key: bytes, stored_value: str) -> str:
    """
    Decrypts an AES-GCM-encrypted password string.
    Input format: nonce_b64:tag_b64:ciphertext_b64
    Returns the plaintext password.
    """
    try:
        nonce_b64, tag_b64, ct_b64 = stored_value.split(":")
    except ValueError:
        raise ValueError("Stored password format invalid (expected nonce:tag:ciphertext)")

    try:
        nonce = base64.b64decode(nonce_b64)
        tag = base64.b64decode(tag_b64)
        ciphertext = base64.b64decode(ct_b64)
    except Exception:
        raise ValueError("Stored password base64 decoding failed")

    cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode("utf-8")
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")
