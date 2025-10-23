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
    password = master_password.encode()
    salt = device_secret.encode()
    key = PBKDF2(password, salt, 32, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA512)
    return key


def encrypt_password(master_key: bytes, plaintext_password: str) -> str:
    """
    Encrypt plaintext password using AES-GCM.
    Returns a single base64 string: nonce_b64:tag_b64:ciphertext_b64
    """
    cipher = AES.new(master_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_password.encode())
    nonce_b64 = base64.b64encode(cipher.nonce).decode()
    tag_b64 = base64.b64encode(tag).decode()
    ct_b64 = base64.b64encode(ciphertext).decode()
    return f"{nonce_b64}:{tag_b64}:{ct_b64}"


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

    nonce = base64.b64decode(nonce_b64)
    tag = base64.b64decode(tag_b64)
    ciphertext = base64.b64decode(ct_b64)

    cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()
