#!/usr/bin/env python3
"""
utils.py - أدوات مساعدة للتشفير
"""

import os
import base64
from typing import Optional
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

KEYS_DIR = "keys"

# ============= وظائف Base64 =============
def _b64(data: bytes) -> str:
    """تحويل bytes إلى base64 string"""
    return base64.b64encode(data).decode('utf-8')

def _unb64(s: str) -> bytes:
    """تحويل base64 string إلى bytes"""
    return base64.b64decode(s.encode('utf-8'))

# ============= تحميل المفاتيح =============
def load_public_key(username: str):
    """تحميل المفتاح العام من ملف"""
    path = os.path.join(KEYS_DIR, f"{username}_public.pem")
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_private_key(username: str, passphrase: Optional[str] = None):
    """تحميل المفتاح الخاص من ملف"""
    path = os.path.join(KEYS_DIR, f"{username}_private.pem")
    with open(path, "rb") as f:
        data = f.read()
    
    if passphrase:
        return serialization.load_pem_private_key(data, password=passphrase.encode())
    else:
        return serialization.load_pem_private_key(data, password=None)

# ============= تشفير RSA =============
def rsa_encrypt_aes_key(public_key, aes_key: bytes) -> bytes:
    """تشفير مفتاح AES باستخدام RSA-OAEP"""
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt_aes_key(private_key, ciphertext: bytes) -> bytes:
    """فك تشفير مفتاح AES باستخدام RSA-OAEP"""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# ============= التوقيع والتحقق =============
def rsa_sign(private_key, data: bytes) -> bytes:
    """توقيع البيانات باستخدام RSA-PSS"""
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def rsa_verify(public_key, data: bytes, signature: bytes) -> bool:
    """التحقق من التوقيع"""
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# ============= Hash =============
def sha256_hex(data: bytes) -> str:
    """حساب SHA-256 hash"""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()

# ============= مسارات الملفات =============
def pubkey_path(username: str) -> str:
    """مسار المفتاح العام"""
    return os.path.join(KEYS_DIR, f"{username}_public.pem")

def privkey_path(username: str) -> str:
    """مسار المفتاح الخاص"""
    return os.path.join(KEYS_DIR, f"{username}_private.pem")
