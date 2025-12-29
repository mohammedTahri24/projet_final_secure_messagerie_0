#!/usr/bin/env python3
"""
crypto.py - تشفير AES-CBC مع HMAC (مطابق للمشروع المطلوب)
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import hashes

def gen_aes_key(key_size: int = 32) -> bytes:
    """توليد مفتاح AES (32 bytes = 256-bit)"""
    return os.urandom(key_size)

def aes_cbc_encrypt(aes_key: bytes, plaintext: bytes, iv: bytes = None):
    """
    تشفير باستخدام AES-CBC
    يعيد (iv, ciphertext)
    """
    if iv is None:
        iv = os.urandom(16)  # 128-bit IV لـ AES
    
    # Padding for CBC (مطلوب لـ CBC)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    # تشفير
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return iv, ciphertext

def aes_cbc_decrypt(aes_key: bytes, iv: bytes, ciphertext: bytes):
    """فك تشفير باستخدام AES-CBC"""
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # إزالة padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext

def compute_hmac(key: bytes, data: bytes) -> bytes:
    """حساب HMAC-SHA256 للنزاهة"""
    h = HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def verify_hmac(key: bytes, data: bytes, signature: bytes) -> bool:
    """التحقق من HMAC-SHA256"""
    h = HMAC(key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(signature)
        return True
    except:
        return False
