#!/usr/bin/env python3
"""
keygen.py - توليد مفاتيح RSA للمشروع
"""

import argparse
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

KEYS_DIR = "keys"
os.makedirs(KEYS_DIR, exist_ok=True)

def generate_rsa_keypair(username: str, bits: int = 3072, passphrase: str = None):
    """توليد زوج مفاتيح RSA"""
    
    print(f"🔐 توليد مفاتيح RSA {bits}-bit للمستخدم '{username}'...")
    
    # توليد المفتاح الخاص
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits
    )
    
    # ترميز المفتاح الخاص
    if passphrase:
        encryption = serialization.BestAvailableEncryption(passphrase.encode())
    else:
        encryption = serialization.NoEncryption()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )
    
    # المفتاح العام
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # حفظ الملفات
    priv_path = os.path.join(KEYS_DIR, f"{username}_private.pem")
    pub_path = os.path.join(KEYS_DIR, f"{username}_public.pem")
    
    with open(priv_path, "wb") as f:
        f.write(private_pem)
    with open(pub_path, "wb") as f:
        f.write(public_pem)
    
    print(f"✅ المفتاح الخاص: {priv_path}")
    print(f"✅ المفتاح العام:  {pub_path}")
    
    if passphrase:
        print(f"🔐 كلمة المرور: '{passphrase}'")
    else:
        print("⚠️  تنبيه: المفتاح الخاص غير محمي بكلمة مرور")

def main():
    parser = argparse.ArgumentParser(description="توليد مفاتيح RSA")
    parser.add_argument("--user", "-u", required=True, help="اسم المستخدم")
    parser.add_argument("--bits", type=int, default=3072, choices=[2048, 3072, 4096],
                       help="حجم مفتاح RSA (افتراضي: 3072)")
    parser.add_argument("--passphrase", "-p", help="كلمة مرور لحماية المفتاح الخاص")
    
    args = parser.parse_args()
    
    generate_rsa_keypair(args.user, args.bits, args.passphrase)
    print(f"\n🎉 تم توليد المفاتيح للمستخدم '{args.user}' بنجاح!")

if __name__ == "__main__":
    main()
