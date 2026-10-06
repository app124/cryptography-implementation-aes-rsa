"""
Cryptography Algorithms Implementation - AES, RSA, SHA
"""
import hashlib

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pss
from Crypto.Util.Padding import pad, unpad


def banner(title):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


# 1. AES (symmetric encryption)
def aes_cbc_demo(message: bytes):
    banner("AES-256 in CBC mode")
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message, AES.block_size))
    iv = cipher.iv

    print("Key        :", key.hex())
    print("IV         :", iv.hex())
    print("Ciphertext :", ciphertext.hex())

    decipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = unpad(decipher.decrypt(ciphertext), AES.block_size)
    print("Decrypted  :", plaintext.decode())


def aes_gcm_demo(message: bytes):
    banner("AES-256 in GCM mode (encryption + integrity check)")
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    nonce = cipher.nonce

    print("Ciphertext :", ciphertext.hex())
    print("Auth tag   :", tag.hex())

    decipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    print("Decrypted  :", decipher.decrypt_and_verify(ciphertext, tag).decode())

    tampered = bytearray(ciphertext)
    tampered[0] ^= 0x01
    try:
        AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(bytes(tampered), tag)
    except ValueError:
        print("Tamper test: modified ciphertext REJECTED (integrity check failed)")


# 2. RSA (asymmetric encryption and digital signature)
def rsa_demo(message: bytes):
    banner("RSA-2048 encryption (OAEP) and signature (PSS)")
    key = RSA.generate(2048)
    public_key = key.publickey()

    encrypted = PKCS1_OAEP.new(public_key).encrypt(message)
    print("Encrypted  :", encrypted.hex()[:64] + "...")
    decrypted = PKCS1_OAEP.new(key).decrypt(encrypted)
    print("Decrypted  :", decrypted.decode())

    digest = SHA256.new(message)
    signature = pss.new(key).sign(digest)
    print("Signature  :", signature.hex()[:64] + "...")
    try:
        pss.new(public_key).verify(digest, signature)
        print("Signature check on original message: VALID")
    except (ValueError, TypeError):
        print("Signature check on original message: INVALID")

    fake_digest = SHA256.new(message + b" (edited)")
    try:
        pss.new(public_key).verify(fake_digest, signature)
        print("Signature check on edited message  : VALID")
    except (ValueError, TypeError):
        print("Signature check on edited message  : INVALID (tampering detected)")

    with open("private.pem", "wb") as f:
        f.write(key.export_key())
    with open("public.pem", "wb") as f:
        f.write(public_key.export_key())
    print("Keys saved : private.pem, public.pem")


# 3. SHA (hashing)
def sha_demo():
    banner("SHA hashing and the avalanche effect")
    a = b"Cybersecurity"
    b = b"cybersecurity"

    for name in ("sha1", "sha256", "sha512"):
        print(f"{name:7}(a):", hashlib.new(name, a).hexdigest())
        print(f"{name:7}(b):", hashlib.new(name, b).hexdigest())
        print()

    with open("sample.txt", "w") as f:
        f.write("This is my original file.\n")
    original = hashlib.sha256(open("sample.txt", "rb").read()).hexdigest()
    with open("sample.txt", "a") as f:
        f.write("One extra line.\n")
    modified = hashlib.sha256(open("sample.txt", "rb").read()).hexdigest()
    print("File hash before edit:", original)
    print("File hash after edit :", modified)
    print("File changed:", original != modified)


if __name__ == "__main__":
    msg = b"Confidential: SOC report for Codec Technologies internship"
    aes_cbc_demo(msg)
    aes_gcm_demo(msg)
    rsa_demo(b"Short message for RSA")
    sha_demo()
