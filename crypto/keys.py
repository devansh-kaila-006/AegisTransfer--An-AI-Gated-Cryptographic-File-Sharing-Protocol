import pqcrypto
import pqcrypto.kem.kyber512
import pqcrypto.sign.dilithium2
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

def _encrypt_key_bytes(data: bytes, passphrase: str) -> bytes:
    if not passphrase:
        return data
    salt = get_random_bytes(16)
    key = PBKDF2(passphrase, salt, 32, count=100000)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    # Return [salt(16)][nonce(16)][tag(16)][ciphertext...]
    return salt + cipher.nonce + tag + ciphertext

def _decrypt_key_bytes(data: bytes, passphrase: str) -> bytes:
    if not passphrase:
        return data
    try:
        salt = data[:16]
        nonce = data[16:32]
        tag = data[32:48]
        ciphertext = data[48:]
        key = PBKDF2(passphrase, salt, 32, count=100000)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except Exception as e:
        raise ValueError(f"Failed to decrypt key (incorrect passphrase or corrupted file): {e}")

def generate_key_pair(private_key_path="server_sk.bin", public_key_path="server_pk.bin", passphrase=None):
    """Generates ML-KEM and ML-DSA keys and saves them."""
    # ML-KEM-512 (Kyber)
    kem_pk, kem_sk = pqcrypto.kem.kyber512.generate_keypair()
    # ML-DSA-44 (Dilithium)
    dsa_pk, dsa_sk = pqcrypto.sign.dilithium2.generate_keypair()
    
    kem_sk_enc = _encrypt_key_bytes(kem_sk, passphrase)
    dsa_sk_enc = _encrypt_key_bytes(dsa_sk, passphrase)
    
    with open(private_key_path + "_kem", "wb") as f:
        f.write(kem_sk_enc)
    with open(public_key_path + "_kem", "wb") as f:
        f.write(kem_pk)
        
    with open(private_key_path + "_dsa", "wb") as f:
        f.write(dsa_sk_enc)
    with open(public_key_path + "_dsa", "wb") as f:
        f.write(dsa_pk)
        
    return (kem_sk, dsa_sk), (kem_pk, dsa_pk)

def load_private_key(filepath, passphrase=None):
    """Loads the KEM and DSA private keys."""
    with open(filepath + "_kem", "rb") as f:
        kem_sk_enc = f.read()
    with open(filepath + "_dsa", "rb") as f:
        dsa_sk_enc = f.read()
        
    kem_sk = _decrypt_key_bytes(kem_sk_enc, passphrase)
    dsa_sk = _decrypt_key_bytes(dsa_sk_enc, passphrase)
    
    return (kem_sk, dsa_sk)

def load_public_key(filepath):
    """Loads the KEM and DSA public keys."""
    with open(filepath + "_kem", "rb") as f:
        kem_pk = f.read()
    with open(filepath + "_dsa", "rb") as f:
        dsa_pk = f.read()
    return (kem_pk, dsa_pk)
