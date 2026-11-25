import pqcrypto
import pqcrypto.kem.kyber512
import pqcrypto.sign.dilithium2
import os

def new_file_key(recipient_public_key):
    """Encapsulate: Kyber ciphertext + the shared secret used directly as the AES-256 key."""
    kem_pk, _ = recipient_public_key
    ct, aes_key = pqcrypto.kem.kyber512.encrypt(kem_pk)
    return ct, aes_key

def recover_file_key(kem_ct, recipient_private_key):
    """Decapsulate: Recover the AES-256 key from the Kyber ciphertext."""
    kem_sk, _ = recipient_private_key
    return pqcrypto.kem.kyber512.decrypt(kem_sk, kem_ct)

def sign_payload(payload, sender_private_key):
    """Signs a payload using ML-DSA (Dilithium)."""
    _, dsa_sk = sender_private_key
    signature = pqcrypto.sign.dilithium2.sign(dsa_sk, payload)
    return signature

def verify_signature(payload, signature, sender_public_key):
    """Verifies a payload's signature using ML-DSA (Dilithium)."""
    _, dsa_pk = sender_public_key
    try:
        pqcrypto.sign.dilithium2.verify(dsa_pk, payload, signature)
        return True
    except Exception:
        return False
