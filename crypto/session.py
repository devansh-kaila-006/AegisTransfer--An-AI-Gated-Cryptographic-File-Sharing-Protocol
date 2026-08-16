import pqcrypto
import os

def wrap_session_key(session_key, recipient_public_key):
    """Wraps the AES session key using ML-KEM (Kyber).
    
    Since Kyber encapsulates a new shared secret rather than wrapping an existing one natively,
    we use the generated shared secret to encrypt the existing session key via XOR (One-Time Pad).
    """
    kem_pk, _ = recipient_public_key
    ct, shared_secret = pqcrypto.kem.ml_kem_512.encaps(kem_pk)
    
    # XOR the 32-byte session key with the 32-byte shared secret
    wrapped_key = bytes(a ^ b for a, b in zip(session_key, shared_secret))
    
    # Return both the KEM ciphertext and the XOR'd key as a single payload
    return ct + wrapped_key

def unwrap_session_key(enc_session_key, recipient_private_key):
    """Unwraps the AES session key using ML-KEM (Kyber)."""
    kem_sk, _ = recipient_private_key
    ct_size = pqcrypto.kem.ml_kem_512.CIPHERTEXT_SIZE
    
    ct = enc_session_key[:ct_size]
    wrapped_key = enc_session_key[ct_size:]
    
    # Decapsulate the shared secret (sk first, then ct)
    shared_secret = pqcrypto.kem.ml_kem_512.decaps(kem_sk, ct)
    
    # Recover the original session key
    session_key = bytes(a ^ b for a, b in zip(wrapped_key, shared_secret))
    return session_key

def sign_payload(payload, sender_private_key):
    """Signs a payload using ML-DSA (Dilithium)."""
    _, dsa_sk = sender_private_key
    signature = pqcrypto.sign.ml_dsa_44.sign(dsa_sk, payload)
    return signature

def verify_signature(payload, signature, sender_public_key):
    """Verifies a payload's signature using ML-DSA (Dilithium)."""
    _, dsa_pk = sender_public_key
    try:
        pqcrypto.sign.ml_dsa_44.verify(dsa_pk, payload, signature)
        return True
    except Exception:
        return False
