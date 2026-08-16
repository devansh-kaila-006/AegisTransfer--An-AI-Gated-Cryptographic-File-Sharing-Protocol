import pqcrypto
import os

def generate_key_pair(private_key_path="server_sk.bin", public_key_path="server_pk.bin", passphrase=None):
    """Generates ML-KEM and ML-DSA keys and saves them."""
    # ML-KEM-512 (Kyber)
    kem_pk, kem_sk = pqcrypto.kem.ml_kem_512.keygen()
    # ML-DSA-44 (Dilithium)
    dsa_pk, dsa_sk = pqcrypto.sign.ml_dsa_44.keygen()
    
    # Save the keys as raw bytes
    with open(private_key_path + "_kem", "wb") as f:
        f.write(kem_sk)
    with open(public_key_path + "_kem", "wb") as f:
        f.write(kem_pk)
        
    with open(private_key_path + "_dsa", "wb") as f:
        f.write(dsa_sk)
    with open(public_key_path + "_dsa", "wb") as f:
        f.write(dsa_pk)
        
    return (kem_sk, dsa_sk), (kem_pk, dsa_pk)

def load_private_key(filepath, passphrase=None):
    """Loads the KEM and DSA private keys."""
    with open(filepath + "_kem", "rb") as f:
        kem_sk = f.read()
    with open(filepath + "_dsa", "rb") as f:
        dsa_sk = f.read()
    return (kem_sk, dsa_sk)

def load_public_key(filepath):
    """Loads the KEM and DSA public keys."""
    with open(filepath + "_kem", "rb") as f:
        kem_pk = f.read()
    with open(filepath + "_dsa", "rb") as f:
        dsa_pk = f.read()
    return (kem_pk, dsa_pk)
