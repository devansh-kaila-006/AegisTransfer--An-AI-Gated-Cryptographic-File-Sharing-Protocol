from Crypto.PublicKey import RSA
import os

def generate_key_pair(private_key_path="private.pem", public_key_path="public.pem", passphrase=None):
    """Generates an RSA key pair and saves them to files."""
    key = RSA.generate(3072)
    
    if passphrase:
        private_key = key.export_key(passphrase=passphrase, pkcs=8, protection="scryptAndAES128-CBC")
    else:
        private_key = key.export_key()
        
    with open(private_key_path, "wb") as f:
        f.write(private_key)
        
    public_key = key.publickey().export_key()
    with open(public_key_path, "wb") as f:
        f.write(public_key)
        
    return private_key, public_key

def load_private_key(filepath, passphrase=None):
    with open(filepath, "rb") as f:
        return RSA.import_key(f.read(), passphrase=passphrase)

def load_public_key(filepath):
    with open(filepath, "rb") as f:
        return RSA.import_key(f.read())
