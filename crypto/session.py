from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256

def wrap_session_key(session_key, recipient_public_key):
    """Wraps the AES session key using RSA-OAEP.
    
    Args:
        session_key (bytes): The 32-byte AES session key to encrypt.
        recipient_public_key (RSA._RSAobj): The RSA public key of the receiver.
        
    Returns:
        bytes: The RSA-encrypted session key.
    """
    cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    return enc_session_key

def unwrap_session_key(enc_session_key, recipient_private_key):
    """Unwraps the AES session key using RSA-OAEP.
    
    Args:
        enc_session_key (bytes): The RSA-encrypted AES session key.
        recipient_private_key (RSA._RSAobj): The RSA private key of the receiver.
        
    Returns:
        bytes: The decrypted 32-byte AES session key.
    """
    cipher_rsa = PKCS1_OAEP.new(recipient_private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    return session_key

def sign_payload(payload, sender_private_key):
    """Signs a payload (e.g., file digest) using RSA-PSS.
    
    Args:
        payload (bytes): The data (usually an authentication tag) to sign.
        sender_private_key (RSA._RSAobj): The RSA private key of the sender.
        
    Returns:
        bytes: The cryptographic digital signature.
    """
    h = SHA256.new(payload)
    signature = pss.new(sender_private_key).sign(h)
    return signature

def verify_signature(payload, signature, sender_public_key):
    """Verifies a payload's signature using RSA-PSS.
    
    Args:
        payload (bytes): The original data that was signed.
        signature (bytes): The cryptographic signature to verify.
        sender_public_key (RSA._RSAobj): The RSA public key of the signer.
        
    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    h = SHA256.new(payload)
    verifier = pss.new(sender_public_key)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
