from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_file(file_data, key=None, aad=None):
    """Encrypts file data using AES-256-GCM.
    
    Args:
        file_data (bytes): Raw bytes of the file to encrypt.
        key (bytes, optional): A 32-byte AES key. If None, generates a random key.
        aad (bytes, optional): Additional Authenticated Data (e.g. filename).
        
    Returns:
        tuple: A tuple containing:
            - ciphertext (bytes): The encrypted file data.
            - nonce (bytes): The 16-byte random nonce used for GCM.
            - tag (bytes): The 16-byte authentication tag.
            - key (bytes): The 32-byte AES session key.
    """
    if key is None:
        key = get_random_bytes(32) # AES-256
        
    cipher = AES.new(key, AES.MODE_GCM)
    if aad:
        cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    
    return ciphertext, cipher.nonce, tag, key

def decrypt_file(ciphertext, nonce, tag, key, aad=None):
    """Decrypts file data using AES-256-GCM.
    
    Args:
        ciphertext (bytes): The encrypted file data.
        nonce (bytes): The 16-byte nonce used during encryption.
        tag (bytes): The 16-byte authentication tag.
        key (bytes): The 32-byte AES session key.
        aad (bytes, optional): Additional Authenticated Data (e.g. filename).
        
    Returns:
        bytes: The decrypted plaintext file data.
        
    Raises:
        ValueError: If the key is incorrect or the ciphertext/tag has been tampered with.
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except ValueError:
        raise ValueError("Key incorrect or message corrupted")
