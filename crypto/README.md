# Cryptography Subsystem

This module contains the implementation of the **Hybrid Cryptosystem** used to secure file transfers.

## Architecture

To achieve both high performance and extreme security (Defense-in-Depth), this system utilizes a combination of symmetric and asymmetric encryption:

1. **`file_cipher.py` (AES-256-GCM)**
   - Used for bulk data encryption. 
   - Generates a unique, one-time 256-bit symmetric session key for every file upload.
   - Operates in Galois/Counter Mode (GCM) to provide Authenticated Encryption with Associated Data (AEAD), ensuring the ciphertext has not been tampered with before decryption.

2. **`session.py` (RSA-OAEP & RSA-PSS)**
   - **RSA-OAEP (Optimal Asymmetric Encryption Padding):** Used to "wrap" (encrypt) the AES session key using the server's public key. This ensures the session key is securely transmitted and can only be accessed by the server's private key.
   - **RSA-PSS (Probabilistic Signature Scheme):** Used to generate a cryptographic digital signature of the encrypted payload. This guarantees non-repudiation and integrity.

3. **`keys.py` (Key Management & Storage Security)**
   - Handles the generation of **3072-bit RSA key pairs**, meeting modern long-term security recommendations (NIST standards).
   - **PKCS#8 Protection at Rest:** The private key (`server_private.pem`) is never stored on the hard drive in plaintext. It is heavily encrypted at rest using a PKCS#8 passphrase with `scryptAndAES128-CBC`. The server decrypts it into memory only during startup.
