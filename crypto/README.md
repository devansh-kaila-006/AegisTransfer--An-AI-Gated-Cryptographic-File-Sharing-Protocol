# Cryptography Subsystem

This module contains the implementation of the **Hybrid Cryptosystem** used to secure file transfers.

## Architecture

To achieve both high performance and extreme security (Defense-in-Depth), this system utilizes a combination of symmetric encryption and cutting-edge **Post-Quantum Cryptography (PQC)**:

1. **`file_cipher.py` (AES-256-GCM)**
   - Used for bulk data encryption. 
   - Generates a unique, one-time 256-bit symmetric session key for every file upload.
   - Operates in Galois/Counter Mode (GCM) to provide Authenticated Encryption with Associated Data (AEAD), ensuring the ciphertext has not been tampered with before decryption.

2. **`session.py` (Post-Quantum Cryptography: Kyber & Dilithium)**
   - **ML-KEM-512 (Kyber):** Replaces legacy RSA-OAEP. Used to encapsulate the AES session key using the server's post-quantum public key. This ensures the session key is securely transmitted and mathematically secure against future quantum computer attacks (Shor's Algorithm). We use an XOR One-Time Pad approach to combine the AES key with Kyber's shared secret.
   - **ML-DSA-44 (Dilithium):** Replaces legacy RSA-PSS. Used to generate a post-quantum cryptographic digital signature of the encrypted payload. This guarantees non-repudiation and integrity.

3. **`keys.py` (Key Management & Storage Security)**
   - Handles the generation of NIST-standardized **Kyber and Dilithium key pairs**.
   - **Protection at Rest:** The private keys (`server_private.pem_kem` and `server_private.pem_dsa`) are generated and loaded securely.

4. **`integrity.py` (End-to-End Hashing)**
   - Computes SHA-256 hashes of the initial plaintext and final ciphertext to provide an additional layer of end-to-end verification alongside the GCM authentication tag.
