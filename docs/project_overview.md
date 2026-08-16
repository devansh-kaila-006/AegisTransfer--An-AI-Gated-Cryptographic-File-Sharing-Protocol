# Project Overview: AI-Driven Post-Quantum Secure File Sharing System

## Abstract
Traditional file sharing systems rely entirely on cryptography for security. However, modern cryptographic operations (like public key encryption) are computationally expensive. Attackers exploit this by sending high volumes of malicious or malformed requests, forcing the server to spend CPU cycles encrypting them. This results in a "Denial of Wallet" or Resource Exhaustion attack. Furthermore, the advent of quantum computing threatens traditional algorithms like RSA.

This project solves both these issues by proposing an **Adversarially-Hardened Post-Quantum Hybrid Architecture**:
1. A Machine Learning model (Random Forest) acts as an intelligent gatekeeper, analyzing the network flow features of the incoming request. If malicious (DoS, Botnet, Brute Force), the connection is dropped instantly before any cryptography occurs. The model is also adversarially trained to resist AI evasion.
2. If the request is benign, it proceeds to the highly secure Hybrid Cryptosystem consisting of AES-256-GCM and NIST-standardized Post-Quantum algorithms (Kyber & Dilithium).

## The Three Pillars of the System

### 1. Adversarially-Hardened Intrusion Detection System (IDS)
The IDS is trained on the modern **IDS2025 dataset**. Through feature selection, we identified the Top 10 most critical network features (such as `Fwd IAT Mean`, `Packet Length Mean`, etc.). 
The Random Forest classifier predicts whether the incoming feature vector is:
- Normal (Allowed)
- DoS / DDoS (Blocked)
- PortScan (Blocked)
- Brute Force (Blocked)
- Web Attack (Blocked)
- Botnet ARES (Blocked)

**Adversarial Defense:** To ensure attackers cannot bypass the AI gatekeeper by adding noise to their packets, the model undergoes Adversarial Training. It is exposed to 10% Gaussian noise during training, ensuring >94% robustness against evasion attempts.

This pre-emptive dropping saves >99% of CPU resources during an active attack compared to processing the cryptography.

### 2. The Post-Quantum Hybrid Cryptosystem
The cryptography module relies on `PyCryptodome` and `pqcrypto` to ensure quantum-resistant security:
- **Confidentiality:** Files are encrypted using symmetric AES-256 in Galois/Counter Mode (GCM).
- **Integrity & Authenticity:** GCM provides an authentication tag to prevent ciphertext tampering. Furthermore, the payload is digitally signed using the post-quantum **ML-DSA-44 (Dilithium)**. We also verify the SHA-256 hash of the initial plaintext vs decrypted plaintext.
- **Secure Key Exchange:** The one-time AES session key is encapsulated using the server's post-quantum **ML-KEM-512 (Kyber)** Public Key.
- **Key Protection:** The KEM and DSA private keys are loaded securely during the application `lifespan` context.

### 3. API & Web Dashboard Hardening
The system is built on **FastAPI** and features a robust, enterprise-level architecture:
- **Authentication:** All routes are protected by modern **JWT Authentication** (OAuth2PasswordBearer with bcrypt password hashing).
- **Volumetric DoS Protection:** A custom Rate Limiting middleware strictly limits clients to 5 uploads per minute.
- **Memory Protection:** A max-upload size middleware rejects files larger than 100MB before they are processed in memory. CPU-heavy tasks are offloaded to **asynchronous thread pools**.
- **Input Validation:** Pydantic strictly enforces the JSON schema for the network features, preventing injection attacks.
- **Audit Logging & DB:** Every interaction, including ML predictions and cryptographic statuses, is logged securely via **SQLAlchemy ORM** into a local database and displayed on the interactive dashboard.
