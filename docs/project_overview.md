# Project Overview: AI-Driven Secure File Sharing System

## Abstract
Traditional file sharing systems rely entirely on cryptography for security. However, modern cryptographic operations (like RSA public key encryption) are computationally expensive. Attackers exploit this by sending high volumes of malicious or malformed requests, forcing the server to spend CPU cycles encrypting them. This results in a "Denial of Wallet" or Resource Exhaustion attack.

This project solves this by proposing a **Hybrid Security Architecture**:
1. A Machine Learning model (Random Forest) acts as an intelligent gatekeeper, analyzing the network flow features of the incoming request. If malicious (DoS, Botnet, Brute Force), the connection is dropped instantly before any cryptography occurs.
2. If the request is benign, it proceeds to the highly secure Hybrid Cryptosystem (AES-256-GCM + RSA-3072-OAEP/PSS).

## The Three Pillars of the System

### 1. Intrusion Detection System (IDS)
The IDS is trained on the modern **IDS2025 dataset**. Through feature selection, we identified the Top 10 most critical network features (such as `Fwd IAT Mean`, `Packet Length Mean`, etc.). 
The Random Forest classifier predicts whether the incoming feature vector is:
- Normal (Allowed)
- DoS / DDoS (Blocked)
- PortScan (Blocked)
- Brute Force (Blocked)
- Web Attack (Blocked)
- Botnet ARES (Blocked)

This pre-emptive dropping saves >99% of CPU resources during an active attack compared to processing the cryptography.

### 2. The Hybrid Cryptosystem
The cryptography module relies on the `PyCryptodome` library and ensures:
- **Confidentiality:** Files are encrypted using symmetric AES-256 in Galois/Counter Mode (GCM).
- **Integrity & Authenticity:** GCM provides an authentication tag to prevent ciphertext tampering. Furthermore, the payload is digitally signed using asymmetric **RSA-PSS**.
- **Secure Key Exchange:** The one-time AES session key is "wrapped" (encrypted) using the server's **3072-bit RSA Public Key** via RSA-OAEP padding.
- **Key Protection:** The 3072-bit Private Key is secured on the hard drive using **PKCS#8** password-based encryption (`scryptAndAES128-CBC`), simulating a Hardware Security Module (HSM).

### 3. API & Web Dashboard Hardening
The system is built on **FastAPI** and features a robust, enterprise-level architecture:
- **Authentication:** All routes are protected by HTTP Basic Authentication.
- **Volumetric DoS Protection:** A custom Rate Limiting middleware strictly limits clients to 5 uploads per minute.
- **Memory Protection:** A max-upload size middleware rejects files larger than 100MB before they are processed in memory.
- **Input Validation:** Pydantic strictly enforces the JSON schema for the network features, preventing injection attacks.
- **Full API Lifecycle:** Endpoints exist for Uploading, Downloading (Decryption), Listing (`/files`), Deleting (`/delete`), Healthchecks (`/health`), and Metrics (`/metrics`).
- **Audit Logging:** Every interaction, including ML predictions and cryptographic statuses, is logged in a local SQLite database and displayed on the interactive dashboard.
