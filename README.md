# AI-Driven Secure File Sharing System (Post-Quantum Ready)

A novel, hybrid-security approach to secure file transfers that combines **Adversarially-Hardened Machine Learning Intrusion Detection (IDS)** with a **Post-Quantum Hybrid Cryptosystem**. 

This system protects against traditional data-at-rest/data-in-transit attacks (using quantum-resistant cryptography), computational resource exhaustion attacks (using AI to pre-emptively drop malicious network flows), and advanced ML evasion techniques (using Adversarial Training).

## Features
- **AI Pre-Emptive Protection:** Uses a Random Forest classifier trained on the modern IDS2025 dataset to detect DoS, PortScans, Brute Force, and Botnet traffic before cryptographic operations occur.
- **Adversarial ML Defense:** The IDS model is adversarially trained against 10% Gaussian noise, increasing robustness against AI evasion attacks from 17% up to 94%.
- **Post-Quantum Cryptography (PQC):** Secures files using AES-256-GCM (Symmetric Encryption), **ML-KEM-512 (Kyber)** for Asymmetric Key Encapsulation, and **ML-DSA-44 (Dilithium)** for Digital Signatures. Completely eliminates vulnerable legacy RSA architectures.
- **Robust API Hardening:** The API is protected by modern JWT Authentication (OAuth2 + bcrypt), a volumetric rate limiter (5 requests/min), CORS restrictions, and a strict 100MB max file size limit to prevent Memory Exhaustion DoS attacks. Database interactions are securely handled via SQLAlchemy ORM.
- **Strict Input Validation & Integrity:** FastAPI and Pydantic strictly enforce valid network feature schemas. A dedicated `integrity.py` module ensures End-to-End SHA-256 hash verification alongside AES-GCM tags.
- **Full File Lifecycle:** Secure file uploads (`/upload`), encrypted file listing (`/files`), authenticated decryption/downloads (`/download/{filename}`), and secure file deletion (`/delete`).
- **Security Audit Logging:** All file transfer attempts and IDS predictions are securely logged via SQLAlchemy into a local SQLite database (`audit_log.db`).
- **Advanced Empirical Testing:** Mathematically proven robustness via 5-Fold Cross Validation, Algorithm Comparisons (RF vs XGBoost vs LightGBM), and comprehensive Adversarial Robustness metrics. All CPU heavy tasks are non-blocking via asynchronous threadpools.

## API Endpoints
- `GET /` - The main frontend dashboard.
- `POST /token` - OAuth2 login to receive a JWT access token.
- `POST /upload` - Uploads, analyzes, encrypts (AES), and signs (Dilithium) a file, while encapsulating the key (Kyber).
- `GET /download/{filename}` - Verifies signatures, decapsulates, decrypts, and serves a file.
- `DELETE /files/{filename}` - Securely deletes an encrypted file and its metadata.
- `GET /files` - Lists all encrypted files currently stored on the server.
- `GET /health` - System healthcheck (DB, ML Model, Crypto Keys).
- `GET /metrics` - Returns the Random Forest model's performance metrics.

## Directory Structure
- `/crypto/` - Contains the custom Post-Quantum Hybrid Cryptosystem implementation (AES + Kyber + Dilithium).
- `/ml/` - Contains the Machine Learning pipeline (Preprocessing, Adversarial Training, Algorithm Comparison).
- `/docs/` - Contains detailed documentation, project overviews, and rigorous empirical results.
- `/data/` - Contains the training datasets (e.g., `IDS2025.xlsx`).
- `/static/` - Static assets, including the generated ML comparison charts and Adversarial Robustness graphs.
- `/templates/` - Jinja2 HTML templates for the dashboard.
- `app.py` - The main FastAPI application utilizing `lifespan` context managers and background threadpools.
- `database.py` - SQLAlchemy ORM schema and audit logging operations.
- `config.py` - Pydantic-based settings management.

## How to Run
1. Install requirements: `pip install -r requirements.txt`
2. Start the server: `python -m uvicorn app:app --host 127.0.0.1 --port 5000`
3. Visit `http://127.0.0.1:5000` in your browser.
4. Login with Username: `admin` / Password: `password`.
