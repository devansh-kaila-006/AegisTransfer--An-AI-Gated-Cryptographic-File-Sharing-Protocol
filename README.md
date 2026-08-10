# AI-Driven Secure File Sharing System

A novel, hybrid-security approach to secure file transfers that combines **Machine Learning-based Intrusion Detection (IDS)** with a **Hybrid Cryptosystem**. 

This system protects against both traditional data-at-rest/data-in-transit attacks (using cryptography) and computational resource exhaustion attacks (using AI to pre-emptively drop malicious network flows).

## Features
- **AI Pre-Emptive Protection:** Uses a Random Forest classifier trained on the modern IDS2025 dataset to detect DoS, PortScans, Brute Force, and Botnet traffic before cryptographic operations occur.
- **Hybrid Cryptography:** Secures files using AES-256-GCM (Symmetric Encryption), RSA-OAEP (Asymmetric Key Wrapping), and RSA-PSS (Digital Signatures). Keys are **RSA-3072** and stored using **PKCS#8** protection.
- **Robust API Hardening:** The API is protected by HTTP Basic Authentication, a volumetric rate limiter (5 requests/min), CORS restrictions, and a strict 100MB max file size limit to prevent Memory Exhaustion DoS attacks.
- **Strict Input Validation:** FastAPI and Pydantic strictly enforce valid network feature schemas, rejecting malformed packets instantly.
- **Full File Lifecycle:** Secure file uploads (`/upload`), encrypted file listing (`/files`), authenticated decryption/downloads (`/download/{filename}`), and secure file deletion (`/delete`).
- **Security Audit Logging:** All file transfer attempts and IDS predictions are securely logged in a local SQLite database (`audit_log.db`).
- **Advanced Empirical Testing:** Mathematically proven robustness via 5-Fold Cross Validation, Algorithm Comparisons (RF vs XGBoost vs LightGBM), and comprehensive Realistic Traffic CPU Benchmarking.

## API Endpoints
- `GET /` - The main frontend dashboard.
- `POST /upload` - Uploads, analyzes, encrypts, and signs a file.
- `GET /download/{filename}` - Verifies signatures, decrypts, and serves a file.
- `DELETE /files/{filename}` - Securely deletes an encrypted file and its metadata.
- `GET /files` - Lists all encrypted files currently stored on the server.
- `GET /health` - System healthcheck (DB, ML Model, Crypto Keys).
- `GET /metrics` - Returns the Random Forest model's performance metrics.

## Directory Structure
- `/crypto/` - Contains the custom Hybrid Cryptosystem implementation (AES + RSA). Fully documented with Google-style docstrings.
- `/ml/` - Contains the Machine Learning pipeline (Preprocessing, Training, Algorithm Comparison, K-Fold CV).
- `/docs/` - Contains detailed documentation, project overviews, and rigorous empirical results.
- `/data/` - Contains the training datasets (e.g., `IDS2025.xlsx`).
- `/static/` - Static assets, including the generated Baseline and Realistic Mix benchmark charts, and ML comparison charts.
- `/templates/` - Jinja2 HTML templates for the dashboard.
- `app.py` - The main FastAPI application.
- `database.py` - SQLite audit logging operations.
- `benchmark.py` - Script to generate CPU performance comparisons (Rate Limiting vs AI-Gated vs Crypto-Only).

## How to Run
1. Install requirements: `pip install -r requirements.txt`
2. Start the server: `python -m uvicorn app:app --host 127.0.0.1 --port 5000`
3. Visit `http://127.0.0.1:5000` in your browser.
4. Login with Username: `admin` / Password: `password`.
