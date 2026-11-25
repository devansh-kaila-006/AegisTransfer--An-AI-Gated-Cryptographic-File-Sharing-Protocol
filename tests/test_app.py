import pytest
import os
import json
from fastapi.testclient import TestClient
from app import app, get_password_hash
import base64

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

def get_auth_token(client):
    response = client.post(
        "/token", 
        data={"username": "admin", "password": "password"}
    )
    assert response.status_code == 200
    return response.json()["access_token"]

valid_features = json.dumps({
    "Destination Port": 80,
    "Average Packet Size": 100,
    "Packet Length Mean": 50,
    "Fwd IAT Mean": 10,
    "Total Fwd Packets": 5,
    "PSH Flag Count": 0,
    "Bwd Packet Length Min": 0,
    "Bwd Packetss": 2,
    "Init_Win_bytes_forward": 256,
    "Fwd IAT Max": 100
})

def test_auth_401(client):
    """Test that missing or invalid auth yields 401 on protected endpoints."""
    response = client.post("/upload", files={"file": ("test.txt", b"hello")}, data={"network_features": valid_features})
    assert response.status_code == 401

def test_traversal_rejection(client):
    """Test that path traversal attempts in filenames are sanitized."""
    token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {token}"}
    
    # Upload with a path traversal filename
    response = client.post(
        "/upload", 
        headers=headers,
        files={"file": ("../../etc/passwd", b"malicious content")}, 
        data={"network_features": valid_features}
    )
    assert response.status_code == 200
    
    assert os.path.exists("uploads/passwd.enc")
    
    os.remove("uploads/passwd.enc")
    os.remove("uploads/passwd.meta")

def test_encrypt_decrypt_roundtrip(client):
    """Test a full upload (encrypt) and download (decrypt) cycle."""
    token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {token}"}
    
    filename = "roundtrip_test.txt"
    content = b"Super secret data for roundtrip testing"
    
    # Upload
    res_up = client.post(
        "/upload", 
        headers=headers,
        files={"file": (filename, content)}, 
        data={"network_features": valid_features}
    )
    assert res_up.status_code == 200
    assert os.path.exists(f"uploads/{filename}.enc")
    
    # Download
    res_down = client.get(
        f"/download/{filename}", 
        headers=headers
    )
    assert res_down.status_code == 200
    assert res_down.content == content
    
    # Cleanup
    client.delete(f"/files/{filename}", headers=headers)
    assert not os.path.exists(f"uploads/{filename}.enc")

def test_tamper_signature_fail(client):
    """Test that modifying the encrypted file triggers a signature/integrity failure."""
    token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {token}"}
    
    filename = "tamper_test.txt"
    
    client.post(
        "/upload", 
        headers=headers,
        files={"file": (filename, b"Important data")}, 
        data={"network_features": valid_features}
    )
    
    enc_filepath = f"uploads/{filename}.enc"
    
    # Tamper with the ciphertext
    with open(enc_filepath, "ab") as f:
        f.write(b"tamper")
        
    # Attempt download
    res_down = client.get(f"/download/{filename}", headers=headers)
    assert res_down.status_code == 403
    assert "integrity check failed" in res_down.json()["detail"] or "Signature verification failed" in res_down.json()["detail"]
    
    # Cleanup
    os.remove(enc_filepath)
    os.remove(f"uploads/{filename}.meta")

def test_rate_limit_429(client):
    """Test that the rate limiter blocks more than 5 requests."""
    token = get_auth_token(client)
    headers = {"Authorization": f"Bearer {token}"}
    
    for _ in range(5):
        client.post(
            "/upload", 
            headers=headers,
            files={"file": ("limit.txt", b"data")}, 
            data={"network_features": valid_features}
        )
        
    response = client.post(
        "/upload", 
        headers=headers,
        files={"file": ("limit.txt", b"data")}, 
        data={"network_features": valid_features}
    )
    assert response.status_code == 429
    assert "Rate limit exceeded" in response.json()["error"]
    
    if os.path.exists("uploads/limit.txt.enc"):
        os.remove("uploads/limit.txt.enc")
    if os.path.exists("uploads/limit.txt.meta"):
        os.remove("uploads/limit.txt.meta")
