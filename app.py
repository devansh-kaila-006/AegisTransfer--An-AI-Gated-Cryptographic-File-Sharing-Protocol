import os
import json
import base64
import joblib
import pandas as pd
import secrets
from fastapi import FastAPI, UploadFile, File, Form, Request, HTTPException, Depends, status
from fastapi.responses import JSONResponse, FileResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field, ValidationError
import database
from crypto import keys, file_cipher, session
import uvicorn
import time
from collections import defaultdict
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.middleware.cors import CORSMiddleware

MAX_UPLOAD_SIZE = int(os.getenv("MAX_UPLOAD_SIZE", "104857600")) # 100MB

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBasic()

class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_requests: int = 5, window_seconds: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.clients = defaultdict(list)
        
    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/upload" and request.method == "POST":
            client_ip = request.client.host
            now = time.time()
            # Clean up old requests outside the time window
            self.clients[client_ip] = [req_time for req_time in self.clients[client_ip] if now - req_time < self.window_seconds]
            
            if len(self.clients[client_ip]) >= self.max_requests:
                return JSONResponse(status_code=429, content={"error": "Rate limit exceeded: Max 5 uploads per minute to prevent volumetric DoS attacks."})
                
            self.clients[client_ip].append(now)
            
        response = await call_next(request)
        return response

app.add_middleware(RateLimitMiddleware)

# Ensure required directories exist
os.makedirs("uploads", exist_ok=True)
database.init_db()

# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# --- Authentication ---
def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(credentials.username, "admin")
    correct_password = secrets.compare_digest(credentials.password, "password")
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# --- Input Validation (Pydantic) ---
class NetworkFeatures(BaseModel):
    Destination_Port: float = Field(alias="Destination Port")
    Average_Packet_Size: float = Field(alias="Average Packet Size")
    Packet_Length_Mean: float = Field(alias="Packet Length Mean")
    Fwd_IAT_Mean: float = Field(alias="Fwd IAT Mean")
    Total_Fwd_Packets: float = Field(alias="Total Fwd Packets")
    PSH_Flag_Count: float = Field(alias="PSH Flag Count")
    Bwd_Packet_Length_Min: float = Field(alias="Bwd Packet Length Min")
    Bwd_Packetss: float = Field(alias="Bwd Packetss")
    Init_Win_bytes_forward: float = Field(alias="Init_Win_bytes_forward")
    Fwd_IAT_Max: float = Field(alias="Fwd IAT Max")

# Load ML Model
MODEL_PATH = "ml/ids_model.pkl"
FEATURES_PATH = "ml/feature_names.pkl"
try:
    clf = joblib.load(MODEL_PATH)
    feature_names = joblib.load(FEATURES_PATH)
    print("Loaded ML model successfully.")
except Exception as e:
    print(f"Warning: Could not load ML model. ({e})")
    clf, feature_names = None, None

# Load or generate keys
KEY_PASSPHRASE = "secure_college_project_passphrase"
if not os.path.exists("server_private.pem"):
    keys.generate_key_pair("server_private.pem", "server_public.pem", passphrase=KEY_PASSPHRASE)
server_priv = keys.load_private_key("server_private.pem", passphrase=KEY_PASSPHRASE)
server_pub = keys.load_public_key("server_public.pem")

@app.get("/")
async def dashboard(request: Request, username: str = Depends(verify_credentials)):
    logs = database.get_logs()
    return templates.TemplateResponse(request=request, name="index.html", context={"logs": logs, "user": username})

@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...), 
    network_features: str = Form("{}"),
    username: str = Depends(verify_credentials)
):
    prediction = "Normal"
    confidence = 1.0
    action = "Allowed"
    
    # Input Validation & ML Prediction
    if clf and feature_names:
        try:
            # Pydantic strict validation
            features_dict = json.loads(network_features)
            validated_features = NetworkFeatures(**features_dict).model_dump(by_alias=True)
            
            df = pd.DataFrame([validated_features])
            df = df[feature_names] # Ensure ordering matches training
            
            pred = clf.predict(df)[0]
            proba = clf.predict_proba(df)[0].max()
            prediction = pred
            confidence = float(proba)
            if prediction != "Normal":
                action = "Blocked"
        except ValidationError as e:
            raise HTTPException(status_code=400, detail=f"Invalid network feature schema: {e}")
        except Exception as e:
            print("Error in ML prediction:", e)
            
    if action == "Blocked":
        database.log_event(file.filename, "N/A", "N/A", prediction, confidence, action)
        return JSONResponse(status_code=403, content={"error": f"Upload blocked due to detected threat: {prediction}"})
        
    # Cryptographic Processing
    file_data = await file.read()
    if len(file_data) > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=400, detail="File too large. Maximum size is 100MB.")
        
    ciphertext, nonce, tag, session_key = file_cipher.encrypt_file(file_data)
    
    signature = session.sign_payload(tag, server_priv)
    wrapped_key = session.wrap_session_key(session_key, server_pub)
    
    # Save the encrypted file
    enc_filepath = f"uploads/{file.filename}.enc"
    with open(enc_filepath, "wb") as f:
        f.write(ciphertext)
        
    # Save the cryptographic metadata required for decryption
    meta_filepath = f"uploads/{file.filename}.meta"
    metadata = {
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8'),
        "wrapped_key": base64.b64encode(wrapped_key).decode('utf-8'),
        "signature": base64.b64encode(signature).decode('utf-8')
    }
    with open(meta_filepath, "w") as f:
        json.dump(metadata, f)
        
    database.log_event(file.filename, "AES-256-GCM", "RSA-PSS Valid", prediction, confidence, action)
    
    return JSONResponse(content={
        "status": "success", 
        "prediction": prediction,
        "action": action,
        "message": "File encrypted and signed successfully"
    })

@app.get("/download/{filename}")
async def download_file(filename: str, username: str = Depends(verify_credentials)):
    enc_filepath = f"uploads/{filename}.enc"
    meta_filepath = f"uploads/{filename}.meta"
    
    if not os.path.exists(enc_filepath) or not os.path.exists(meta_filepath):
        raise HTTPException(status_code=404, detail="File not found")
        
    # Load encrypted data
    with open(enc_filepath, "rb") as f:
        ciphertext = f.read()
        
    # Load metadata
    with open(meta_filepath, "r") as f:
        metadata = json.load(f)
        
    nonce = base64.b64decode(metadata["nonce"])
    tag = base64.b64decode(metadata["tag"])
    wrapped_key = base64.b64decode(metadata["wrapped_key"])
    signature = base64.b64decode(metadata["signature"])
    
    # 1. Verify Signature
    is_valid = session.verify_signature(tag, signature, server_pub)
    if not is_valid:
        raise HTTPException(status_code=403, detail="Signature verification failed. File has been tampered with!")
        
    # 2. Unwrap Session Key
    try:
        session_key = session.unwrap_session_key(wrapped_key, server_priv)
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to unwrap session key.")
        
    # 3. Decrypt File
    try:
        plaintext = file_cipher.decrypt_file(ciphertext, nonce, tag, session_key)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=f"Decryption failed: {e}")
        
    # Write plaintext to temp file to send to user
    temp_filepath = f"uploads/temp_{filename}"
    with open(temp_filepath, "wb") as f:
        f.write(plaintext)
        
    return FileResponse(path=temp_filepath, filename=filename, media_type='application/octet-stream')

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "model_loaded": clf is not None,
        "database_connected": True,
        "keys_present": os.path.exists("server_private.pem")
    }

@app.get("/metrics")
async def get_metrics():
    metrics_path = "static/metrics.json"
    if os.path.exists(metrics_path):
        with open(metrics_path, "r") as f:
            return json.load(f)
    raise HTTPException(status_code=404, detail="Metrics not found")

@app.get("/files")
async def list_files(username: str = Depends(verify_credentials)):
    files = []
    if os.path.exists("uploads"):
        for f in os.listdir("uploads"):
            if f.endswith(".enc"):
                base_name = f[:-4] # remove .enc
                files.append(base_name)
    return {"files": files}

@app.delete("/files/{filename}")
async def delete_file(filename: str, username: str = Depends(verify_credentials)):
    enc_filepath = f"uploads/{filename}.enc"
    meta_filepath = f"uploads/{filename}.meta"
    
    deleted = False
    if os.path.exists(enc_filepath):
        os.remove(enc_filepath)
        deleted = True
    if os.path.exists(meta_filepath):
        os.remove(meta_filepath)
        deleted = True
        
    if not deleted:
        raise HTTPException(status_code=404, detail="File not found")
        
    return {"status": "success", "message": f"Deleted {filename}"}

if __name__ == '__main__':
    uvicorn.run("app:app", host="127.0.0.1", port=5000, reload=True)
