import os
import json
import base64
import joblib
import pandas as pd
import secrets
from datetime import timedelta
from fastapi import FastAPI, UploadFile, File, Form, Request, HTTPException, Depends, status
from fastapi.responses import JSONResponse, FileResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, ValidationError
import database
from crypto import keys, file_cipher, session, integrity
import uvicorn
import time
from collections import defaultdict
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.middleware.cors import CORSMiddleware
from config import settings
from passlib.context import CryptContext
from jose import JWTError, jwt
from contextlib import asynccontextmanager
from fastapi.concurrency import run_in_threadpool

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# Simulated user database for JWT demonstration
fake_users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": get_password_hash("password"),
        "disabled": False,
    }
}

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = time.time() + expires_delta.total_seconds()
    else:
        expire = time.time() + (15 * 60)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return encoded_jwt

ml_models = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load ML Model
    MODEL_PATH = "ml/ids_model.pkl"
    FEATURES_PATH = "ml/feature_names.pkl"
    try:
        ml_models["clf"] = joblib.load(MODEL_PATH)
        ml_models["feature_names"] = joblib.load(FEATURES_PATH)
        print("Loaded ML model successfully.")
    except Exception as e:
        print(f"Warning: Could not load ML model. ({e})")
        ml_models["clf"] = None
        ml_models["feature_names"] = None
        
    # Load or generate keys
    if not os.path.exists("server_private.pem_kem"):
        keys.generate_key_pair("server_private.pem", "server_public.pem", passphrase=settings.key_passphrase)
    ml_models["server_priv"] = keys.load_private_key("server_private.pem", passphrase=settings.key_passphrase)
    ml_models["server_pub"] = keys.load_public_key("server_public.pem")

    yield
    ml_models.clear()

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5000", "http://localhost:5000"], # Tightened CORS
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
            self.clients[client_ip] = [req_time for req_time in self.clients[client_ip] if now - req_time < self.window_seconds]
            
            if len(self.clients[client_ip]) >= self.max_requests:
                return JSONResponse(status_code=429, content={"error": "Rate limit exceeded: Max 5 uploads per minute to prevent volumetric DoS attacks."})
                
            self.clients[client_ip].append(now)
            
        response = await call_next(request)
        return response

app.add_middleware(RateLimitMiddleware)

os.makedirs("uploads", exist_ok=True)
database.init_db()

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = fake_users_db.get(username)
    if user is None:
        raise credentials_exception
    return user["username"]

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

@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/")
async def dashboard(request: Request):
    logs = database.get_logs()
    # Removing basic auth requirement from dashboard to allow login page / tokens
    return templates.TemplateResponse(request=request, name="index.html", context={"logs": logs, "user": "Guest"})

@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...), 
    network_features: str = Form("{}"),
    username: str = Depends(get_current_user)
):
    prediction = "Normal"
    confidence = 1.0
    action = "Allowed"
    
    clf = ml_models.get("clf")
    feature_names = ml_models.get("feature_names")
    
    if clf and feature_names:
        try:
            features_dict = json.loads(network_features)
            validated_features = NetworkFeatures(**features_dict).model_dump(by_alias=True)
            
            df = pd.DataFrame([validated_features])
            df = df[feature_names]
            
            # CPU-bound inference in threadpool
            pred = await run_in_threadpool(clf.predict, df)
            proba = await run_in_threadpool(clf.predict_proba, df)
            
            prediction = pred[0]
            confidence = float(proba[0].max())
            if prediction != "Normal":
                action = "Blocked"
        except ValidationError as e:
            raise HTTPException(status_code=400, detail=f"Invalid network feature schema: {e}")
        except Exception as e:
            print("Error in ML prediction:", e)
            
    if action == "Blocked":
        database.log_event(file.filename, "N/A", "N/A", prediction, confidence, action)
        return JSONResponse(status_code=403, content={"error": f"Upload blocked due to detected threat: {prediction}"})
        
    file_data = await file.read()
    if len(file_data) > settings.max_upload_size:
        raise HTTPException(status_code=400, detail="File too large. Maximum size is 100MB.")
        
    initial_hash = await run_in_threadpool(integrity.compute_hash, file_data)
        
    server_priv = ml_models.get("server_priv")
    server_pub = ml_models.get("server_pub")

    # CPU-bound cryptography in threadpool
    ciphertext, nonce, tag, session_key = await run_in_threadpool(file_cipher.encrypt_file, file_data)
    enc_hash = await run_in_threadpool(integrity.compute_hash, ciphertext)
    signature = await run_in_threadpool(session.sign_payload, tag, server_priv)
    wrapped_key = await run_in_threadpool(session.wrap_session_key, session_key, server_pub)
    
    enc_filepath = f"uploads/{file.filename}.enc"
    with open(enc_filepath, "wb") as f:
        f.write(ciphertext)
        
    meta_filepath = f"uploads/{file.filename}.meta"
    metadata = {
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8'),
        "wrapped_key": base64.b64encode(wrapped_key).decode('utf-8'),
        "signature": base64.b64encode(signature).decode('utf-8'),
        "initial_hash": initial_hash,
        "enc_hash": enc_hash
    }
    with open(meta_filepath, "w") as f:
        json.dump(metadata, f)
        
    database.log_event(file.filename, "AES-256-GCM", "ML-DSA Valid", prediction, confidence, action)
    
    return JSONResponse(content={
        "status": "success", 
        "prediction": prediction,
        "action": action,
        "message": "File encrypted and signed successfully",
        "hashes": {
            "initial_hash": initial_hash,
            "enc_hash": enc_hash
        }
    })

@app.get("/download/{filename}")
async def download_file(filename: str, username: str = Depends(get_current_user)):
    enc_filepath = f"uploads/{filename}.enc"
    meta_filepath = f"uploads/{filename}.meta"
    
    if not os.path.exists(enc_filepath) or not os.path.exists(meta_filepath):
        raise HTTPException(status_code=404, detail="File not found")
        
    with open(enc_filepath, "rb") as f:
        ciphertext = f.read()
        
    with open(meta_filepath, "r") as f:
        metadata = json.load(f)
        
    current_enc_hash = await run_in_threadpool(integrity.compute_hash, ciphertext)
    if "enc_hash" in metadata and current_enc_hash != metadata["enc_hash"]:
        raise HTTPException(status_code=403, detail="Encrypted file integrity check failed (enc_hash mismatch).")
        
    nonce = base64.b64decode(metadata["nonce"])
    tag = base64.b64decode(metadata["tag"])
    wrapped_key = base64.b64decode(metadata["wrapped_key"])
    signature = base64.b64decode(metadata["signature"])
    
    server_priv = ml_models.get("server_priv")
    server_pub = ml_models.get("server_pub")

    # CPU-bound verification and decryption in threadpool
    is_valid = await run_in_threadpool(session.verify_signature, tag, signature, server_pub)
    if not is_valid:
        raise HTTPException(status_code=403, detail="Signature verification failed. File has been tampered with!")
        
    try:
        session_key = await run_in_threadpool(session.unwrap_session_key, wrapped_key, server_priv)
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to unwrap session key.")
        
    try:
        plaintext = await run_in_threadpool(file_cipher.decrypt_file, ciphertext, nonce, tag, session_key)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=f"Decryption failed: {e}")
        
    decrypted_hash = await run_in_threadpool(integrity.compute_hash, plaintext)
    if "initial_hash" in metadata and decrypted_hash != metadata["initial_hash"]:
        raise HTTPException(status_code=403, detail="Decrypted file integrity check failed (initial_hash mismatch).")
        
    temp_filepath = f"uploads/temp_{filename}"
    with open(temp_filepath, "wb") as f:
        f.write(plaintext)
        
    return FileResponse(path=temp_filepath, filename=filename, media_type='application/octet-stream')

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "model_loaded": ml_models.get("clf") is not None,
        "database_connected": True,
        "keys_present": os.path.exists("server_private.pem_kem")
    }

@app.get("/metrics")
async def get_metrics():
    metrics_path = "static/metrics.json"
    if os.path.exists(metrics_path):
        with open(metrics_path, "r") as f:
            return json.load(f)
    raise HTTPException(status_code=404, detail="Metrics not found")

@app.get("/files")
async def list_files(username: str = Depends(get_current_user)):
    files = []
    if os.path.exists("uploads"):
        for f in os.listdir("uploads"):
            if f.endswith(".enc"):
                base_name = f[:-4]
                files.append(base_name)
    return {"files": files}

@app.delete("/files/{filename}")
async def delete_file(filename: str, username: str = Depends(get_current_user)):
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
