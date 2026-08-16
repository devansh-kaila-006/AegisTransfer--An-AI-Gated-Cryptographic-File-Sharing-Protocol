import time
import os
import joblib
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from crypto.keys import generate_key_pair, load_public_key, load_private_key
from crypto.file_cipher import encrypt_file
from crypto.session import wrap_session_key, sign_payload

def run_benchmark():
    print("Running Pre-Emptive Resource Protection Benchmark...")
    # Load ML Model
    model_path = os.path.join("ml", "ids_model.pkl")
    features_path = os.path.join("ml", "feature_names.pkl")
    clf = joblib.load(model_path)
    feature_names = joblib.load(features_path)
    
    # ---------------------------------------------------------
    # Experiment 1: Baseline Comparison (Time per 100 requests)
    # ---------------------------------------------------------
    # 1. Rate Limiting Only (Dictionary lookup simulation)
    start_rl = time.time()
    rate_limit_db = {}
    for i in range(100):
        # simulate checking IP against dict and adding timestamp
        if "192.168.1.1" not in rate_limit_db:
            rate_limit_db["192.168.1.1"] = []
        rate_limit_db["192.168.1.1"].append(time.time())
    rl_time = (time.time() - start_rl) * 1000 # ms
    
    # 2. AI-Gated Only
    df_100 = pd.DataFrame(0, index=range(100), columns=feature_names)
    start_ml = time.time()
    _ = clf.predict(df_100)
    ml_time = (time.time() - start_ml) * 1000 # ms
    
    # 3. Crypto Only
    KEY_PASSPHRASE = "secure_college_project_passphrase"
    if not os.path.exists("server_private.pem_kem"):
        generate_key_pair("server_private.pem", "server_public.pem")
        
    priv_key = load_private_key("server_private.pem")
    pub_key = load_public_key("server_public.pem")
    dummy_data = b"A" * 1024 * 1024 * 5 # 5MB file
        
    start_crypto = time.time()
    for i in range(100):
        ciphertext, nonce, tag, key = encrypt_file(dummy_data)
        enc_key = wrap_session_key(key, pub_key)
        sign_payload(ciphertext, priv_key)
    crypto_time = (time.time() - start_crypto) * 1000 # ms
    
    print(f"\n--- Baseline Comparison (100 Requests) ---")
    print(f"Rate Limiting Only: {rl_time:.2f} ms")
    print(f"AI-Gated (Inference): {ml_time:.2f} ms")
    print(f"Traditional Crypto: {crypto_time:.2f} ms")
    
    # ---------------------------------------------------------
    # Experiment 2: Realistic Attack Mix (70% Benign, 30% Attack)
    # ---------------------------------------------------------
    # Traditional System: Processes 100 requests with Crypto (it doesn't know what is malicious)
    traditional_mix_time = crypto_time
    
    # AI-Gated System: Processes 100 requests with ML, drops 30, processes 70 with Crypto
    start_crypto_70 = time.time()
    for i in range(70):
        ciphertext, nonce, tag, key = encrypt_file(dummy_data)
        enc_key = wrap_session_key(key, pub_key)
        sign_payload(ciphertext, priv_key)
    crypto_70_time = (time.time() - start_crypto_70) * 1000
    
    ai_mix_time = ml_time + crypto_70_time
    
    print(f"\n--- Realistic Traffic Mix (70 Benign / 30 Attack) ---")
    print(f"Traditional System CPU Time: {traditional_mix_time:.2f} ms")
    print(f"AI-Gated System CPU Time: {ai_mix_time:.2f} ms")
    print(f"Resource Savings: {((traditional_mix_time - ai_mix_time) / traditional_mix_time) * 100:.2f}%")
    
    # ---------------------------------------------------------
    # Generate Charts
    # ---------------------------------------------------------
    static_dir = "static"
    os.makedirs(static_dir, exist_ok=True)
    
    # Chart 1
    plt.figure(figsize=(10, 6))
    sns.barplot(x=['Rate Limiting', 'AI-Gated (ML)', 'Crypto-Only'], y=[rl_time, ml_time, crypto_time], palette=['blue', 'green', 'red'])
    plt.title('Baseline CPU Cost (100 Malicious Requests)')
    plt.ylabel('CPU Time (ms)')
    plt.yscale('log') # Log scale because crypto is massive
    plt.tight_layout()
    plt.savefig(os.path.join(static_dir, "benchmark_baseline.png"))
    plt.close()
    
    # Chart 2
    plt.figure(figsize=(8, 6))
    sns.barplot(x=['Traditional Architecture\n(100% Crypto Processing)', 'AI-Gated Architecture\n(30% Pre-Emptive Drop)'], y=[traditional_mix_time, ai_mix_time], palette=['#F44336', '#4CAF50'])
    plt.title('Realistic Traffic Mix CPU Cost\n(70 Benign / 30 Malicious)')
    plt.ylabel('Total CPU Time (ms)')
    plt.tight_layout()
    plt.savefig(os.path.join(static_dir, "benchmark_realistic.png"))
    plt.close()
    
    print(f"\nBenchmark charts saved to {static_dir}/")

if __name__ == "__main__":
    run_benchmark()
