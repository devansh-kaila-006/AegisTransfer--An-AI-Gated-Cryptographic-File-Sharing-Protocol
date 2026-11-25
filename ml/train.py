import pandas as pd
import numpy as np
import time
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib
from preprocess import load_and_clean_data
import os
import json
import matplotlib.pyplot as plt
import seaborn as sns

def train_model():
    print("--- Phase 1: Advanced ML Pipeline & Comparisons ---")
    data_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'IDS2025.xlsx')
    X, y = load_and_clean_data(data_path)
    
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    
    print("Splitting data (75/25)...")
    X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.25, stratify=y_encoded, random_state=42)
    
    print("Training initial Random Forest to determine feature importance...")
    initial_clf = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
    initial_clf.fit(X_train, y_train)
    
    importances = initial_clf.feature_importances_
    indices = np.argsort(importances)[::-1][:10]
    top_features = [X.columns[i] for i in indices]
    print(f"\nSelected Top 10 Features: {top_features}")
    
    X_train = X_train[top_features]
    X_test = X_test[top_features]
    
    print("\n--- Model Algorithm Comparison ---")
    models = {
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
        "XGBoost": XGBClassifier(n_estimators=100, random_state=42, n_jobs=-1, use_label_encoder=False, eval_metric='mlogloss'),
        "LightGBM": LGBMClassifier(n_estimators=100, random_state=42, n_jobs=-1, verbose=-1)
    }
    
    results = []
    for name, model in models.items():
        print(f"Training {name}...")
        t0 = time.time()
        model.fit(X_train, y_train)
        train_time = time.time() - t0
        
        t1 = time.time()
        y_pred = model.predict(X_test)
        inference_time = (time.time() - t1) * 1000 # ms
        
        acc = accuracy_score(y_test, y_pred)
        results.append({
            "Model": name,
            "Accuracy": acc,
            "Train Time (s)": train_time,
            "Inference Time (ms)": inference_time
        })
        print(f"{name} -> Acc: {acc:.4f} | Inf Time: {inference_time:.2f}ms")
        
    res_df = pd.DataFrame(results)
    
    # --- ADVERSARIAL ML DEFENSE PHASE (Noise Sweep) ---
    print("\n--- Phase 2: Adversarial Robustness & Training ---")
    
    X_train_unenc, X_test_unenc, y_train_unenc, y_test_unenc = train_test_split(X[top_features], y, test_size=0.25, stratify=y, random_state=42)
    
    standard_rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    standard_rf.fit(X_train_unenc, y_train_unenc)
    
    print("Hardening Model: Generating Adversarial Training Data (10% Noise)...")
    attack_indices_train = y_train_unenc != "Normal"
    X_train_attacks = X_train_unenc[attack_indices_train].copy()
    y_train_attacks = y_train_unenc[attack_indices_train]
    
    noise_train = np.random.normal(0, 0.10 * X_train_attacks.std(axis=0), X_train_attacks.shape)
    X_train_adv = X_train_attacks + noise_train
    
    X_train_hardened = pd.concat([X_train_unenc, X_train_adv])
    y_train_hardened = pd.concat([y_train_unenc, y_train_attacks])
    
    hardened_rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    hardened_rf.fit(X_train_hardened, y_train_hardened)
    
    # Evaluate across a noise sweep
    noise_levels = [0.05, 0.10, 0.20, 0.30]
    standard_accs = []
    hardened_accs = []
    
    attack_indices_test = y_test_unenc != "Normal"
    X_test_attacks = X_test_unenc[attack_indices_test].copy()
    y_test_attacks = y_test_unenc[attack_indices_test]
    
    print("Evaluating models across noise sweep...")
    for noise_pct in noise_levels:
        noise = np.random.normal(0, noise_pct * X_test_attacks.std(axis=0), X_test_attacks.shape)
        X_test_adv = X_test_attacks + noise
        
        pred_std = standard_rf.predict(X_test_adv)
        standard_accs.append(accuracy_score(y_test_attacks, pred_std))
        
        pred_hard = hardened_rf.predict(X_test_adv)
        hardened_accs.append(accuracy_score(y_test_attacks, pred_hard))
    
    base_dir = os.path.join(os.path.dirname(__file__), '..')
    static_dir = os.path.join(base_dir, "static")
    os.makedirs(static_dir, exist_ok=True)
    
    plt.figure(figsize=(8, 6))
    noise_labels = [f"{int(n*100)}%" for n in noise_levels]
    plt.plot(noise_labels, standard_accs, marker='o', color='#f44336', label='Standard RF', linewidth=2)
    plt.plot(noise_labels, hardened_accs, marker='o', color='#4CAF50', label='Hardened RF (Adversarial Training)', linewidth=2)
    
    plt.title('Model Robustness Against Gaussian Feature Perturbation')
    plt.ylabel('Accuracy on Adversarial Test Set')
    plt.xlabel('Noise Intensity (% of standard deviation)')
    plt.ylim(0, 1.0)
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig(os.path.join(static_dir, "adversarial_robustness.png"))
    plt.close()
    
    # Re-generate metrics.json
    metrics_path = os.path.join(static_dir, "metrics.json")
    y_pred_hard = hardened_rf.predict(X_test_unenc)
    with open(metrics_path, 'w') as f:
        json.dump({
            "accuracy": accuracy_score(y_test_unenc, y_pred_hard),
            "classes": list(hardened_rf.classes_),
            "report": classification_report(y_test_unenc, y_pred_hard, output_dict=True)
        }, f, indent=4)
    
    print(f"\nSaving production Hardened model and artifacts...")
    model_path = os.path.join(os.path.dirname(__file__), "ids_model.pkl")
    features_path = os.path.join(os.path.dirname(__file__), "feature_names.pkl")
    
    # Compress the model (fixes 80MB bloat)
    joblib.dump(hardened_rf, model_path, compress=3)
    joblib.dump(top_features, features_path)
        
    print("Training complete! Visualizations saved to /static/")

if __name__ == "__main__":
    train_model()
