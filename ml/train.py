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
    
    # Encode targets for XGBoost/LightGBM compatibility
    le = LabelEncoder()
    y_encoded = le.fit_transform(y)
    
    print("Splitting data (75/25)...")
    X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.25, stratify=y_encoded, random_state=42)
    
    print("Training initial Random Forest to determine feature importance...")
    initial_clf = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
    initial_clf.fit(X_train, y_train)
    
    # Feature Selection: Get top 10 features
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
    
    # --- ADVERSARIAL ML DEFENSE PHASE ---
    print("\n--- Phase 2: Adversarial Robustness & Training ---")
    
    # Re-split with unencoded y for the final model so it outputs strings like "Dos/DDos"
    X_train_unenc, X_test_unenc, y_train_unenc, y_test_unenc = train_test_split(X[top_features], y, test_size=0.25, stratify=y, random_state=42)
    
    # Train Standard (Baseline) Model
    standard_rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    standard_rf.fit(X_train_unenc, y_train_unenc)
    
    # Generate Synthetic Adversarial Test Set
    print("Generating Synthetic Adversarial Test Set (Noise Injection)...")
    attack_indices_test = y_test_unenc != "Normal"
    X_test_attacks = X_test_unenc[attack_indices_test].copy()
    y_test_attacks = y_test_unenc[attack_indices_test]
    
    # Add 10% Gaussian noise relative to standard deviation to simulate feature evasion
    noise = np.random.normal(0, 0.10 * X_test_attacks.std(axis=0), X_test_attacks.shape)
    X_test_adv = X_test_attacks + noise
    
    # Evaluate Standard Model on Adversarial Data
    y_pred_adv_standard = standard_rf.predict(X_test_adv)
    acc_standard_adv = accuracy_score(y_test_attacks, y_pred_adv_standard)
    print(f"Standard Model Accuracy on Adversarial Data: {acc_standard_adv:.4f}")
    
    # Generate Adversarial Training Set
    print("Hardening Model: Generating Adversarial Training Data...")
    attack_indices_train = y_train_unenc != "Normal"
    X_train_attacks = X_train_unenc[attack_indices_train].copy()
    y_train_attacks = y_train_unenc[attack_indices_train]
    
    noise_train = np.random.normal(0, 0.10 * X_train_attacks.std(axis=0), X_train_attacks.shape)
    X_train_adv = X_train_attacks + noise_train
    
    # Concatenate clean and adversarial data
    X_train_hardened = pd.concat([X_train_unenc, X_train_adv])
    y_train_hardened = pd.concat([y_train_unenc, y_train_attacks])
    
    # Train Hardened Model
    hardened_rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    hardened_rf.fit(X_train_hardened, y_train_hardened)
    
    # Evaluate Hardened Model on Adversarial Data
    y_pred_adv_hardened = hardened_rf.predict(X_test_adv)
    acc_hardened_adv = accuracy_score(y_test_attacks, y_pred_adv_hardened)
    print(f"Hardened Model Accuracy on Adversarial Data: {acc_hardened_adv:.4f}")
    
    # Generate Adversarial Robustness Chart
    base_dir = os.path.join(os.path.dirname(__file__), '..')
    static_dir = os.path.join(base_dir, "static")
    os.makedirs(static_dir, exist_ok=True)
    
    plt.figure(figsize=(8, 6))
    sns.barplot(x=['Standard RF', 'Hardened RF'], y=[acc_standard_adv, acc_hardened_adv], palette=['#f44336', '#4CAF50'])
    plt.title('Model Robustness Against Adversarial Attacks (10% Noise)')
    plt.ylabel('Accuracy on Adversarial Test Set')
    plt.ylim(0, 1.0)
    for i, v in enumerate([acc_standard_adv, acc_hardened_adv]):
        plt.text(i, v + 0.02, f'{v:.2f}', ha='center', fontweight='bold')
    plt.tight_layout()
    plt.savefig(os.path.join(static_dir, "adversarial_robustness.png"))
    plt.close()
    
    # 1. Model Comparison Chart
    fig, ax1 = plt.subplots(figsize=(10, 6))
    sns.barplot(x="Model", y="Accuracy", data=res_df, ax=ax1, color='lightblue')
    ax1.set_ylim(0.9, 1.0)
    ax1.set_ylabel("Accuracy", color='blue')
    
    ax2 = ax1.twinx()
    sns.lineplot(x="Model", y="Inference Time (ms)", data=res_df, ax=ax2, color='red', marker="o")
    ax2.set_ylabel("Inference Time (ms)", color='red')
    
    plt.title("ML Algorithm Comparison: Accuracy vs Inference Speed")
    plt.tight_layout()
    plt.savefig(os.path.join(static_dir, "ml_comparison.png"))
    plt.close()
    
    print(f"\nSaving production Hardened model and artifacts...")
    model_path = os.path.join(os.path.dirname(__file__), "ids_model.pkl")
    features_path = os.path.join(os.path.dirname(__file__), "feature_names.pkl")
    joblib.dump(hardened_rf, model_path)
    joblib.dump(top_features, features_path)
        
    print("Training complete! Visualizations saved to /static/")

if __name__ == "__main__":
    train_model()
