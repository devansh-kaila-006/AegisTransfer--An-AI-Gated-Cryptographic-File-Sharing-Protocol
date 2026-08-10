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
        
        # Train time
        t0 = time.time()
        model.fit(X_train, y_train)
        train_time = time.time() - t0
        
        # Inference time (batch of size len(X_test))
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
    
    print("\n--- K-Fold Cross Validation (Random Forest) ---")
    # Cross validation to mathematically prove robustness without needing NSL-KDD
    rf_cv = RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1)
    # Convert X[top_features] to numpy to avoid feature name warnings during CV
    scores = cross_val_score(rf_cv, X[top_features], y_encoded, cv=5, scoring='accuracy')
    print(f"5-Fold CV Accuracy: {scores.mean():.4f} (+/- {scores.std() * 2:.4f})")
    
    # We will save the original Random Forest trained on un-encoded labels for seamless integration with app.py
    print("\nTraining final Production Random Forest model (Unencoded Labels)...")
    final_rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    # Re-split with unencoded y for the final model so it outputs strings like "Dos/DDos"
    X_train_unenc, X_test_unenc, y_train_unenc, y_test_unenc = train_test_split(X[top_features], y, test_size=0.25, stratify=y, random_state=42)
    final_rf.fit(X_train_unenc, y_train_unenc)
    
    # Plotting comparisons
    base_dir = os.path.join(os.path.dirname(__file__), '..')
    static_dir = os.path.join(base_dir, "static")
    os.makedirs(static_dir, exist_ok=True)
    
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
    
    print(f"Saving production model and artifacts...")
    model_path = os.path.join(os.path.dirname(__file__), "ids_model.pkl")
    features_path = os.path.join(os.path.dirname(__file__), "feature_names.pkl")
    joblib.dump(final_rf, model_path)
    joblib.dump(top_features, features_path)
        
    print("Training complete! Visualizations saved to /static/")

if __name__ == "__main__":
    train_model()
