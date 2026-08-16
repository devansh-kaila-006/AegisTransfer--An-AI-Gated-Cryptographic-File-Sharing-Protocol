# Machine Learning / IDS Subsystem

This module contains the Intrusion Detection System (IDS) pipeline responsible for analyzing incoming network requests and pre-emptively dropping malicious connections to save CPU resources.

## Pipeline Overview

1. **`preprocess.py`:** Loads the empirical `IDS2025.xlsx` dataset, cleans missing values, and separates the network flow features from the target labels.
2. **`train.py`:** 
   - Uses `RandomForestClassifier` for **Feature Selection**, reducing 79 raw network features down to the 10 most critical predictors (e.g., `Destination Port`, `Fwd IAT Mean`).
   - Conducts **Algorithm Comparisons** by training and evaluating `RandomForest`, `XGBoost`, and `LightGBM` simultaneously.
   - **Adversarial Training Defense:** Implements an advanced security hardening phase where the model is trained against synthetic adversarial perturbations (10% Gaussian Noise) to prevent evasion attacks.
   - Outputs the final, production-ready `ids_model.pkl` and visualization artifacts to the `/static/` directory.

## Advanced Evaluation Experiments
To mathematically justify our architectural choices, we ran comparative experiments:

1. **Algorithm Comparison:** 
   - **XGBoost:** Highest accuracy (98.84%) but slower inference (~38ms).
   - **LightGBM:** Lower accuracy (90.26%) and slower inference (~104ms).
   - **Random Forest:** Near-perfect accuracy (98.56%) and extremely fast inference (~89ms). 
   - *Conclusion:* Because the primary goal of this gatekeeper is to prevent resource exhaustion, **Random Forest** was selected for production due to its optimal balance of high accuracy and low inference time.

2. **Adversarial Robustness:** Machine learning models are vulnerable to attackers injecting slight statistical noise into their network packets to trick the IDS into classifying an attack as "Normal".
   - When the standard model was exposed to noisy data, its accuracy dropped to **17.88%**.
   - After applying our **Adversarial Training Defense**, the hardened model's accuracy on the same noisy adversarial data rebounded completely to **94.09%**.
   - *Conclusion:* The AI Gatekeeper is not just fast, it is highly resilient against sophisticated, AI-aware attackers trying to evade detection.
