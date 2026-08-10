# Machine Learning / IDS Subsystem

This module contains the Intrusion Detection System (IDS) pipeline responsible for analyzing incoming network requests and pre-emptively dropping malicious connections to save CPU resources.

## Pipeline Overview

1. **`preprocess.py`:** Loads the empirical `IDS2025.xlsx` dataset, cleans missing values, and separates the network flow features from the target labels.
2. **`train.py`:** 
   - Uses `RandomForestClassifier` for **Feature Selection**, reducing 79 raw network features down to the 10 most critical predictors (e.g., `Destination Port`, `Fwd IAT Mean`).
   - Conducts **Algorithm Comparisons** by training and evaluating `RandomForest`, `XGBoost`, and `LightGBM` simultaneously.
   - Proves model robustness mathematically using **5-Fold Cross Validation**.
   - Outputs the final, production-ready `ids_model.pkl` and visualization artifacts to the `/static/` directory.

## Advanced Evaluation Experiments
To mathematically justify our architectural choices, we ran comparative experiments:

1. **Algorithm Comparison:** 
   - **XGBoost:** Highest accuracy (98.84%) but slower inference (~81ms).
   - **LightGBM:** Lowest accuracy (92.92%) and slowest inference (~122ms).
   - **Random Forest:** Near-perfect accuracy (98.56%) and the fastest inference (~57ms). 
   - *Conclusion:* Because the primary goal of this gatekeeper is to prevent resource exhaustion, **Random Forest** was selected for production due to its optimal balance of high accuracy and extremely low inference time.

2. **Cross Validation:** The production Random Forest model achieved an average **98.57% (+/- 0.0009)** accuracy across 5-Fold Cross Validation, proving it does not overfit to the training set and generalizes exceptionally well to unseen anomalous behaviors (DoS, Botnets, Brute Force).
