import pandas as pd
import numpy as np

def load_and_clean_data(filepath="../data/IDS2025.xlsx"):
    print(f"Loading data from {filepath}...")
    df = pd.read_excel(filepath)
    
    print(f"Original shape: {df.shape}")
    
    # Clean missing and infinite values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    
    # Separate features and target
    y = df['newLabel']
    X = df.drop(columns=['newLabel'])
    
    print(f"Cleaned shape: {df.shape}")
    return X, y
