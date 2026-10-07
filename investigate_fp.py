import sys
import os
import pandas as pd
import pickle

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from model import extract_features

FEATURES_PATH = "models/feature_names.pkl"
MODEL_PATH = "models/phishing_model.pkl"

with open(FEATURES_PATH, "rb") as f:
    feature_names = pickle.load(f)

with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

fp_urls = [
    "https://store.epicgames.com/en-US/",
    "https://www.paypal.com/signin?returnUri=https%3A%2F%2Fwww.paypal.com%2Fmyaccount%2Fsummary",
    "https://www.netflix.com/login"
]

with open('results.txt', 'w', encoding='utf-8') as out:
    out.write("=== False Positive Investigation ===\n")
    
    for url in fp_urls:
        out.write(f"\nAnalyzing: {url}\n")
        features = extract_features(url)
        features_df = pd.DataFrame([{name: features.get(name, 0) for name in feature_names}])
        
        proba = model.predict_proba(features_df)[0]
        proba_phish = proba[1]
        out.write(f"Base Phishing Probability: {proba_phish:.4f}\n")
        
        importances = list(zip(feature_names, model.feature_importances_))
        importances.sort(key=lambda x: x[1], reverse=True)
        
        out.write("Top 10 Feature Contributions (Importance):\n")
        for fname, importance in importances[:10]:
            val = features.get(fname, 0)
            out.write(f"  {fname}: Value={val}, Importance={importance:.4f}\n")
        
        out.write("Non-zero Features in URL:\n")
        non_zero = [(n, v) for n, v in features.items() if v > 0]
        for n, v in non_zero:
            out.write(f"  {n}: {v}\n")
