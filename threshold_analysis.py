import os
import sys
import pickle
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from model import extract_features

def evaluate_thresholds():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(script_dir, 'models', 'phishing_model.pkl')
    features_path = os.path.join(script_dir, 'models', 'feature_names.pkl')
    data_path = os.path.join(script_dir, 'dataset_phishing.csv')
    out_path = os.path.join(script_dir, 'threshold_results.txt')

    with open(model_path, 'rb') as f:
        model = pickle.load(f)
    with open(features_path, 'rb') as f:
        feature_names = pickle.load(f)

    df = pd.read_csv(data_path)
    X = df[feature_names]
    y = np.where(df['status'] == 'phishing', 1, 0)
    
    _, X_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    y_proba = model.predict_proba(X_test)[:, 1]

    thresholds = [0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95]
    
    with open(out_path, 'w', encoding='utf-8') as out:
        out.write("=== THRESHOLD ANALYSIS ===\n\n")
        out.write(f"| Threshold | Accuracy | Precision | Recall | F1 | FPR | FNR | TP | TN | FP | FN |\n")
        out.write(f"|-----------|----------|-----------|--------|----|-----|-----|----|----|----|----|\n")
        
        best_t = 0.50
        best_f1 = 0
        
        for t in thresholds:
            y_pred = (y_proba >= t).astype(int)
            
            acc = accuracy_score(y_test, y_pred)
            prec = precision_score(y_test, y_pred)
            rec = recall_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred)
            
            cm = confusion_matrix(y_test, y_pred)
            tn, fp, fn, tp = cm.ravel()
            
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
            
            out.write(f"| {t:.2f} | {acc:.4f} | {prec:.4f} | {rec:.4f} | {f1:.4f} | {fpr:.4f} | {fnr:.4f} | {tp} | {tn} | {fp} | {fn} |\n")
            
            if f1 > best_f1:
                best_f1 = f1
                best_t = t

        out.write("\n=== INVESTIGATING: https://coupons.wyscale.com/ ===\n")
        url = "https://coupons.wyscale.com/"
        features = extract_features(url)
        features_df = pd.DataFrame([{name: features.get(name, 0) for name in feature_names}])
        
        proba = model.predict_proba(features_df)[0]
        proba_phish = proba[1]
        out.write(f"Base Phishing Probability: {proba_phish:.4f}\n")
        
        importances = list(zip(feature_names, model.feature_importances_))
        importances.sort(key=lambda x: x[1], reverse=True)
        
        out.write("\nTop 10 Feature Contributions (Importance):\n")
        for fname, importance in importances[:10]:
            val = features.get(fname, 0)
            out.write(f"  {fname}: Value={val}, Importance={importance:.4f}\n")
            
        out.write("\nAll non-zero feature values:\n")
        non_zero = [(n, v) for n, v in features.items() if n in feature_names and v > 0]
        for n, v in non_zero:
            out.write(f"  {n}: {v}\n")

if __name__ == '__main__':
    evaluate_thresholds()
