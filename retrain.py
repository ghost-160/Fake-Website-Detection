import sys
import os
import pandas as pd
import numpy as np
import pickle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, roc_auc_score

import urllib.parse
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from model import extract_features

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    df = pd.read_csv(os.path.join(script_dir, 'dataset_phishing.csv'))
    
    # These are features the original script just sets to 0 because we don't have code to extract them,
    # PLUS features we drop because doing HTTP requests in the backend adds immense latency and fails on WAFs.
    fallback_features = [
        'punycode', 'port', 'tld_in_path', 'tld_in_subdomain', 
        'abnormal_subdomain', 'random_domain', 
        'path_extension', 'nb_redirection', 'nb_external_redirection',
        'char_repeat', 'shortest_words_raw', 
        'shortest_word_path', 'longest_words_raw', 'longest_word_path',
        'avg_words_raw', 'avg_word_host', 'avg_word_path', 'phish_hints', 'domain_in_brand',
        'brand_in_subdomain', 'brand_in_path', 'suspecious_tld', 'statistical_report',
        'nb_hyperlinks', 'ratio_intHyperlinks', 'ratio_extHyperlinks', 'ratio_nullHyperlinks',
        'nb_extCSS', 'ratio_intRedirection', 'ratio_extRedirection', 'ratio_intErrors',
        'ratio_extErrors', 'login_form', 'external_favicon', 'links_in_tags', 'submit_email',
        'ratio_intMedia', 'ratio_extMedia', 'sfh', 'iframe', 'popup_window', 'safe_anchor',
        'onmouseover', 'right_clic', 'empty_title', 'domain_in_title', 'domain_with_copyright',
        'whois_registered_domain', 'domain_registration_length', 'domain_age', 'web_traffic',
        'dns_record', 'google_index', 'page_rank'
    ]
    
    feature_columns = [col for col in df.columns if col not in ['url', 'status'] and col not in fallback_features]
    
    X = df[feature_columns]
    y = np.where(df['status'] == 'phishing', 1, 0)
    
    print(f"Original Num Features: {len(df.columns) - 2}")
    print(f"New Num Features: {len(feature_columns)}")
    print(f"Features strictly used: {feature_columns}")
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=15, min_samples_leaf=3)
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    
    accuracy = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_proba)
    print(f"New Model Accuracy: {accuracy * 100:.2f}%")
    print(f"New Model ROC-AUC: {auc:.4f}")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    
    # Save the new model and features
    models_dir = os.path.join(script_dir, 'models')
    with open(os.path.join(models_dir, 'phishing_model.pkl'), 'wb') as f:
        pickle.dump(model, f)
        
    with open(os.path.join(models_dir, 'feature_names.pkl'), 'wb') as f:
        pickle.dump(list(X.columns), f)
        
    print("New model saved.")

if __name__ == '__main__':
    main()
