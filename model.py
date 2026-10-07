import re
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import pickle
import os
import urllib.parse

def extract_features(url):
    features = {}
    
    parsed_url = urllib.parse.urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path
    
    # Basic URL features
    features['length_url'] = len(url)
    features['length_hostname'] = len(domain)
    
    # Check if URL contains IP address
    features['ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0
        
    features['nb_dots'] = url.count('.')
    features['nb_hyphens'] = url.count('-')
    features['nb_at'] = url.count('@')
    features['nb_qm'] = url.count('?')
    features['nb_and'] = url.count('&')
    features['nb_or'] = url.count('|')
    features['nb_eq'] = url.count('=')
    features['nb_underscore'] = url.count('_')
    features['nb_tilde'] = url.count('~')
    features['nb_percent'] = url.count('%')
    features['nb_slash'] = url.count('/')
    features['nb_star'] = url.count('*')
    features['nb_colon'] = url.count(':')
    features['nb_comma'] = url.count(',')
    features['nb_semicolumn'] = url.count(';')
    features['nb_dollar'] = url.count('$')
    features['nb_space'] = url.count(' ')
    features['nb_www'] = 1 if 'www' in domain else 0
    features['nb_com'] = 1 if '.com' in domain else 0
    features['nb_dslash'] = url.count('//')
    features['http_in_path'] = 1 if 'http' in path else 0
    features['https_token'] = 1 if 'https' in domain else 0
    
    # Ratio features
    features['ratio_digits_url'] = len(re.findall(r'\d', url)) / len(url) if len(url) > 0 else 0
    features['ratio_digits_host'] = len(re.findall(r'\d', domain)) / len(domain) if len(domain) > 0 else 0
    
    # More advanced domain features
    features['nb_subdomains'] = domain.count('.')
    features['prefix_suffix'] = 1 if '-' in domain else 0
    
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl', 't.co', 'is.gd', 'cli.gs', 'yfrog', 'migre.me', 'ff.im']
    features['shortening_service'] = 1 if any(short in domain for short in shorteners) else 0
    
    features['length_words_raw'] = len(re.findall(r'\w+', url))
    words_host = re.findall(r'\w+', domain)
    features['shortest_word_host'] = len(min(words_host, key=len)) if words_host else 0
    features['longest_word_host'] = len(max(words_host, key=len)) if words_host else 0
    
    return features


# Function to predict if a new URL is phishing or legitimate
def predict_url(url):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    try:
        # Extract features from the URL
        features_dict = extract_features(url)
        
        # Get the feature names in the correct order
        with open(os.path.join(script_dir, 'models', 'feature_names.pkl'), 'rb') as f:
            feature_names = pickle.load(f)
        
        # Create a DataFrame with the features in the correct order
        features_df = pd.DataFrame([{name: features_dict.get(name, 0) for name in feature_names}])
        
        # Load the model
        with open(os.path.join(script_dir, 'models', 'phishing_model.pkl'), 'rb') as f:
            loaded_model = pickle.load(f)
        
        # Make prediction
        prediction = loaded_model.predict(features_df)
        
        # Output the prediction result
        print(f"URL: {url} -> Prediction: {'Phishing' if prediction[0] == 1 else 'Legitimate'}")
        
        # Get prediction probability
        proba = loaded_model.predict_proba(features_df)[0]
        print(f"Confidence: Legitimate {proba[0]:.2f}, Phishing {proba[1]:.2f}")
        
        return prediction[0]
    except Exception as e:
        print(f"Error during prediction: {e}")
        return None

if __name__ == "__main__":
    pass
