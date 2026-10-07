from flask import Flask, request, jsonify
import pickle
import pandas as pd
import os
import sys
from flask_cors import CORS
import ssl
import socket
from urllib.parse import urlparse
import traceback

# Add the parent directory to sys.path to import from model.py
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from model import extract_features  # Import the function to extract features

app = Flask(__name__)
CORS(app)
# Define paths with proper directory handling
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
MODEL_PATH = os.path.join(parent_dir, "models", "phishing_model.pkl")
FEATURES_PATH = os.path.join(parent_dir, "models", "feature_names.pkl")

try:
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    
    with open(FEATURES_PATH, "rb") as f:
        feature_names = pickle.load(f)
    
    print(f"Successfully loaded model from {MODEL_PATH}")
except Exception as e:
    print(f"Error loading model: {e}")
    raise
#ssl check
def verify_ssl(url):

    if not url.startswith("https://"):
        return {
            "ssl_valid": False,
            "ssl_error": "Site does not use HTTPS"
        }

    try:

        parsed = urlparse(url)

        hostname = parsed.netloc.split(":")[0]

        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, 443),
            timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as secure_sock:

                cert = secure_sock.getpeercert()

                return {
                    "ssl_valid": True,
                    "ssl_error": None,
                    "issuer": cert.get("issuer"),
                    "subject": cert.get("subject")
                }

    except Exception as e:

        return {
            "ssl_valid": False,
            "ssl_error": str(e)
        }

# Exact-domain and safe subdomain matching
TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "twitter.com", "instagram.com",
    "linkedin.com", "apple.com", "microsoft.com", "wikipedia.org", "amazon.com",
    "github.com", "stackoverflow.com", "reddit.com", "netflix.com", "bing.com",
    "epicgames.com", "paypal.com", "chatgpt.com", "openai.com"
}

def is_trusted_domain(hostname):
    # Ensure exact match or valid subdomain match like foo.google.com
    parts = hostname.split('.')
    if len(parts) >= 2:
        base_domain = f"{parts[-2]}.{parts[-1]}"
        if base_domain in TRUSTED_DOMAINS:
            # check the logic: if hostname is evil-google.com, parts is ['evil-google', 'com'] -> base is evil-google.com (false)
            return True
    return False

def evaluate_url(url):
    ssl_result = verify_ssl(url)
    
    parsed = urlparse(url)
    hostname = parsed.netloc.split(":")[0]
    
    if is_trusted_domain(hostname) and ssl_result["ssl_valid"]:
        return {
            "url": url,
            "prediction": "Safe",
            "safe": True,
            "ssl_valid": True,
            "ssl_error": None,
            "confidence": 100.0,
            "message": "This site is a verified trusted domain."
        }

    # Extract features from URL
    features_dict = extract_features(url)
    
    # Ensure features are in the correct order
    features_df = pd.DataFrame([{name: features_dict.get(name, 0) for name in feature_names}])
    
    # Make prediction
    proba = model.predict_proba(features_df)[0]  # Get probability
    proba_legit = proba[0]
    proba_phish = proba[1]

    # Adjust probabilities based on SSL validity
    if not ssl_result["ssl_valid"]:
        # Instead of +0.5, we give a slight penalty (+0.15)
        # HTTP is becoming less common, but local dev/some sites still use it.
        # Phishing sites often HAVE valid SSL (e.g., Let's Encrypt), so we shouldn't rely on it too heavily.
        proba_phish = min(1.0, proba_phish + 0.15)
        proba_legit = max(0.0, 1.0 - proba_phish)
    else:
        # Valid SSL gives a slight boost to legitimacy
        proba_legit = min(1.0, proba_legit + 0.05)
        proba_phish = max(0.0, 1.0 - proba_legit)

    # Threshold Optimization: Random Forest lexical models often need slightly higher thresholds 
    # to avoid false positives. Using 0.55 for phishing threshold based on validation data analysis.
    PHISHING_THRESHOLD = 0.55
    is_safe = bool(proba_phish < PHISHING_THRESHOLD)
    result = "Safe" if is_safe else "Phishing"
    
    # Send confidence back as percentage
    confidence = float(round(max(proba_legit, proba_phish) * 100, 2))

    security_message = (
        "This site is secure"
        if is_safe
        else "This site is a phishing attempt!"
    )

    return {
        "url": url,
        "prediction": result,
        "safe": is_safe,
        "ssl_valid": ssl_result["ssl_valid"],
        "ssl_error": ssl_result["ssl_error"],
        "confidence": confidence,
        "message": security_message
    }

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "Invalid request"}), 400
        
        result = evaluate_url(data['url'])
        return jsonify(result)
    
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/check', methods=['GET'])
def check():
    try:
        url = request.args.get('url')
        if not url:
            return jsonify({"error": "No URL provided"}), 400

        result = evaluate_url(url)
        return jsonify(result)

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5001)
