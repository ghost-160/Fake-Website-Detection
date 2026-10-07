import sys
import os
import io

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(current_dir, 'backend'))

from app import evaluate_url, verify_ssl, is_trusted_domain, feature_names, model, extract_features
import pandas as pd
from urllib.parse import urlparse

url = 'https://chatgpt.com/'

print('Investigating URL:', url)

# 1. SSL
ssl_res = verify_ssl(url)
print('SSL Result:', ssl_res)

# 2. Trusted domain
parsed = urlparse(url)
hostname = parsed.netloc.split(':')[0]
is_trusted = is_trusted_domain(hostname)
print('Trusted Domain:', is_trusted)

# 3. Features
features_dict = extract_features(url)
print('Extracted Features:', features_dict)

# 4. Model Probabilities
features_df = pd.DataFrame([{name: features_dict.get(name, 0) for name in feature_names}])
proba = model.predict_proba(features_df)[0]
raw_legit, raw_phish = proba[0], proba[1]
print(f'Raw Random Forest Phishing Probability: {raw_phish}')

# 5. Adjusted
if not ssl_res['ssl_valid']:
    adj_phish = min(1.0, raw_phish + 0.15)
else:
    adj_legit = min(1.0, raw_legit + 0.05)
    adj_phish = max(0.0, 1.0 - adj_legit)

print(f'Final Phishing Probability after SSL adj: {adj_phish}')

# 6. Final
eval_res = evaluate_url(url)
print('Final Result:', eval_res)
