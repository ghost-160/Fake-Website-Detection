import os
import sys
import pandas as pd
from urllib.parse import urlparse

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(current_dir, 'backend'))

from app import evaluate_url

legit_urls = [
    'https://chatgpt.com/',
    'https://store.epicgames.com/',
    'https://www.paypal.com/',
    'https://www.netflix.com/',
    'https://github.com/',
    'https://www.microsoft.com/'
]

phishing_urls = [
    'http://secure-login-paypal.com',
    'http://update-apple-id.net',
    'http://verify-your-account-banking.com/login.php',
    'https://coupons.wyscale.com/'
]

lookalike_urls = [
    'https://chatgpt-login-example.com',
    'https://fake-chatgpt.com',
    'https://chatgpt.com.attacker.com',
    'https://openai-login-example.com'
]

print("=== RUNNING REGRESSION TESTS ===")

all_passed = True

print("\n--- Legitimate URLs (Should be Safe) ---")
for url in legit_urls:
    res = evaluate_url(url)
    status = "PASS" if res['prediction'] == "Safe" else "FAIL"
    if status == "FAIL": all_passed = False
    print(f"{status}: {url} -> {res['prediction']} (Conf: {res['confidence']})")

print("\n--- Phishing URLs (Should be Phishing) ---")
for url in phishing_urls:
    res = evaluate_url(url)
    status = "PASS" if res['prediction'] == "Phishing" else "FAIL"
    if status == "FAIL": all_passed = False
    print(f"{status}: {url} -> {res['prediction']} (Conf: {res['confidence']})")

print("\n--- Lookalike URLs (Should be Phishing) ---")
for url in lookalike_urls:
    res = evaluate_url(url)
    status = "PASS" if res['prediction'] == "Phishing" else "FAIL"
    if status == "FAIL": all_passed = False
    print(f"{status}: {url} -> {res['prediction']} (Conf: {res['confidence']})")

if all_passed:
    print("\nALL TESTS PASSED: TRUE")
else:
    print("\nALL TESTS PASSED: FALSE")
