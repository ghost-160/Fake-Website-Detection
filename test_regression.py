import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
# Use the function from app that handles SSL, threshold, and feature extraction together
from backend.app import evaluate_url

legitimate_urls = [
    "https://store.epicgames.com/en-US/",
    "https://www.paypal.com/signin",
    "https://www.netflix.com/login",
    "https://github.com/login",
    "https://www.microsoft.com/en-us/software-download/windows11"
]

phishing_urls = [
    "http://secure-login-paypal.com",
    "http://update-apple-id.net",
    "http://verify-your-account-banking.com/login.php",
    "https://coupons.wyscale.com/"
]

def test():
    print("=== LEGITIMATE TESTING ===")
    legit_fail = 0
    for url in legitimate_urls:
        res = evaluate_url(url)
        passed = res['safe']
        if not passed: legit_fail += 1
        print(f"URL: {url} -> Predicted: {res['prediction']} (Conf: {res['confidence']}%) - Pass: {passed}")

    print("\n=== PHISHING TESTING ===")
    phish_fail = 0
    for url in phishing_urls:
        res = evaluate_url(url)
        passed = not res['safe']
        if not passed: phish_fail += 1
        print(f"URL: {url} -> Predicted: {res['prediction']} (Conf: {res['confidence']}%) - Pass: {passed}")
        
    print(f"\nFinal: FPR: {legit_fail}/{len(legitimate_urls)}, FNR: {phish_fail}/{len(phishing_urls)}")

if __name__ == '__main__':
    test()
