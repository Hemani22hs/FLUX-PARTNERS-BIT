import urllib.parse
import random
import re
import base64
from math import log2

# ------------------------------
# Check if URL contains raw IPv4
# ------------------------------
def is_ip_in_url(data: str) -> bool:
    try:
        url_parts = urllib.parse.urlparse(data)
        host = url_parts.netloc.split(':')[0]
        ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"
        return bool(re.match(ip_pattern, host))
    except:
        return False

# ------------------------------
# Extract emails from text
# ------------------------------
def extract_emails(text: str):
    email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    return re.findall(email_pattern, text)

# ------------------------------
# Shannon entropy calculation
# ------------------------------
def calculate_entropy(text: str) -> float:
    if not text:
        return 0
    probability = [text.count(c)/len(text) for c in set(text)]
    return -sum(p * log2(p) for p in probability)

# ------------------------------
# Main analysis function
# ------------------------------
def analyze_input(data: str):
    risk_score = 0
    details = []

    # URLs
    urls = re.findall(r"https?://[^\s]+", data)
    # Emails
    emails = extract_emails(data)

    details.append(f"🔍 URLs Found: {urls if urls else 'None'}")
    details.append(f"📧 Emails Found: {emails if emails else 'None'}")

    # IP check
    if any(is_ip_in_url(url) for url in urls):
        risk_score += 25
        details.append("⚠️ URL contains raw IP address.")

    # Punycode check
    if any("xn--" in url for url in urls):
        risk_score += 25
        details.append("⚠️ Punycode domain detected.")

    # Base64 in URL
    if any(re.search(r"[A-Za-z0-9+/]{12,}={0,2}", url) for url in urls):
        risk_score += 15
        details.append("⚠️ URL contains Base64 tokens.")

    # Suspicious TLDs
    bad_tlds = [".zip", ".xyz", ".top", ".tk", ".click"]
    if any(url.endswith(tld) for tld in bad_tlds for url in urls):
        risk_score += 20
        details.append("⚠️ Suspicious TLD detected.")

    # Typosquatting patterns
    typo_patterns = {
        "g00gle": "google",
        "faceb00k": "facebook",
        "paypa1": "paypal",
        "app1e": "apple",
        "m1crosoft": "microsoft"
    }

    for url in urls:
        for typo, legit in typo_patterns.items():
            if typo in url.lower():
                risk_score += 30
                details.append(f"⚠️ Typosquatting detected: '{typo}' instead of '{legit}'.")

    # Email domain check
    safe_domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]
    for email in emails:
        domain = email.split("@")[-1]
        if domain not in safe_domains:
            risk_score += 20
            details.append(f"⚠️ Suspicious email domain: {domain}")

    # Keywords
    phishing_keywords = [
        "verify your account", "reset your password", "urgent update",
        "your account will be closed", "confirm login", "bank alert",
        "click this link"
    ]
    for kw in phishing_keywords:
        if kw in data.lower():
            risk_score += 10
            details.append(f"⚠️ High-risk keyword found: '{kw}'")

    # Entropy
    entropy = calculate_entropy(data)
    if entropy > 4.0:
        risk_score += 15
        details.append(f"⚠️ High entropy detected ({entropy:.2f}).")

    # Final verdict
    if risk_score >= 70:
        verdict = "🛑 HIGH RISK — Likely PHISHING"
    elif risk_score >= 40:
        verdict = "🟧 MEDIUM RISK — Suspicious"
    else:
        verdict = "🟩 LOW RISK — Likely Safe"

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "details": details
    }
