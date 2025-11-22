import re
from urllib.parse import urlparse
from datetime import datetime

# ---------------------------------------
# 1. Extract URLs from text/email
# ---------------------------------------
def extract_urls(text: str):
    url_pattern = r"(https?://[^\s]+)"
    return re.findall(url_pattern, text)


# ---------------------------------------
# 2. URL Risk Analyzer (MOVED UP)
# ---------------------------------------
def analyze_url(url: str) -> dict:
    parsed = urlparse(url)
    domain = parsed.netloc

    # suspicious URL patterns
    red_flags = [
        "secure-", "login-", "verify-", "banking", "update", "freegift",
        ".xyz", ".click", "account-reset", "paypal-login"
    ]

    risk_flag = any(flag in url.lower() for flag in red_flags)

    return {
        "type": "url",
        "url": url,
        "domain": domain,
        "risk": "High" if risk_flag else "Low",
        "reason": "Suspicious pattern found" if risk_flag else "No issues",
        "timestamp": str(datetime.now())
    }


# ---------------------------------------
# 3. Email Phishing Analyzer
# ---------------------------------------
def analyze_email(subject: str, sender: str, body: str) -> dict:
    phishing_keywords = [
        "urgent", "verify now", "password reset", "bank account",
        "update information", "lottery", "compromised", "suspended",
        "click below", "confirm immediately"
    ]

    # Check if email contains phishing keywords
    keyword_flag = any(
        kw in subject.lower() or kw in body.lower()
        for kw in phishing_keywords
    )

    # suspicious sender domains
    suspicious_domains = ["xyz", "click", "secure-login", "bank-security"]
    sender_domain = sender.split("@")[-1]

    domain_flag = any(sd in sender_domain.lower() for sd in suspicious_domains)

    # extract URLs inside email
    urls_found = extract_urls(body)

    # analyze URLs
    url_results = [analyze_url(u) for u in urls_found]

    # risk decision
    suspicious = keyword_flag or domain_flag or any(r["risk"] == "High" for r in url_results)

    return {
        "type": "email",
        "subject": subject,
        "sender": sender,
        "urls_found": urls_found,
        "url_checks": url_results,
        "risk": "High" if suspicious else "Low",
        "timestamp": str(datetime.now())
    }


# ---------------------------------------
# 4. File Attachment Analyzer
# ---------------------------------------
def analyze_attachment(filename: str, content: bytes) -> dict:
    dangerous_extensions = ["exe", "js", "scr", "bat", "cmd", "vbs", "zip"]
    ext = filename.split(".")[-1].lower()

    risk_flag = ext in dangerous_extensions

    return {
        "type": "attachment",
        "filename": filename,
        "size_bytes": len(content),
        "risk": "High" if risk_flag else "Low",
        "reason": "Suspicious file extension" if risk_flag else "No issues",
        "timestamp": str(datetime.now())
    }


# ---------------------------------------
# 5. Domain Reputation Checker
# ---------------------------------------
def domain_reputation(domain: str) -> dict:
    # bad domain list
    bad_domains = ["malicious.com", "fakebank.com", "phishingsite.org"]

    risk_flag = domain.lower() in bad_domains or domain.endswith(".xyz")

    return {
        "type": "domain",
        "domain": domain,
        "risk": "High" if risk_flag else "Low",
        "reason": "Blacklisted domain" if risk_flag else "No issues",
        "timestamp": str(datetime.now())
    }

