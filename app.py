# app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from logic import phish_check
import urllib.parse
import re
import random # Used for simulating external API call results for the hackathon

# --- FLASK APP SETUP ---
app = Flask(__name__)
# Enable CORS to allow your frontend (running on a different port/address) to talk to the backend
CORS(app) 

# --- CORE DETECTION ENGINE (LOGIC LAYER) ---

def run_whois_check(domain: str):
    """
    Simulated WHOIS/Domain Age Check. 
    In a real app, you'd use a library (e.g., 'python-whois') and penalize new domains.
    """
    # Assign a high penalty randomly 20% of the time to simulate a suspicious new domain
    if random.random() < 0.2:
        return 20, "Domain Age Suspicious (New Registration or Privacy Guarded)"
    return 0, None

def run_safe_browsing_check(url: str):
    """
    Simulated Google Safe Browsing API or similar external check.
    In a real app, you'd use the 'requests' library to call a known blacklist API.
    """
    # Assign a high penalty if a known phishing string is present or randomly 10% of the time
    if 'known-bad-site.com' in url or random.random() < 0.1:
        return 50, "External API Flags as Known Malware/Phishing"
    return 0, None

def phish_check(data: str):
    """
    Main function for the Core Detection Engine. 
    Performs checks and calculates a risk score based on heuristics and external checks.
    """
    risk_score = 0
    details = []
    is_url = data.startswith('http')

    # --- 1. AUTHORITATIVE CHECKS (Highest Priority) ---
    if is_url:
        ext_score, ext_detail = run_safe_browsing_check(data)
        risk_score += ext_score
        if ext_detail:
            details.append(f"🔴 Authority Check: {ext_detail}")

    # --- 2. URL HEURISTIC CHECKS ---
    if is_url:
        try:
            # Parse the URL to access its components
            url_parts = urllib.parse.urlparse(data)
            netloc = url_parts.netloc # The domain and port part (e.g., www.example.com:8080)
            
            # Sub-Check A: Non-Standard Port
            if ':' in netloc:
                port = netloc.split(':')[-1]
                if port not in ['80', '443']: 
                    risk_score += 15
                    details.append(f"🚩 Non-Standard Port Used ({port})")
            
            # Sub-Check B: Excessive Subdomains / Subdomain Spoofing
            # More than 3 dots can indicate an attempt to hide the real domain (e.g., login.bank.secure.info.co)
            if netloc.count('.') > 3:
                 risk_score += 10
                 details.append("🚩 Excessive Subdomains (Domain Complexity)")

            # Sub-Check C: Punycode/IDN Spoofing
            # Punycode starts with 'xn--' and is often used to hide deceptive characters (e.g., Cyrillic 'a')
            if 'xn--' in netloc:
                risk_score += 35
                details.append("🛑 Punycode (IDN) Detected - High Risk Spoofing")
            
            # Sub-Check D: Typosquatting Simulation
            typo_patterns = {
                'google': ['g0ogle', 'googgle', 'gooogle'], 
                'paypal': ['paypa1', 'paypaal']
            }
            domain_part = netloc.split(':')[0].lower() # Get domain without port
            for standard_name, typos in typo_patterns.items():
                for typo in typos:
                    # Check if a known typo is in the domain, but the actual standard name is not 
                    if typo in domain_part and standard_name not in domain_part:
                        risk_score += 25
                        details.append(f"⚠️ Typosquatting: Domain resembles '{standard_name}'")
                        break
                        
            # Check E: WHOIS/Age Check (simulated)
            whois_score, whois_detail = run_whois_check(domain_part)
            risk_score += whois_score
            if whois_detail:
                details.append(f"⚠️ Domain Heuristic: {whois_detail}")

        except Exception:
            # Fallback for URLs that are poorly formed or unparseable
            risk_score += 10
            details.append("Invalid or Malformed URL Structure.")
            
    # --- 3. KEYWORD/CONTENT HEURISTIC CHECKS (For URLs or Email Text) ---
    
    # Check for high-pressure or urgent keywords common in social engineering
    keywords = ['urgent action required', 'account locked', 'verify now', 'suspicious activity detected', 'reset password immediately']
    
    for keyword in keywords:
        if keyword in data.lower():
            risk_score += 8
            details.append(f"🔎 Keyword: Found high-pressure phrase: '{keyword.split(' ')[0]}'...")

    # --- FINAL VERDICT CALCULATION ---
    
    # Cap the score at 100 for display simplicity
    risk_score = min(risk_score, 100) 
    
    if risk_score >= 60:
        verdict = "**HIGH RISK (LIKELY PHISHING)**"
    elif risk_score >= 25:
        verdict = "MODERATE RISK (PROCEED WITH EXTREME CAUTION)"
    else:
        verdict = "LOW RISK (APPEARS SAFE)"
        
    return risk_score, verdict, details

# --- FLASK ROUTE DEFINITION (API Endpoint) ---

@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Receives input data from the frontend and returns the analysis results.
    """
    # Basic input validation
    if not request.json or 'data' not in request.json:
        return jsonify({"error": "Missing 'data' field in request"}), 400

    input_data = request.json.get('data', '')

    # Run the core analysis logic
    score, verdict, details = phish_check(input_data)
    
    # Return results as JSON
    return jsonify({
        'score': score,
        'verdict': verdict,
        'details': details
    })

if __name__ == '__main__':
    # Start the server on the address expected by the frontend (127.0.0.1:5000)
    app.run(debug=True, port=5000, host='127.0.0.1')