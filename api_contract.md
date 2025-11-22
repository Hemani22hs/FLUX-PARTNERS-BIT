# API Contract - /analyze (POST)

URL: POST http://127.0.0.1:5000/analyze
Headers:
  Content-Type: application/json

Request JSON:
{
  "data": "<string> - URL or body text to analyze",
  "type": "<optional string> - 'url' or 'text' (server can auto-detect if missing)"
}

Response JSON:
{
  "score": <int 0-100>,
  "verdict": "<LOW RISK | MODERATE RISK | HIGH RISK>",
  "details": ["<list of human-readable reasons>"],
  "meta": {
     "is_url": <true|false>,
     "checks": {
        "whois": {...},       // optional
        "safe_browsing": {...} // optional
     }
  }
}
