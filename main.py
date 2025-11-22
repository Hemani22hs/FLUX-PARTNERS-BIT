from fastapi import FastAPI
from pydantic import BaseModel
from phish_services import analyze_url, analyze_email



app = FastAPI(
    title="PhishGuard API",
    description="AI-powered phishing detection backend",
    version="1.0.0"
)

# Request Models
class URLRequest(BaseModel):
    url: str

class EmailRequest(BaseModel):
    subject: str
    sender: str
    body: str

# Root route
@app.get("/")
def root():
    return {"message": "PhishGuard API is running!"}

# URL phishing detection route
@app.post("/analyze/url")
def analyze_url_endpoint(data: URLRequest):
    result = analyze_url(data.url)
    return {"url": data.url, "result": result}

# Email phishing detection route
@app.post("/analyze/email")
def analyze_email_endpoint(data: EmailRequest):
    result = analyze_email(data.subject, data.sender, data.body)
    return {
        "subject": data.subject,
        "sender": data.sender,
        "result": result
    }
