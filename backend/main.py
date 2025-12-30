from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from models import UserLogin, UserRegister, AnalysisRequest, AnalysisResponse, URLAnalysisRequest
import random
import json
import os
import datetime
import joblib

# Load Model
import sys
# Ensure we can import from the subfolder if needed, though usually automatic if __init__.py exists or python 3.3+
# However, importing directly from makineogr.ai_modulu should work if running from backend dir

# Import Phishing Model Logic
try:
    from makineogr.ai_modulu import tahmin_et
    print("DEBUG: Phishing model module loaded successfully.")
except ImportError as e:
    print(f"ERROR: Failed to load Phishing model module: {e}")
    tahmin_et = None

MODEL_PATH = "spam_model_FINAL_calibrated.joblib"
try:
    spam_model = joblib.load(MODEL_PATH)
    print(f"DEBUG: Model loaded from {MODEL_PATH}")
except Exception as e:
    print(f"ERROR: Failed to load model from {MODEL_PATH}: {e}")
    spam_model = None

app = FastAPI(title="PhishGuard Backend")

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Persistence Layer ---
USERS_FILE = "users.json"
SCANS_FILE = "scans.json"

def load_data(filename):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            try:
                return json.load(f)
            except:
                return []
    return []

def save_data(filename, data):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

def load_users():
    return load_data(USERS_FILE)

def save_users(users):
    save_data(USERS_FILE, users)

def load_scans():
    return load_data(SCANS_FILE)

def save_scans(scans):
    save_data(SCANS_FILE, scans)

# Initialize in-memory cache (optional, but good for performance if using global vars)
# We will reload on write to be safe with single-file persistence
users_db = load_users()
scans_db = load_scans()

print("--------------------------------------------------")
print(f"DEBUG: Server Persistence Layer Initialized")
print(f"DEBUG: Loaded Users ({len(users_db)}): {[u['username'] for u in users_db]}")
print(f"DEBUG: Loaded Scans ({len(scans_db)})")
print("--------------------------------------------------")

# --- Endpoints ---

@app.get("/")
def read_root():
    return {"message": "Welcome to PhishGuard API"}

@app.get("/get-stats")
def get_stats():
    current_scans = load_scans()
    today_str = datetime.date.today().isoformat()
    
    email_count = sum(1 for s in current_scans if s.get('type') == 'email' and s.get('timestamp', '').startswith(today_str))
    url_count = sum(1 for s in current_scans if s.get('type') == 'url' and s.get('timestamp', '').startswith(today_str))
    
    # Get last 10 scans, reversed (newest first)
    recent_scans = current_scans[-10:][::-1]
    
    return {
        "summary": {
            "email_count": email_count,
            "url_count": url_count
        },
        "recent_scans": recent_scans
    }

@app.post("/auth/register")
def register(user: UserRegister):
    print(f"Register attempt: {user.username}")
    
    current_users = load_users()
    
    for u in current_users:
        if u['username'] == user.username:
            raise HTTPException(status_code=400, detail="Kullanıcı adı zaten kullanımda")
    
    user_dict = user.model_dump()
    current_users.append(user_dict)
    save_users(current_users)
    
    print(f"User registered: {user.username}")
    return {"message": "User registered successfully"}

@app.post("/auth/login")
def login(user: UserLogin):
    print(f"Login attempt: {user.username}")
    
    current_users = load_users()
    
    for u in current_users:
        if u['username'] == user.username and u['password'] == user.password:
            print("Login successful")
            return {"token": "fake-jwt-token", "username": user.username}
            
    print("Login failed: Invalid credentials")
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.post("/analyze", response_model=AnalysisResponse)
def analyze_text(request: AnalysisRequest):
    if spam_model:
        try:
            # Model prediction
            # Assuming model.predict_proba returns [prob_safe, prob_spam]
            # We want the spam probability
            model_score = 0
            risk_level = "Low"
            
            # Predict
            prediction = spam_model.predict([request.text])[0]
            
            # Try to get probability if available
            if hasattr(spam_model, "predict_proba"):
                proba = spam_model.predict_proba([request.text])[0]
                # Assuming index 1 is spam class
                spam_prob = proba[1]
                model_score = int(spam_prob * 100)
            else:
                # Fallback if only predict matches
                model_score = 100 if prediction == 1 else 0
                
            # Determine Risk Level
            if model_score > 70:
                risk_level = "High"
            elif model_score > 30:
                risk_level = "Medium"
                
            score = model_score
        except Exception as e:
            print(f"Error during model prediction: {e}")
            score = 0
            risk_level = "Error"
    else:
        # Fallback Mock Analysis Logic
        score = random.randint(0, 100)
        
        risk_level = "Low"
        if score > 70:
            risk_level = "High"
        elif score > 30:
            risk_level = "Medium"
    
    # Save Scan
    new_scan = {
        "timestamp": datetime.datetime.now().isoformat(),
        "type": "email",
        "content": request.text[:50] + "..." if len(request.text) > 50 else request.text,
        "score": score,
        "risk_level": risk_level
    }
    current_scans = load_scans()
    current_scans.append(new_scan)
    save_scans(current_scans)
        
    return AnalysisResponse(score=score, risk_level=risk_level)

@app.post("/analyze-url", response_model=AnalysisResponse)
def analyze_url(request: URLAnalysisRequest):
    print(f"Analyzing URL: {request.url}")
    
    score = 0
    risk_level = "Low"
    details = "Analysis completed"

    if tahmin_et:
        try:
            result = tahmin_et(request.url)
            print(f"DEBUG: tahmin_et result for {request.url}: {result}")
            
            # result example: {'durum': 1, 'mesaj': '✅ GÜVENLİ SİTE', 'renk': '#28a745'}
            # result example: {'durum': -1, 'mesaj': '⚠️ YAPAY ZEKA UYARISI: Oltalama Sitesi!', 'renk': '#ff4d4d'}
            
            details = result.get("mesaj", "No details")
            
            if result.get("durum") == 1:
                score = result.get("risk_puani", 10)  # Safe, dynamic score
                risk_level = "Low"
            elif result.get("durum") == -1:
                score = result.get("risk_puani", 95)  # Phishing
                risk_level = "High"
            else:
                score = result.get("risk_puani", 50) # Unknown/Error
                risk_level = "Medium"
                
            # Adjust Risk Level Label based on Score just in case
            if score > 70:
                risk_level = "High"
            elif score > 30:
                risk_level = "Medium"
            else:
                risk_level = "Low"
        except Exception as e:
            print(f"Error in phishing analysis: {e}")
            score = 50
            risk_level = "Error"
    else:
        # Fallback Mock Analysis Logic
        print("WARNING: Using mock logic for URL analysis")
        score = random.randint(0, 100)
        
        risk_level = "Low"
        if score > 70:
            risk_level = "High"
        elif score > 30:
            risk_level = "Medium"
    
    # Save Scan
    new_scan = {
        "timestamp": datetime.datetime.now().isoformat(),
        "type": "url",
        "content": request.url,
        "score": score,
        "risk_level": risk_level,
        "details": details
    }
    current_scans = load_scans()
    current_scans.append(new_scan)
    save_scans(current_scans)
        
    return AnalysisResponse(score=score, risk_level=risk_level)
