from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from sse_starlette.sse import EventSourceResponse
from pydantic import BaseModel, Field
import asyncio
import pandas as pd
from typing import Optional
import json
import sys
import os
from contextlib import asynccontextmanager
import pickle
from pathlib import Path

# Import your API functions
from .api import preprocess_token_data, columns_to_keep, extract_fields

# Add parent directory to sys.path if needed
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from main import token_analysis

# -------------------------------
# Globals
# -------------------------------
BASE_DIR = Path(__file__).resolve().parent
model = None
feature_names = []
log_transformed_columns = []

# -------------------------------
# Pydantic model
# -------------------------------
class TokenScore(BaseModel):
    token_address: str
    spam_probability: float
    non_spam_probability: float
    prediction: str
    confidence: str
    decision_score: float

# -------------------------------
# FastAPI app and lifespan
# -------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    load_model()
    yield

app = FastAPI(lifespan=lifespan)

# -------------------------------
# Load model
# -------------------------------
def load_model():
    """Load the trained logistic regression model"""
    global model, feature_names, log_transformed_columns
    
    try:
        model_path = BASE_DIR / "models" / "logistic_regression_model.pkl"
        if not model_path.exists():
            raise FileNotFoundError(
                f"Model file not found at {model_path}. Please ensure it exists."
            )
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        feature_names = columns_to_keep
        log_transformed_columns = [
            "analyses.liquidity.locked_liquidity_percent",
            "analyses.lifecycle.token_age_seconds",
            "analyses.lifecycle.inactive_days",
            "analyses.liquidity.liquidity_usd",
            "analyses.liquidity.liquidity_to_market_cap_ratio",
            "analyses.liquidity.volume_to_liquidity_ratio"
        ]
        print(f"Model loaded successfully with {len(feature_names)} features.")
    except Exception as e:
        print(f"Error loading model: {str(e)}")
        raise

# -------------------------------
# Token scoring
# -------------------------------
def score_token(token_data: dict) -> TokenScore:
    try:
        r = extract_fields(token_data, columns_to_keep)
        df = pd.DataFrame([r])
        X = preprocess_token_data(df)
        probabilities = model.predict_proba(X)[0]
        spam_prob, non_spam_prob = probabilities[0], probabilities[1]
        decision_score = model.decision_function(X)[0]
        prediction = "spam" if spam_prob > 0.5 else "non-spam"
        max_prob = max(spam_prob, non_spam_prob)
        if max_prob >= 0.9:
            confidence = "high"
        elif max_prob >= 0.7:
            confidence = "medium"
        else:
            confidence = "low"

        return TokenScore(
            token_address=token_data.get('token_address', 'unknown'),
            spam_probability=float(spam_prob),
            non_spam_probability=float(non_spam_prob),
            prediction=prediction,
            confidence=confidence,
            decision_score=float(decision_score)
        )
    except Exception as e:
        print(f"Error scoring token: {str(e)}")
        raise

# -------------------------------
# Mount static files and templates
# -------------------------------
# Ensure directories exist
if not (BASE_DIR / "static").exists():
    (BASE_DIR / "static").mkdir()
if not (BASE_DIR / "templates").exists():
    (BASE_DIR / "templates").mkdir()

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# -------------------------------
# Progress tracking
# -------------------------------
progress_data = {"value": 0, "total": 32}

async def progress_generator():
    while True:
        yield f"data: {json.dumps(progress_data)}\n\n"
        await asyncio.sleep(0.1)

# -------------------------------
# Routes
# -------------------------------
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/progress")
async def progress_stream():
    return EventSourceResponse(progress_generator())

@app.post("/api/analyze")
async def analyze(request: Request):
    try:
        body = await request.json()
        token = body.get("token")
        chain = body.get("chain")
        if not token or not chain:
            raise HTTPException(status_code=400, detail="Missing token or chain")

        def update_progress(current, total):
            progress_data["value"] = current
            progress_data["total"] = total

        raw_results = token_analysis(token, chain, progress_callback=update_progress)
        if model is None:
            raise HTTPException(status_code=500, detail="Model not loaded")
        result = score_token(raw_results)
        return {"status": "success", "data": {"raw_results": raw_results, "score": result}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/results", response_class=HTMLResponse)
async def results(request: Request, token: Optional[str] = None, chain: Optional[str] = None):
    return templates.TemplateResponse("results.html", {
        "request": request,
        "token": token,
        "chain": chain
    })
