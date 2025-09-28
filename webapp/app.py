from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.background import BackgroundTasks
from sse_starlette.sse import EventSourceResponse
from pydantic import BaseModel, Field, validator
import asyncio
import pandas as pd
from typing import Optional
import json
import sys
import os
from contextlib import asynccontextmanager
import pickle
import logging
import numpy as np
from pathlib import Path
from api import preprocess_token_data
from api import columns_to_keep,extract_fields
from api import log_transformed_columns

# Add the parent directory to sys.path to import main
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from main import token_analysis
from main import evaluate_token_safety

class TokenScore(BaseModel):
    """Response model for token scoring"""
    token_address: str
    spam_probability: float = Field(..., description="Probability of being spam (0-1, where 1 = spam)")
    non_spam_probability: float = Field(..., description="Probability of being non-spam (0-1)")
    prediction: str = Field(..., description="Predicted class: 'spam' or 'non-spam'")
    confidence: str = Field(..., description="Confidence level: 'high', 'medium', or 'low'")
    decision_score: float = Field(..., description="Raw decision function score")


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_model()
    yield

app = FastAPI(lifespan=lifespan)

def load_model():
    """Load the trained logistic regression model"""
    global model, feature_names, log_transformed_columns
    
    try:
        # Load the model
        model_path = Path("models/logistic_regression_model.pkl")
        if not model_path.exists():
            raise FileNotFoundError("Model file not found. Please ensure logistic_regression_model.pkl exists.")
        
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        feature_names = columns_to_keep
        log_transformed_columns = ["analyses.liquidity.locked_liquidity_percent", "analyses.lifecycle.token_age_seconds", "analyses.lifecycle.inactive_days", "analyses.liquidity.liquidity_usd", "analyses.liquidity.liquidity_to_market_cap_ratio", "analyses.liquidity.volume_to_liquidity_ratio"]
        # logger.info(f"Model loaded successfully with {len(feature_names)} features")
        
    except Exception as e:
        print(f"Error loading model: {str(e)}")
        raise

def score_token(token_data: dict) -> TokenScore:
    """
    Score a single token for spam probability.
    
    Returns:
        TokenScore object with prediction and confidence
    """
    print(type(token_data))
    try:
        # Convert to DataFrame for preprocessing
        # df = load_json_files(token_data,columns_to_keep)
        r = extract_fields(token_data, columns_to_keep)
        df = pd.DataFrame([r])
        # Preprocess the data
        print(df)
        X = preprocess_token_data(df)
        print(X)
        # Get prediction probabilities
        probabilities = model.predict_proba(X)[0]
        spam_prob = probabilities[0]  # Class 0 = spam
        non_spam_prob = probabilities[1]  # Class 1 = non-spam
        
        # Get decision function score
        decision_score = model.decision_function(X)[0]
        
        # Make prediction
        prediction = "spam" if spam_prob > 0.5 else "non-spam"
        
        # Determine confidence level
        max_prob = max(spam_prob, non_spam_prob)
        if max_prob >= 0.9:
            confidence = "high"
        elif max_prob >= 0.7:
            confidence = "medium"
        else:
            confidence = "low"
        
        # Get token address
        token_address = token_data.get('token_address', 'unknown')#token_data.token_address if isinstance(token_data, TokenFeatures) else token_data.get('token_address', 'unknown')
        
        token_score = TokenScore(
            token_address=token_address,
            spam_probability=float(spam_prob),
            non_spam_probability=float(non_spam_prob),
            prediction=prediction,
            confidence=confidence,
            decision_score=float(decision_score)
        )
        print(token_score)
        return token_score
    except Exception as e:
        print(f"Error scoring token: {str(e)}")
        raise

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Setup templates
templates = Jinja2Templates(directory="templates")

# Global progress tracking
progress_data = {"value": 0, "total": 32}

async def progress_generator():
    while True:
        yield f"data: {json.dumps(progress_data)}\n\n"
        await asyncio.sleep(0.1)

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
        #safety_score = evaluate_token_safety(results)
        #results["safety_score"] = safety_score
        
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