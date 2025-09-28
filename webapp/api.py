"""
FastAPI endpoint for token spam detection using logistic regression model.

This API provides endpoints to:
1. Preprocess token data using the same steps as training
2. Score tokens for spam probability using the trained logistic regression model
3. Get model information and feature importance

Based on preprocessing from 1.Data_Cleaning.ipynb and model from 2.Training.ipynb
"""
import json
import pandas as pd
import numpy as np
import pickle
import logging
from pathlib import Path
from typing import Dict, List, Optional, Union
from contextlib import asynccontextmanager
from pydantic import BaseModel, Field, validator

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

mode = {'analyses.holder.owner.exceeds_5_percent': np.True_,
 'analyses.holder.creator.exceeds_5_percent': np.True_,
 'analyses.holder.top_10_less_than_70_percent_of_circulating': np.False_,
 'analyses.liquidity.slippage_is_suspicious': np.True_,
 'analyses.liquidity.owner_under_5_percent': np.True_,
 'analyses.liquidity.creator_under_5_percent': np.True_,
 'analyses.liquidity.locked_95_for_15_days': np.False_,
 'analyses.contract.code_analysis.patterns_found.anti_analysis_features.count': np.True_,
 'analyses.contract.is_hardcoded_owner': np.False_,
 'analyses.contract.verified': np.True_}
median = {'analyses.holder.howmany_holders_exceeding_5_percent_circulating': np.float64(1.0),
 'analyses.contract.verified': np.float64(1.0),
 'analyses.contract.is_sellable': np.float64(1.0),
 'analyses.holder.total_holders': np.float64(77.0),
 'analyses.security.howmany_suspicious_addresses': np.float64(0.0),
 'analyses.contract.is_hidden_owner': np.float64(0.0),
 'label': np.float64(0.0)}
mean = {'analyses.liquidity.locked_liquidity_percent': np.float64(1.9084448836350397e+17),
 'analyses.contract.verified': np.float64(1.0),
 'analyses.lifecycle.token_age_seconds': np.float64(94808368.49782595),
 'analyses.lifecycle.inactive_days': np.float64(450.0503324825371),
 'analyses.contract.code_analysis.patterns_found.minting_mechanics.count': np.float64(2.630804953560372),
 'analyses.contract.code_analysis.patterns_found.block_based_restrictions.count': np.float64(1.448275862068966),
 'analyses.contract.code_analysis.patterns_found.stealth_fee_mechanics.count': np.float64(1.211382113821138),
 'analyses.contract.code_analysis.patterns_found.ownership_manipulation.count': np.float64(1.0),
 'analyses.contract.code_analysis.patterns_found.transfer_blocking.count': np.float64(1.0),
 'analyses.liquidity.lock_duration': np.float64(0.0),
 'analyses.liquidity.liquidity_usd': np.float64(200995.10966512858),
 'analyses.contract.code_analysis.patterns_found.emergencyFunctions.count': np.float64(2.0),
 'analyses.liquidity.liquidity_to_market_cap_ratio': np.float64(1.2680773602926108),
 'analyses.liquidity.volume_to_liquidity_ratio': np.float64(1.7620107608736028e+18)}

col_dtypes = {'token_address': 'object',
 'analyses.holder.owner.exceeds_5_percent': 'object',
 'analyses.holder.creator.exceeds_5_percent': 'object',
 'analyses.holder.howmany_holders_exceeding_5_percent_circulating': 'int64',
 'analyses.holder.top_10_less_than_70_percent_of_circulating': 'object',
 'analyses.liquidity.slippage_is_suspicious': 'object',
 'analyses.liquidity.locked_liquidity_percent': 'float64',
 'analyses.liquidity.owner_under_5_percent': 'object',
 'analyses.liquidity.creator_under_5_percent': 'object',
 'analyses.liquidity.locked_95_for_15_days': 'object',
 'analyses.lifecycle.token_age_seconds': 'float64',
 'analyses.lifecycle.inactive_days': 'float64',
 'analyses.contract.verified': 'int64',
 'analyses.contract.code_analysis.patterns_found.minting_mechanics.count': 'float64',
 'analyses.contract.is_sellable': 'int64',
 'analyses.contract.code_analysis.patterns_found.block_based_restrictions.count': 'float64',
 'analyses.contract.code_analysis.patterns_found.stealth_fee_mechanics.count': 'float64',
 'analyses.contract.code_analysis.patterns_found.ownership_manipulation.count': 'float64',
 'analyses.contract.code_analysis.patterns_found.transfer_blocking.count': 'float64',
 'analyses.liquidity.lock_duration': 'float64',
 'analyses.liquidity.liquidity_usd': 'float64',
 'analyses.holder.total_holders': 'int64',
 'analyses.contract.code_analysis.patterns_found.anti_analysis_features.count': 'object',
 'analyses.security.howmany_suspicious_addresses': 'int64',
 'analyses.contract.is_hardcoded_owner': 'object',
 'analyses.contract.is_hidden_owner': 'int64',
 'analyses.contract.code_analysis.patterns_found.emergencyFunctions.count': 'float64',
 'analyses.liquidity.liquidity_to_market_cap_ratio': 'float64',
 'analyses.liquidity.volume_to_liquidity_ratio': 'float64',
 'label': 'int64'}

log_transformed_columns = ["analyses.liquidity.locked_liquidity_percent", "analyses.lifecycle.token_age_seconds", "analyses.lifecycle.inactive_days", "analyses.liquidity.liquidity_usd", "analyses.liquidity.liquidity_to_market_cap_ratio", "analyses.liquidity.volume_to_liquidity_ratio"]

columns_to_keep = [
    "token_address",
    "analyses.liquidity.slippage_is_suspicious",
    "analyses.holder.owner.exceeds_5_percent",
    "analyses.holder.creator.exceeds_5_percent",
    "analyses.holder.howmany_holders_exceeding_5_percent_circulating",
    "analyses.holder.top_10_less_than_70_percent_of_circulating",
    "analyses.liquidity.locked_liquidity_percent",
    "analyses.liquidity.owner_under_5_percent",
    "analyses.liquidity.creator_under_5_percent",
    "analyses.liquidity.locked_95_for_15_days",
    "analyses.lifecycle.token_age_seconds",
    "analyses.lifecycle.inactive_days",
    "analyses.contract.verified",
    "analyses.contract.code_analysis.patterns_found.minting_mechanics.count",
    "analyses.contract.is_sellable",
    "analyses.contract.code_analysis.patterns_found.block_based_restrictions.count",
    "analyses.contract.code_analysis.patterns_found.stealth_fee_mechanics.count",
    "analyses.contract.code_analysis.patterns_found.ownership_manipulation.count",
    "analyses.contract.code_analysis.patterns_found.transfer_blocking.count",
    "analyses.liquidity.locked_liquidity_percent",
    "analyses.liquidity.lock_duration",
    "analyses.liquidity.liquidity_usd",
    "analyses.holder.total_holders",
    "analyses.contract.code_analysis.patterns_found.anti_analysis_features.count",
    "analyses.security.howmany_suspicious_addresses",
    "analyses.contract.is_hardcoded_owner",
    "analyses.contract.is_hidden_owner",
    "analyses.contract.code_analysis.patterns_found.emergencyFunctions.count",
    "analyses.liquidity.liquidity_to_market_cap_ratio",
    "analyses.liquidity.volume_to_liquidity_ratio"
]
    

def load_json_source(source):
    """
    Load a JSON source.

    Parameters:
        source (str or list): Path to a JSON file or already-loaded JSON object (dict/list).

    Returns:
        list: List of JSON records.
    """
    if isinstance(source, str):
        # Load JSON from file
        with open(source, "r") as f:
            data = json.load(f)
    elif isinstance(source, (dict, list)):
        # Already a loaded JSON object
        data = source
    else:
        raise ValueError("Source must be a file path or a loaded JSON object (dict or list).")

    return data if isinstance(data, list) else [data]

def extract_fields(record, keys):
    """
    Extract only dot-notated keys from a dict record.

    Parameters:
        record (dict): JSON record.
        keys (list): List of dot-notated keys to extract.

    Returns:
        dict: Flattened dict containing only selected keys.
    """
    out = {}
    for k in keys:
        parts = k.split(".")
        val = record
        try:
            for p in parts:
                val = val[p]
            out[k] = val
        except (KeyError, TypeError):
            out[k] = None  # fill missing with None
    return out

def load_json_files(sources, columns_to_keep):
    """
    Load JSON file(s) or JSON objects and extract only selected fields.

    Parameters:
        sources (str, list, or list of dicts): Single JSON file path, list of JSON file paths,
                                              or list of loaded JSON objects.
        columns_to_keep (list): List of dot-notated keys to extract.

    Returns:
        pd.DataFrame: Flattened DataFrame containing only selected columns.
    """
    # Ensure we have a list
    if not isinstance(sources, list):
        sources = [sources]

    all_records = []

    for src in sources:
        records = load_json_source(src)
        for r in records:
            all_records.append(extract_fields(r, columns_to_keep))

    df = pd.DataFrame(all_records)
    return df


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler for FastAPI app"""
    # Startup
    load_model()
    yield
    # Shutdown (if needed)
    
# Initialize FastAPI app
app = FastAPI(
    title="Token Spam Detection API",
    description="API for detecting spam tokens using logistic regression",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models for request/response
class TokenFeatures(BaseModel):
    """Input features for a single token"""
    token_address: str = Field(..., description="Token contract address")
    verified: Optional[bool] = None
    is_hidden_owner: Optional[bool] = None
    is_sellable: Optional[bool] = None
    is_proxy: Optional[bool] = None
    has_source_code: Optional[bool] = None
    has_abi: Optional[bool] = None
    total_snippets: Optional[float] = None
    honeypot_mechanics_number: Optional[float] = None
    stealth_fee_mechanics_number: Optional[float] = None
    liquidity_manipulation_number: Optional[float] = None
    router_manipulation_number: Optional[float] = None
    balance_manipulation_number: Optional[float] = None
    emergency_functions_number: Optional[float] = None
    total_holders: Optional[float] = None
    total_supply: Optional[float] = None
    total_circulating_supply: Optional[float] = None
    howmany_holders_exceeding_5_percent_circulating: Optional[float] = None
    total_top_10_balance: Optional[float] = None
    top10_percentage_of_total_supply: Optional[float] = None
    top10_percentage_of_circulating_supply: Optional[float] = None
    top_10_less_than_70_percent_of_total: Optional[bool] = None
    top_10_less_than_70_percent_of_circulating: Optional[bool] = None
    owner_exceeds_5_percent_circulating: Optional[bool] = None
    creator_exceeds_5_percent_circulating: Optional[bool] = None
    owner_is_creator: Optional[bool] = None
    token_age_seconds: Optional[float] = None
    creation_to_first_trade_seconds: Optional[float] = None
    creation_to_first_trade_blocks: Optional[float] = None
    inactive_days: Optional[float] = None
    price_usd: Optional[float] = None
    liquidity_usd: Optional[float] = None
    market_cap_usd: Optional[float] = None
    liquidity_to_market_cap_ratio: Optional[float] = None
    token_volume: Optional[float] = None
    volume_usd: Optional[float] = None
    volume_to_liquidity_ratio: Optional[float] = None
    locked_liquidity_percent: Optional[float] = None
    creator_under_5_percent: Optional[bool] = None
    creator_percent_of_lp: Optional[float] = None
    owner_under_5_percent: Optional[bool] = None
    owner_percent_of_lp: Optional[float] = None
    total_lp_supply: Optional[float] = None
    lp_holders_count: Optional[float] = None
    howmany_suspicious_urls: Optional[float] = None

class TokenScore(BaseModel):
    """Response model for token scoring"""
    token_address: str
    spam_probability: float = Field(..., description="Probability of being spam (0-1, where 1 = spam)")
    non_spam_probability: float = Field(..., description="Probability of being non-spam (0-1)")
    prediction: str = Field(..., description="Predicted class: 'spam' or 'non-spam'")
    confidence: str = Field(..., description="Confidence level: 'high', 'medium', or 'low'")
    decision_score: float = Field(..., description="Raw decision function score")

class BatchTokenScore(BaseModel):
    """Response model for batch scoring"""
    results: List[TokenScore]
    total_tokens: int
    spam_count: int
    non_spam_count: int

class ModelInfo(BaseModel):
    """Model information response"""
    model_type: str
    features_count: int
    feature_names: List[str]
    coefficients: Dict[str, float]
    intercept: float
    log_transformed_features: List[str]

# Global variables for model and preprocessing

def load_model():
    """Load the trained logistic regression model"""
    global model, feature_names, log_transformed_columns
    
    try:
        # Load the model
        model_path = Path("logistic_regression_model.pkl")
        if not model_path.exists():
            raise FileNotFoundError("Model file not found. Please ensure logistic_regression_model.pkl exists.")
        
        with open(model_path, 'rb') as f:
            model = pickle.load(f)
        feature_names = columns_to_keep
        log_transformed_columns = ["analyses.liquidity.locked_liquidity_percent", "analyses.lifecycle.token_age_seconds", "analyses.lifecycle.inactive_days", "analyses.liquidity.liquidity_usd", "analyses.liquidity.liquidity_to_market_cap_ratio", "analyses.liquidity.volume_to_liquidity_ratio"]
        # logger.info(f"Model loaded successfully with {len(feature_names)} features")
        
    except Exception as e:
        logger.error(f"Error loading model: {str(e)}")
        raise



def preprocess_token_data(df: pd.DataFrame) -> np.ndarray:
    """
    Preprocess token data using the same steps as training.
    
    Args:
        df: pandas DataFrame with token data (can include 'token_address' column)
    
    Returns:
        numpy array of preprocessed features ready for model prediction
    
    Based on preprocessing from 1.Data_Cleaning.ipynb:
    1. Handle boolean-like strings
    2. Impute missing values
    3. Apply log transformation to skewed features
    """
    try:
        # Make a copy to avoid modifying the original DataFrame
        # df = df.copy()
        
        # Remove token_address column if present
        if 'token_address' in df.columns:
            df = df.drop(columns=['token_address'])
        
        # Step 1: Normalize boolean-like strings into real booleans
        for col in df.columns:
            df[col] = df[col].astype(col_dtypes[col])
            if df[col].dtype == "object":
                # Convert to string and normalize
                df[col] = df[col].astype(str).str.lower()
                # Map common boolean representations
                df[col] = df[col].map({
                    "true": True, "false": False,
                    "yes": True, "no": False,
                    "1": True, "0": False,
                    "nan": np.nan, "none": np.nan
                })
                df[col] = df[col].astype(bool)
        print("Step 1 complete")
        # Step 2: Impute missing values based on data type
        for col in df.columns:
            if df[col].dtype == "bool":
                # For boolean features, use mode (most common value)
                mode_val = df[col].mode(dropna=True)
                fill_val = mode_val.iloc[0] if not mode_val.empty else False
                df[col] = df[col].fillna(mode[col])
            elif pd.api.types.is_integer_dtype(df[col]):
                # For integer features, use median
                df[col] = df[col].fillna(median[col])
            elif pd.api.types.is_float_dtype(df[col]):
                # For float features, use mean
                df[col] = df[col].fillna(mean[col])
        print("Step 2 complete")

        # Step 3: Apply log transformation to skewed features
        for col in log_transformed_columns:
            if col in df.columns:
                df[col] = np.log1p(df[col])
        print("Step 3 complete")

        # Ensure all features are in the correct order and fill missing columns with 0
        # df = df.reindex(columns=feature_names, fill_value=0)
        #extract mode median and mean of the columns and then fill df with 
        df = df.fillna(0)
        len(df.columns)
        # Convert to numpy array
        return df.values
        
    except Exception as e:
        logger.error(f"Error preprocessing token data: {str(e)}")
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
        df = load_json_files(token_data,columns_to_keep)
        # Preprocess the data
        X = preprocess_token_data(df)
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
        token_address = token_data.token_address if isinstance(token_data, TokenFeatures) else token_data.get('token_address', 'unknown')
        
        return TokenScore(
            token_address=token_address,
            spam_probability=float(spam_prob),
            non_spam_probability=float(non_spam_prob),
            prediction=prediction,
            confidence=confidence,
            decision_score=float(decision_score)
        )
        
    except Exception as e:
        logger.error(f"Error scoring token: {str(e)}")
        raise

# API Endpoints

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Token Spam Detection API",
        "version": "1.0.0",
        "status": "running"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "model_loaded": model is not None
    }

@app.post("/score", response_model=TokenScore)
async def score_single_token(token: dict):
    """
    Score a single token for spam probability.
    
    Returns the probability of the token being spam along with prediction and confidence.
    """
    if model is None:
        raise HTTPException(status_code=500, detail="Model not loaded")
    
    try:
        result = score_token(token)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error processing token: {str(e)}")


@app.get("/model/info", response_model=ModelInfo)
async def get_model_info():
    """
    Get information about the trained model.
    
    Returns model type, features, coefficients, and other metadata.
    """
    if model is None:
        raise HTTPException(status_code=500, detail="Model not loaded")
    
    try:
        # Get coefficients
        coefficients = dict(zip(feature_names, model.coef_[0]))
        
        return ModelInfo(
            model_type="Logistic Regression (L1 Regularized)",
            features_count=len(feature_names),
            feature_names=feature_names,
            coefficients=coefficients,
            intercept=float(model.intercept_[0]),
            log_transformed_features=log_transformed_columns
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting model info: {str(e)}")

@app.get("/model/features/importance")
async def get_feature_importance():
    """
    Get feature importance based on coefficient magnitudes.
    
    Returns features sorted by absolute coefficient value.
    """
    if model is None:
        raise HTTPException(status_code=500, detail="Model not loaded")
    
    try:
        # Calculate feature importance (absolute coefficient values)
        importance = []
        for feature, coef in zip(feature_names, model.coef_[0]):
            importance.append({
                "feature": feature,
                "coefficient": float(coef),
                "importance": float(abs(coef))
            })
        
        # Sort by importance (descending)
        importance.sort(key=lambda x: x["importance"], reverse=True)
        
        return {
            "feature_importance": importance,
            "total_features": len(importance)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting feature importance: {str(e)}")

# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=8000)

