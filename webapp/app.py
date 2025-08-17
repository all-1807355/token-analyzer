from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from sse_starlette.sse import EventSourceResponse
import asyncio
from typing import Optional
import json
import sys
import os

# Add the parent directory to sys.path to import main
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from main import token_analysis

app = FastAPI()

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

        results = token_analysis(token, chain, progress_callback=update_progress)
        return {"status": "success", "data": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/results", response_class=HTMLResponse)
async def results(request: Request, token: Optional[str] = None, chain: Optional[str] = None):
    return templates.TemplateResponse("results.html", {
        "request": request,
        "token": token,
        "chain": chain
    })