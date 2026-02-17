


# from fastapi import FastAPI
# from pydantic import BaseModel
# from fastapi.middleware.cors import CORSMiddleware
# from typing import List, Dict, Any, Optional
# from app.model import model

# app = FastAPI(title="MediBot API", version="1.0.0")

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# # Matches 'SymptomRequest' in Spring Boot
# class SymptomsInput(BaseModel):
#     symptoms: List[str]

# # Matches 'FastApiResponse' in Spring Boot
# class PredictionResponse(BaseModel):
#     predictions: List[Dict[str, Any]]
#     error: Optional[str] = None

# @app.post("/predict", response_model=PredictionResponse)
# def predict_disease(symptom_data: SymptomsInput):
#     result = model.predict(symptom_data.symptoms)

#     if isinstance(result, dict) and "error" in result:
#         return {"predictions": [], "error": result["message"]}

#     # Ensure float precision matches Java's double
#     return {
#         "predictions": result,
#         "error": None
#     






from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any, Optional
from app.model import model
from contextlib import asynccontextmanager
from apscheduler.schedulers.background import BackgroundScheduler
import httpx
import logging

# Configure logging to see the pings in Render logs
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Replace with your actual FastAPI Render URL
SELF_PING_URL = "https://medibot-ai-service.onrender.com/"

def ping_self():
    """Function to ping the root endpoint to keep the service awake."""
    try:
        with httpx.Client() as client:
            response = client.get(SELF_PING_URL)
            logger.info(f"Keep-Alive: Pinged {SELF_PING_URL} - Status: {response.status_code}")
    except Exception as e:
        logger.error(f"Keep-Alive: Ping failed: {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # STARTUP: Setup and start the scheduler
    scheduler = BackgroundScheduler()
    # Runs every 10 minutes (600 seconds)
    scheduler.add_job(ping_self, 'interval', minutes=10)
    scheduler.start()
    logger.info("Keep-Alive Scheduler Started.")
    
    yield
    
    # SHUTDOWN: Clean up
    scheduler.shutdown()
    logger.info("Keep-Alive Scheduler Stopped.")

app = FastAPI(title="MediBot API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SymptomsInput(BaseModel):
    symptoms: List[str]

class PredictionResponse(BaseModel):
    predictions: List[Dict[str, Any]]
    error: Optional[str] = None

@app.get("/")
def health_check():
    return {"status": "ok", "message": "MediBot API is running."}

@app.post("/predict", response_model=PredictionResponse)
def predict_disease(symptom_data: SymptomsInput):
    result = model.predict(symptom_data.symptoms)

    if isinstance(result, dict) and "error" in result:
        return {"predictions": [], "error": result["message"]}

    return {
        "predictions": result,
        "error": None
    }
