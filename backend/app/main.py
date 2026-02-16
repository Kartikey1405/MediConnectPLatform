


from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any, Optional
from app.model import model

app = FastAPI(title="MediBot API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Matches 'SymptomRequest' in Spring Boot
class SymptomsInput(BaseModel):
    symptoms: List[str]

# Matches 'FastApiResponse' in Spring Boot
class PredictionResponse(BaseModel):
    predictions: List[Dict[str, Any]]
    error: Optional[str] = None

@app.post("/predict", response_model=PredictionResponse)
def predict_disease(symptom_data: SymptomsInput):
    result = model.predict(symptom_data.symptoms)

    if isinstance(result, dict) and "error" in result:
        return {"predictions": [], "error": result["message"]}

    # Ensure float precision matches Java's double
    return {
        "predictions": result,
        "error": None
    }
