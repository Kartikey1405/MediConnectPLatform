import joblib
import pandas as pd
import numpy as np
import re
from pathlib import Path
from difflib import get_close_matches

class PredictionModel:
    def __init__(self):
        BASE_DIR = Path(__file__).resolve(strict=True).parent.parent
        MODEL_DIR = BASE_DIR / "ml" / "saved_model"
        
        try:
            self.model = joblib.load(MODEL_DIR / "random_forest_model.joblib")
            self.encoder = joblib.load(MODEL_DIR / "label_encoder.joblib")
            self.columns = joblib.load(MODEL_DIR / "symptom_columns.joblib")
            
            # Map names for fuzzy matching
            self.col_dict = {col.lower().replace("_", " "): col for col in self.columns}
            self.lower_columns = list(self.col_dict.keys())
            
            print(" Backend model loaded successfully.")
        except Exception as e:
            print(f" Error loading model: {e}")
            self.model = None

    def validate_symptoms(self, raw_input_list):
        valid = []
        found_symptoms_set = set()
        full_text = " ".join(raw_input_list).lower()
        full_text = re.sub(r'[^\w\s]', ' ', full_text)

        for known_symptom in self.lower_columns:
            if known_symptom in full_text:
                original_name = self.col_dict[known_symptom]
                if original_name not in found_symptoms_set:
                    valid.append(original_name)
                    found_symptoms_set.add(original_name)

        if not valid:
            words = full_text.split()
            for word in words:
                if len(word) < 3: continue
                matches = get_close_matches(word, self.lower_columns, n=1, cutoff=0.7)
                if matches:
                    original_name = self.col_dict[matches[0]]
                    if original_name not in found_symptoms_set:
                        valid.append(original_name)
                        found_symptoms_set.add(original_name)
        return valid

    def predict(self, symptoms: list):
        if not self.model:
            return {"error": "Model offline"}

        valid_symptoms = self.validate_symptoms(symptoms)

        if not valid_symptoms:
            return {"error": "no_symptoms_found", "message": "Please describe symptoms clearly."}

        # GUARDRAILS: Specific logic for lone symptoms
        if len(valid_symptoms) == 1:
            sym = valid_symptoms[0].lower()
            if "headache" in sym:
                return [{"disease": "Migraine / Tension Headache", "confidence": 0.90}]
            if "fever" in sym:
                return {"error": "more_info_needed", "message": "Fever is broad. Please add details like chills or cough."}

        # PREDICTION: Return all top 3 matches with any confidence
        input_vector = [1 if symptom in valid_symptoms else 0 for symptom in self.columns]
        input_df = pd.DataFrame([input_vector], columns=self.columns)

        probabilities = self.model.predict_proba(input_df)[0]
        top_3_indices = np.argsort(probabilities)[-3:][::-1]
        
        predictions = []
        for index in top_3_indices:
            prob = probabilities[index]
            if prob > 0.0: # Capture everything relevant
                predictions.append({
                    "disease": self.encoder.inverse_transform([index])[0],
                    "confidence": float(prob)
                })
            
        return predictions

model = PredictionModel()
