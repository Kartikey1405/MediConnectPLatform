# # # import joblib
# # # import pandas as pd
# # # import numpy as np
# # # import re
# # # from pathlib import Path
# # # from difflib import get_close_matches

# # # class PredictionModel:
# # #     def __init__(self):
# # #         """
# # #         Loads the trained model and artifacts.
# # #         """
# # #         # Path setup: Assumes this file is in 'app/' and models are in 'ml/saved_model/'
# # #         BASE_DIR = Path(__file__).resolve(strict=True).parent.parent
# # #         MODEL_DIR = BASE_DIR / "ml" / "saved_model"
        
# # #         try:
# # #             self.model = joblib.load(MODEL_DIR / "random_forest_model.joblib")
# # #             self.encoder = joblib.load(MODEL_DIR / "label_encoder.joblib")
# # #             self.columns = joblib.load(MODEL_DIR / "symptom_columns.joblib")
            
# # #             # Create a dictionary for fast lookup: "headache" -> "Headache"
# # #             # This maps lowercase column names to the exact column name required by the model
# # #             self.col_dict = {col.lower(): col for col in self.columns}
# # #             self.lower_columns = list(self.col_dict.keys())
            
# # #             print(" Backend model loaded successfully.")
# # #         except FileNotFoundError:
# # #             print(" Error: Model files not found. Please check your paths.")
# # #             self.model = None

# # #     def validate_symptoms(self, raw_input_list):
# # #         """
# # #         Smart Validation:
# # #         1. Joins list into a sentence (handles both comma-lists and full sentences).
# # #         2. Scans for known symptoms (keywords).
# # #         3. Handles 'high fever' matching 'high_fever'.
# # #         4. Fallback to fuzzy matching for typos.
# # #         """
# # #         valid = []
# # #         found_symptoms_set = set() # To prevent duplicates

# # #         # 1. MERGE & CLEAN INPUT
# # #         # Combine list ["I have fever", "headache"] -> "i have fever headache"
# # #         full_text = " ".join(raw_input_list).lower()
# # #         # Remove punctuation (commas, dots, etc.) but keep spaces and underscores
# # #         full_text = re.sub(r'[^\w\s]', ' ', full_text)

# # #         print(f"\n Scanning user text: '{full_text}'")

# # #         # 2. KEYWORD SCANNING (The "Sentence" Fix)
# # #         # We look for OUR database symptoms inside the USER'S text.
# # #         for known_symptom in self.lower_columns:
# # #             # Create a version with spaces instead of underscores (e.g., "high fever")
# # #             symptom_with_space = known_symptom.replace("_", " ")

# # #             # CHECK: Does "high_fever" OR "high fever" exist in the text as a whole word?
# # #             # \b ensures we don't match "ache" inside "headache"
# # #             if (re.search(r'\b' + re.escape(known_symptom) + r'\b', full_text) or 
# # #                 re.search(r'\b' + re.escape(symptom_with_space) + r'\b', full_text)):
                
# # #                 original_name = self.col_dict[known_symptom]
# # #                 # Only add if not already found
# # #                 if original_name not in found_symptoms_set:
# # #                     valid.append(original_name)
# # #                     found_symptoms_set.add(original_name)
# # #                     print(f"   -> Matched keyword: {original_name}")

# # #         # 3. TYPO CHECKING (The Fallback)
# # #         # If the keyword scan missed something (e.g., user typed "headach"), 
# # #         # we split the text into words and check for typos.
# # #         words = full_text.split()
# # #         for word in words:
# # #             # Skip common words like "i", "am", "having" to save time
# # #             if len(word) < 3: continue
            
# # #             matches = get_close_matches(word, self.lower_columns, n=1, cutoff=0.85)
# # #             if matches:
# # #                 matched = matches[0]
# # #                 original_name = self.col_dict[matched]
# # #                 if original_name not in found_symptoms_set:
# # #                     valid.append(original_name)
# # #                     found_symptoms_set.add(original_name)
# # #                     print(f"   -> Fixed typo: '{word}' => '{original_name}'")

# # #         return valid

# # #     def predict(self, symptoms: list):
# # #         if not self.model:
# # #             return {"error": "Model not loaded"}

# # #         # 1️ Validate & Extract
# # #         valid_symptoms = self.validate_symptoms(symptoms)

# # #         # If extraction failed entirely (e.g., input was "1" or "xyz")
# # #         if not valid_symptoms:
# # #             return {
# # #                 "error": "no_symptoms_found",
# # #                 "message": "I couldn't identify any specific symptoms. Please describe them clearly (e.g., 'high fever, headache').",
# # #                 "original_input": symptoms
# # #             }

# # #         #  Predict
# # #         # Create input vector (all zeros except for found symptoms)
# # #         input_vector = [1 if symptom in valid_symptoms else 0 for symptom in self.columns]
# # #         input_df = pd.DataFrame([input_vector], columns=self.columns)

# # #         probabilities = self.model.predict_proba(input_df)[0]
        
# # #         # Get top 3 predictions
# # #         top_3_indices = np.argsort(probabilities)[-3:][::-1]
        
# # #         predictions = []
# # #         for index in top_3_indices:
# # #             disease_name = self.encoder.inverse_transform([index])[0]
# # #             prob = probabilities[index]
# # #             # Only include if probability is > 0
# # #             if prob > 0.0:
# # #                 predictions.append({
# # #                     "disease": disease_name,
# # #                     "confidence": float(prob)
# # #                 })
            
# # #         return predictions

# # # # Create singleton instance
# # # model = PredictionModel()


# # import joblib
# # import pandas as pd
# # import numpy as np
# # import re
# # from pathlib import Path
# # from difflib import get_close_matches

# # class PredictionModel:
# #     def __init__(self):
# #         BASE_DIR = Path(__file__).resolve(strict=True).parent.parent
# #         MODEL_DIR = BASE_DIR / "ml" / "saved_model"
        
# #         try:
# #             self.model = joblib.load(MODEL_DIR / "random_forest_model.joblib")
# #             self.encoder = joblib.load(MODEL_DIR / "label_encoder.joblib")
# #             self.columns = joblib.load(MODEL_DIR / "symptom_columns.joblib")
# #             self.col_dict = {col.lower().replace("_", " "): col for col in self.columns}
# #             self.lower_columns = list(self.col_dict.keys())
# #             print("Backend model and artifacts loaded successfully.")
# #         except FileNotFoundError:
# #             print("Error: Model files not found.")
# #             self.model = None

# #     def validate_symptoms(self, raw_input_list):
# #         valid = []
# #         found_symptoms_set = set()
# #         full_text = " ".join(raw_input_list).lower()
# #         full_text = re.sub(r'[^\w\s]', ' ', full_text)

# #         # 1. Broad Keyword Matching
# #         for known_symptom in self.lower_columns:
# #             # Match if the user text contains the exact symptom (e.g., 'high fever')
# #             if known_symptom in full_text:
# #                 original_name = self.col_dict[known_symptom]
# #                 if original_name not in found_symptoms_set:
# #                     valid.append(original_name)
# #                     found_symptoms_set.add(original_name)

# #         # 2. Fuzzy Fallback for individual words
# #         if not valid:
# #             words = full_text.split()
# #             for word in words:
# #                 if len(word) < 3: continue
# #                 matches = get_close_matches(word, self.lower_columns, n=1, cutoff=0.7)
# #                 if matches:
# #                     original_name = self.col_dict[matches[0]]
# #                     if original_name not in found_symptoms_set:
# #                         valid.append(original_name)
# #                         found_symptoms_set.add(original_name)

# #         return valid

# #     def predict(self, symptoms: list):
# #         if not self.model:
# #             return {"error": "Model not loaded"}

# #         valid_symptoms = self.validate_symptoms(symptoms)

# #         # FIX: Handle single/insufficient symptoms to prevent wild predictions
# #         if len(valid_symptoms) == 0:
# #             return {
# #                 "error": "insufficient_data",
# #                 "message": "I couldn't identify any symptoms. Please try again with details like 'headache' or 'fever'."
# #             }
        
# #         # SPECIAL CASE: Direct mapping for common single symptoms
# #         # Prevents "Fever -> AIDS" or "Headache -> Hemorrhage"
# #         if len(valid_symptoms) == 1:
# #             sym = valid_symptoms[0].lower()
# #             if "headache" in sym:
# #                 return [{"disease": "Migraine / Tension Headache", "confidence": 0.90}]
# #             if "fever" in sym:
# #                 return {
# #                     "error": "more_info_needed",
# #                     "message": "Fever is a broad symptom. Could you please add more details? (e.g., cough, chills, or body ache)"
# #                 }

# #         # 3. Standard ML Prediction for 2+ symptoms
# #         input_vector = [1 if s in valid_symptoms else 0 for s in self.columns]
# #         input_df = pd.DataFrame([input_vector], columns=self.columns)
# #         probabilities = self.model.predict_proba(input_df)[0]
        
# #         top_3_indices = np.argsort(probabilities)[-3:][::-1]
# #         predictions = []
# #         for index in top_3_indices:
# #             prob = probabilities[index]
# #             if prob > 0.05: # Only show meaningful results
# #                 predictions.append({
# #                     "disease": self.encoder.inverse_transform([index])[0],
# #                     "confidence": round(float(prob), 4)
# #                 })
        
# #         return predictions







# import joblib
# import pandas as pd
# import numpy as np
# import re
# from pathlib import Path
# from difflib import get_close_matches

# class PredictionModel:
#     def __init__(self):
#         """
#         Loads the trained model and artifacts.
#         """
#         BASE_DIR = Path(__file__).resolve(strict=True).parent.parent
#         MODEL_DIR = BASE_DIR / "ml" / "saved_model"
        
#         try:
#             self.model = joblib.load(MODEL_DIR / "random_forest_model.joblib")
#             self.encoder = joblib.load(MODEL_DIR / "label_encoder.joblib")
#             self.columns = joblib.load(MODEL_DIR / "symptom_columns.joblib")
            
#             # Map lowercase names to exact column names
#             self.col_dict = {col.lower().replace("_", " "): col for col in self.columns}
#             self.lower_columns = list(self.col_dict.keys())
            
#             print(" Backend model loaded successfully.")
#         except Exception as e:
#             print(f" Error loading model: {e}")
#             self.model = None

#     def validate_symptoms(self, raw_input_list):
#         valid = []
#         found_symptoms_set = set()

#         full_text = " ".join(raw_input_list).lower()
#         full_text = re.sub(r'[^\w\s]', ' ', full_text)

#         # 1. Keyword Scanning
#         for known_symptom in self.lower_columns:
#             if known_symptom in full_text:
#                 original_name = self.col_dict[known_symptom]
#                 if original_name not in found_symptoms_set:
#                     valid.append(original_name)
#                     found_symptoms_set.add(original_name)

#         # 2. Fuzzy Fallback (Typos)
#         if not valid:
#             words = full_text.split()
#             for word in words:
#                 if len(word) < 3: continue
#                 matches = get_close_matches(word, self.lower_columns, n=1, cutoff=0.7)
#                 if matches:
#                     original_name = self.col_dict[matches[0]]
#                     if original_name not in found_symptoms_set:
#                         valid.append(original_name)
#                         found_symptoms_set.add(original_name)

#         return valid

#     def predict(self, symptoms: list):
#         if not self.model:
#             return {"error": "Model not loaded", "message": "ML Model is offline."}

#         valid_symptoms = self.validate_symptoms(symptoms)

#         # GUARDRAIL 1: No symptoms found
#         if not valid_symptoms:
#             return {
#                 "error": "no_symptoms_found",
#                 "message": "I couldn't identify any specific symptoms. Please describe them clearly (e.g., 'high fever, headache')."
#             }

#         # GUARDRAIL 2: Common single-symptom overrides
#         if len(valid_symptoms) == 1:
#             sym = valid_symptoms[0].lower()
#             if "headache" in sym:
#                 return [{"disease": "Migraine / Tension Headache", "confidence": 0.90}]
#             if "fever" in sym:
#                 return {
#                     "error": "more_info_needed",
#                     "message": "Fever is a broad symptom. Could you please add more details like chills, cough, or body ache?"
#                 }

#         # 3. Standard Prediction for 2+ symptoms
#         input_vector = [1 if symptom in valid_symptoms else 0 for symptom in self.columns]
#         input_df = pd.DataFrame([input_vector], columns=self.columns)

#         probabilities = self.model.predict_proba(input_df)[0]
#         top_3_indices = np.argsort(probabilities)[-3:][::-1]
        
#         predictions = []
#         for index in top_3_indices:
#             prob = probabilities[index]
#             if prob > 0.05:
#                 predictions.append({
#                     "disease": self.encoder.inverse_transform([index])[0],
#                     "confidence": float(prob)
#                 })
            
#         return predictions

# # CRITICAL: Create the singleton instance for main.py to import
# model = PredictionModel()


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