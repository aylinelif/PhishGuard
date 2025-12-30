
import joblib
import os
import numpy as np

model_path = "backend/makineogr/phishing_modeli.pkl"
try:
    model = joblib.load(model_path)
    print(f"Classes: {model.classes_}")
except Exception as e:
    print(e)
