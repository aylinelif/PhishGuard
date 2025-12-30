
import joblib
import os
import sys
import numpy as np

# Adjust path to find the module if needed, or just load directly
model_path = "backend/makineogr/phishing_modeli.pkl"

try:
    if os.path.exists(model_path):
        model = joblib.load(model_path)
        print(f"Model loaded: {type(model)}")
        if hasattr(model, "predict_proba"):
            print("predict_proba is available")
            # Create a dummy feature vector of correct shape (1, 13 based on feature_extraction code I saw earlier? 
            # Looking at ai_modulu.py:
            # features list has: 
            # 1. IP (1/-1)
            # 2. Length (1/0/-1)
            # 3. Shortening (1/-1)
            # 4. @ (1/-1)
            # 5. Double slash (1/-1)
            # 6. Dash (1/-1)
            # 7. SSL (1/-1)
            # 8. Domain Age (1) - Constant?
            # 9. HTTPS Token (1/-1)
            # Total 9 features appended.
            
            dummy_features = np.ones((1, 9)) 
            try:
                prob = model.predict_proba(dummy_features)
                print(f"Dummy prediction proba: {prob}")
            except Exception as e:
                print(f"predict_proba failed with dummy data: {e}")
        else:
            print("predict_proba is NOT available")
    else:
        print("Model file not found")
except Exception as e:
    print(f"Error loading model: {e}")
