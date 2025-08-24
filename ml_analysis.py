import joblib
import numpy as np
import warnings
import os

# Suppress scikit-learn warnings to avoid cluttering the output
warnings.filterwarnings("ignore", category=UserWarning, module='sklearn')

class FlowDiagnoser:

    def __init__(self, artifact_path='.'):
        """
        Initializes the diagnoser by loading all required .joblib files.
        Raises FileNotFoundError if any file is missing.
        """
        required_files = [
            'selected_features.joblib',
            'scaler.joblib',
            'gatekeeper_model.joblib', 
            'specialist_model.joblib', 
            'main_label_encoder.joblib', 
            'attack_label_encoder.joblib'
        ]
        for f in required_files:
            if not os.path.exists(os.path.join(artifact_path, f)):
                raise FileNotFoundError(f"Missing required model file: {f}")

        self.selected_features = joblib.load(os.path.join(artifact_path, "selected_features.joblib"))
        self.scaler = joblib.load(os.path.join(artifact_path, "scaler.joblib"))
        self.gatekeeper_model = joblib.load(os.path.join(artifact_path, "gatekeeper_model.joblib"))
        self.specialist_model = joblib.load(os.path.join(artifact_path, "specialist_model.joblib"))
        self.main_label_encoder = joblib.load(os.path.join(artifact_path, "main_label_encoder.joblib"))
        self.attack_label_encoder = joblib.load(os.path.join(artifact_path, "attack_label_encoder.joblib"))
        print("Python: All model artifacts loaded successfully.")

# This prevents repeated disk I/O for every prediction.
try:
    DIAGNOSER = FlowDiagnoser()
except FileNotFoundError as e:
    DIAGNOSER = None
    print(f"Python: {e}")

def diagnose_flow(flow_features: dict) -> str:

    if DIAGNOSER is None:
        return "Error: Python models are not loaded. Check file paths."

    try:

        ordered_features = [flow_features[name] for name in DIAGNOSER.selected_features]
        

        feature_array = np.array(ordered_features).reshape(1, -1)
        scaled_features = DIAGNOSER.scaler.transform(feature_array)

        gatekeeper_prediction = DIAGNOSER.gatekeeper_model.predict(scaled_features)[0]
        
        if gatekeeper_prediction == 0:
            return "Benign"
        

        specialist_prediction_numeric = DIAGNOSER.specialist_model.predict(scaled_features)[0]
        

        final_attack_label = DIAGNOSER.attack_label_encoder.inverse_transform([specialist_prediction_numeric])[0]
        final_diagnosis = DIAGNOSER.main_label_encoder.inverse_transform([final_attack_label])[0]
        
        return final_diagnosis

    except KeyError as e:
        return f"Error: Input data is missing a required feature - {e}"
    except Exception as e:
        return f"An unexpected error occurred in Python: {e}"

if __name__ == '__main__':

    if DIAGNOSER:

        required_feature_names = DIAGNOSER.selected_features
        sample_flow = {feature: np.random.uniform(1, 1000) for feature in required_feature_names}

        if 'Dst Port' in sample_flow:
            sample_flow['Dst Port'] = 4444
        elif 'Destination Port' in sample_flow: 
            sample_flow['Destination Port'] = 4444
        
        print("\n--- Running diagnosis on a sample flow ---")
        diagnosis = diagnose_flow(sample_flow)
        print(f"Final Diagnosis: {diagnosis}")
    else:
        print("\n--- Could not run test: models failed to load ---")