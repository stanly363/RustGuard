import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import warnings

# Suppress warnings for a cleaner output
warnings.filterwarnings("ignore", category=UserWarning, module='sklearn')

def train_all_models(input_csv='final.csv'):
    """
    Trains and saves both the Gatekeeper and Specialist models from a single dataset.
    """
    try:
        df = pd.read_csv(input_csv)
        print(f"Loaded '{input_csv}' with {len(df)} total flows.")
    except FileNotFoundError:
        print(f"Error: The file '{input_csv}' was not found. Make sure it's in the same directory.")
        return

    features = [col for col in df.columns if col != 'Label']
    X = df[features]
    y_original = df['Label']

    # --- 2. Train the Gatekeeper Model (Benign vs. Attack) ---
    print("\n--- Training Gatekeeper Model (Benign vs. Attack) ---")

    y_gatekeeper = y_original.apply(lambda x: 'Benign' if x == 'Benign' else 'Attack')
    le_gatekeeper = LabelEncoder()
    y_gatekeeper_encoded = le_gatekeeper.fit_transform(y_gatekeeper)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_gatekeeper_encoded, test_size=0.3, random_state=42, stratify=y_gatekeeper_encoded
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    gatekeeper_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    gatekeeper_model.fit(X_train_scaled, y_train)

    preds = gatekeeper_model.predict(X_test_scaled)
    print(f"Gatekeeper Model Accuracy: {accuracy_score(y_test, preds):.4f}")

    # --- 3. Train and Evaluate the Specialist Model (Specific Attack Types) ---
    print("\n--- Training Specialist Model (Specific Attacks) ---")

    attack_df = df[df['Label'] != 'Benign'].copy()
    X_specialist = attack_df[features]
    y_specialist = attack_df['Label']

    le_specialist = LabelEncoder()
    y_specialist_encoded = le_specialist.fit_transform(y_specialist)

    X_train_spec, X_test_spec, y_train_spec, y_test_spec = train_test_split(
        X_specialist, y_specialist_encoded, test_size=0.3, random_state=42, stratify=y_specialist_encoded
    )

    X_train_spec_scaled = scaler.transform(X_train_spec)
    X_test_spec_scaled = scaler.transform(X_test_spec)

    specialist_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    specialist_model.fit(X_train_spec_scaled, y_train_spec)

    specialist_preds = specialist_model.predict(X_test_spec_scaled)
    print(f"Specialist Model Accuracy: {accuracy_score(y_test_spec, specialist_preds):.4f}")
    
    print("\nSpecialist Model Classification Report:")
    class_names = le_specialist.inverse_transform(range(len(le_specialist.classes_)))
    print(classification_report(y_test_spec, specialist_preds, target_names=class_names))

    # --- 4. Save All Model Artifacts ---
    print("\n--- Saving all model artifacts as .joblib files ---")
    joblib.dump(gatekeeper_model, 'gatekeeper_model.joblib')
    joblib.dump(specialist_model, 'specialist_model.joblib')
    joblib.dump(scaler, 'scaler.joblib')
    joblib.dump(le_gatekeeper, 'main_label_encoder.joblib')
    joblib.dump(le_specialist, 'attack_label_encoder.joblib')
    joblib.dump(features, 'selected_features.joblib')
    
    print("\nAll files have been created successfully.")

if __name__ == "__main__":
    train_all_models()