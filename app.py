from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
from features import extract_features
from pymongo import MongoClient
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import warnings

warnings.filterwarnings("ignore")
load_dotenv()

# =========================================================
# CONFIGURATION
# =========================================================
MODEL_PATH = os.getenv("MODEL_PATH", "models/phishing_model_optimized.pkl")
MONGODB_URI = os.getenv("MONGODB_URI")
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")

DISCRIMINATIVE_FEATURES = [
    "having_IP_Address",
    "having_Sub_Domain",
    "SSLfinal_State",
    "Domain_registeration_length",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "age_of_domain",
    "DNSRecord",
]

# =========================================================
# LOAD MODEL
# =========================================================
model = None
FEATURE_NAMES = DISCRIMINATIVE_FEATURES
MODEL_TYPE = "Unknown"
MODEL_ACCURACY = None

def load_model(path):
    artifact = joblib.load(path)
    if isinstance(artifact, dict):
        m = artifact.get("model")
        features = artifact.get("features", DISCRIMINATIVE_FEATURES)
        model_type = artifact.get("model_type", "Unknown")
        accuracy = artifact.get("accuracy", None)
        return m, features, model_type, accuracy
    else:
        return artifact, DISCRIMINATIVE_FEATURES, "Unknown", None

try:
    model, FEATURE_NAMES, MODEL_TYPE, MODEL_ACCURACY = load_model(MODEL_PATH)
    print(f"✅ Loaded model: {MODEL_TYPE} ({len(FEATURE_NAMES)} features)")
except Exception as e:
    raise RuntimeError(f"❌ Could not load model: {e}")

# =========================================================
# INITIALIZE FLASK
# =========================================================
app = Flask(__name__)
CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)

# =========================================================
# MONGODB CONNECTION
# =========================================================
mongodb_connected = False
url_checks = None

if MONGODB_URI:
    try:
        client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
        client.server_info()
        db = client["mydb"]
        url_checks = db["urlchecks"]
        mongodb_connected = True
        print("✅ MongoDB connected successfully")
    except Exception as e:
        print(f"⚠️ MongoDB connection failed: {e}")
else:
    print("⚠️ No MONGODB_URI found — skipping DB connection")

# =========================================================
# ROUTES
# =========================================================
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "Phishing Detection API",
        "status": "online",
        "model": {
            "type": MODEL_TYPE,
            "features": len(FEATURE_NAMES),
            "accuracy": MODEL_ACCURACY,
        },
        "database": "connected" if mongodb_connected else "disconnected",
    })

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "model_loaded": model is not None,
        "model_type": MODEL_TYPE,
        "features_count": len(FEATURE_NAMES),
        "database_connected": mongodb_connected,
        "timestamp": datetime.now().isoformat()
    })

@app.route("/features", methods=["GET"])
def list_features():
    return jsonify({
        "features": FEATURE_NAMES,
        "count": len(FEATURE_NAMES)
    })

@app.route("/stats", methods=["GET"])
def stats():
    if not mongodb_connected:
        return jsonify({"error": "Database not connected"}), 503
    try:
        total = url_checks.count_documents({})
        phishing = url_checks.count_documents({"prediction": "phishing"})
        legitimate = url_checks.count_documents({"prediction": "legitimate"})
        recent = url_checks.count_documents({"checkedAt": {"$gte": datetime.now() - timedelta(days=1)}})
        phishing_rate = round(phishing / total * 100, 2) if total > 0 else 0
        return jsonify({
            "total_checks": total,
            "phishing_detected": phishing,
            "legitimate": legitimate,
            "recent_24h": recent,
            "phishing_rate": phishing_rate
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =========================================================
# MAIN PREDICTION ENDPOINT
# =========================================================
@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json(silent=True) or {}
        url = data.get("url")
        user_id = data.get("user", "anonymous")

        if not url:
            return jsonify({"error": "No URL provided"}), 400

        print(f"\n🔍 Scanning URL: {url}")

        try:
            features_list = extract_features(url)
        except Exception as fe:
            print(f"❌ Feature extraction failed: {fe}")
            return jsonify({"error": f"Feature extraction failed: {fe}"}), 500

        if not isinstance(features_list, (list, tuple)):
            return jsonify({"error": "Invalid feature format"}), 500
        if len(features_list) != len(FEATURE_NAMES):
            return jsonify({
                "error": "Feature length mismatch",
                "expected": len(FEATURE_NAMES),
                "got": len(features_list)
            }), 500

        # Prediction
        features_df = pd.DataFrame([features_list], columns=FEATURE_NAMES)
        prediction = int(model.predict(features_df)[0])
        result = "phishing" if prediction == 1 else "legitimate"

        # Confidence estimation
        confidence = None
        phishing_probability = None
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(features_df)[0]
            confidence = round(float(max(proba)) * 100, 2)
            phishing_probability = round(float(proba[1]) * 100, 2) if len(proba) > 1 else None

        # Suspicious signals
        signals = [FEATURE_NAMES[i] for i, v in enumerate(features_list) if v == 1]

        response = {
            "url": url,
            "prediction": result,
            "confidence": confidence,
            "phishingProbability": phishing_probability,
            "signals": signals,
            "checkedAt": datetime.now().isoformat(),
            "user": str(user_id)
        }

        # Store in MongoDB
        if mongodb_connected:
            try:
                url_checks.insert_one({
                    **response,
                    "features": dict(zip(FEATURE_NAMES, features_list))
                })
            except Exception as db_err:
                print(f"⚠️ DB insert failed: {db_err}")

        print(f"✅ Result: {result.upper()} ({confidence}% confidence)")
        return jsonify(response)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# =========================================================
# START SERVER
# =========================================================
if __name__ == "__main__":
    port = int(os.getenv("PORT", 7000))
    print("\n" + "="*60)
    print("🚀 PHISHGUARD FLASK API STARTED")
    print("="*60)
    print(f"Model Type: {MODEL_TYPE}")
    print(f"Features: {len(FEATURE_NAMES)}")
    if MODEL_ACCURACY:
        print(f"Accuracy: {MODEL_ACCURACY:.2%}")
    print(f"MongoDB: {'Connected' if mongodb_connected else 'Disconnected'}")
    print(f"Listening on: http://127.0.0.1:{port}")
    print("="*60 + "\n")

    app.run(debug=True, host="0.0.0.0", port=port)
