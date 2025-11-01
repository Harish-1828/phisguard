import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from joblib import dump

os.makedirs("models", exist_ok=True)

data = pd.read_csv("datasets/Phishing_Websites_Data.csv")

discriminative_features = [
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

X = data[discriminative_features].apply(pd.to_numeric, errors="coerce").fillna(0)
y = pd.to_numeric(data["Result"], errors="coerce")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

model = RandomForestClassifier(
    n_estimators=500,
    max_depth=15,
    min_samples_split=10,
    min_samples_leaf=4,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(X_train, y_train)
accuracy = model.score(X_test, y_test)

model_artifact = {
    "model": model,
    "features": discriminative_features,
    "model_type": "RandomForest",
    "accuracy": accuracy,
}

dump(model_artifact, "models/phishing_model_optimized.pkl")

print(f"Model trained: {accuracy:.4f} accuracy")