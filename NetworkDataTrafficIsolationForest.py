import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import joblib

# File paths
DATA_FILE = "cleaned_network_traffic.csv"
MODEL_FILE = "anomaly_model.pkl"
SRC_IP_ENCODER_FILE = "src_ip_encoder.pkl"
DST_IP_ENCODER_FILE = "dst_ip_encoder.pkl"

# Load data
data = pd.read_csv(DATA_FILE)

# Separate features and labels
X = data.drop("label", axis=1)  # Features
y = data["label"]  # Labels

# Encode categorical columns (e.g., src_ip and dst_ip)
src_ip_encoder = LabelEncoder()
dst_ip_encoder = LabelEncoder()

# Fit encoders to the dataset and add "unknown" as a valid class
src_ip_encoder.fit(X["src_ip"])
dst_ip_encoder.fit(X["dst_ip"])

src_ip_encoder.classes_ = np.append(src_ip_encoder.classes_, "unknown")
dst_ip_encoder.classes_ = np.append(dst_ip_encoder.classes_, "unknown")

# Transform IP columns, mapping unseen values to "unknown"
X["src_ip"] = X["src_ip"].apply(lambda x: x if x in src_ip_encoder.classes_ else "unknown")
X["src_ip"] = src_ip_encoder.transform(X["src_ip"])

X["dst_ip"] = X["dst_ip"].apply(lambda x: x if x in dst_ip_encoder.classes_ else "unknown")
X["dst_ip"] = dst_ip_encoder.transform(X["dst_ip"])

# Save the encoders for real-time use
joblib.dump(src_ip_encoder, SRC_IP_ENCODER_FILE)
joblib.dump(dst_ip_encoder, DST_IP_ENCODER_FILE)
print(f"Encoders saved to {SRC_IP_ENCODER_FILE} and {DST_IP_ENCODER_FILE}")

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Train an Isolation Forest model
isolation_forest = IsolationForest(n_estimators=100, contamination=0.04, random_state=42)
isolation_forest.fit(X_train)

# Save the model for real-time use
joblib.dump(isolation_forest, MODEL_FILE)
print(f"Model saved to {MODEL_FILE}")

# Predict anomalies on the test set
y_pred = isolation_forest.predict(X_test)

# Map Isolation Forest outputs to labels (1 for anomalies, 0 for normal)
y_pred = [1 if pred == -1 else 0 for pred in y_pred]

# Evaluate the model
print("Classification Report:")
print(classification_report(y_test, y_pred))

print(f"ROC-AUC Score: {roc_auc_score(y_test, y_pred):.2f}")