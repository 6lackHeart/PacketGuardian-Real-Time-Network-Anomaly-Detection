import pandas as pd
import random

# Load data
INPUT_FILE = "network_traffic.csv"
OUTPUT_FILE = "cleaned_network_traffic.csv"

# Define column headers
HEADERS = ["packet_size", "protocol", "src_ip", "dst_ip", "time_interval"]
data = pd.read_csv(INPUT_FILE, header=None, names=HEADERS)

# Debugging: Initial rows
print(f"Initial number of rows: {len(data)}")

# Remove duplicates
data = data.drop_duplicates()
print(f"Rows after removing duplicates: {len(data)}")

# Ensure numeric types and handle invalid entries
data["packet_size"] = pd.to_numeric(data["packet_size"], errors="coerce")
data["protocol"] = pd.to_numeric(data["protocol"], errors="coerce")
data["time_interval"] = pd.to_numeric(data["time_interval"], errors="coerce")

# Drop rows with NaN values
data = data.dropna()
print(f"Rows after handling NaN values: {len(data)}")

# Handle `time_interval == 0` by replacing it with the median
if (data["time_interval"] == 0).any():
    median_time_interval = data.loc[data["time_interval"] > 0, "time_interval"].median()
    data["time_interval"] = data["time_interval"].replace(0, median_time_interval)

# Validate data ranges
valid_data = (
    (data["packet_size"] > 0) &  # Positive packet sizes
    (data["protocol"] >= 0) & (data["protocol"] <= 255) &  # Valid protocol range
    (data["time_interval"] > 0)  # Positive time intervals
)
data = data[valid_data]
print(f"Rows after validating ranges: {len(data)}")

# Normalize features
from sklearn.preprocessing import MinMaxScaler

scaler = MinMaxScaler()
data[["packet_size", "time_interval"]] = scaler.fit_transform(data[["packet_size", "time_interval"]])

# Calculate the number of anomalies (5% of the dataset size)
num_anomalies = int(len(data) * 0.05)

# Simulate anomalies
anomalies = []
for _ in range(num_anomalies):
    anomalies.append({
        "packet_size": random.choice([99999, 0]),  # Extreme packet sizes
        "protocol": random.choice([999, -1]),     # Invalid protocol numbers
        "src_ip": random.choice(["192.168.999.999", "256.256.256.256"]),  # Invalid IPs
        "dst_ip": random.choice(["10.0.0.1", "8.8.8.8"]),
        "time_interval": random.uniform(0.001, 100.0)  # Extreme intervals
    })

# Convert anomalies to DataFrame and label data
anomalies_df = pd.DataFrame(anomalies)
data["label"] = 0  # Normal traffic
anomalies_df["label"] = 1  # Anomalies

# Combine datasets
combined_data = pd.concat([data, anomalies_df])

# Ensure anomalies are evenly distributed by shuffling the data
combined_data = combined_data.sample(frac=1, random_state=42).reset_index(drop=True)

# Save cleaned dataset
combined_data.to_csv(OUTPUT_FILE, index=False)
print(f"Cleaned dataset saved to {OUTPUT_FILE}")
print(f"Final dataset contains {len(combined_data)} rows with {num_anomalies} anomalies.")

