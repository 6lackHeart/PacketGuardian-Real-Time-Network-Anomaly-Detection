import socket
import csv
import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder

# Configuration
MODE = "realtime"  # Switch between "collection" and "realtime"
BATCH_SIZE = 10       # Process data in batches for better performance

# File paths
COLLECTION_FILE = "network_traffic.csv"
ANOMALY_FILE = "anomalies.csv"
MODEL_FILE = "anomaly_model.pkl"
SRC_IP_ENCODER_FILE = "src_ip_encoder.pkl"
DST_IP_ENCODER_FILE = "dst_ip_encoder.pkl"

# Load the ML model and encoders for realtime mode
model = None
src_ip_encoder = None
dst_ip_encoder = None
if MODE == "realtime":
    model = joblib.load(MODEL_FILE)
    src_ip_encoder = joblib.load(SRC_IP_ENCODER_FILE)
    dst_ip_encoder = joblib.load(DST_IP_ENCODER_FILE)

# Save data to CSV for collection mode
def save_to_csv(data, file_name):
    with open(file_name, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(data)

# Process and analyze a batch of data
def process_batch(batch, mode):
    if mode == "collection":
        for features in batch:
            save_to_csv(features, COLLECTION_FILE)
    elif mode == "realtime":
        columns = ["packet_size", "protocol", "src_ip", "dst_ip", "time_interval"]
        try:
            features_df = pd.DataFrame(batch, columns=columns)

            # Encode src_ip and dst_ip using the saved encoders, handling unseen labels
            features_df["src_ip"] = features_df["src_ip"].apply(
                lambda x: src_ip_encoder.transform([x])[0] if x in src_ip_encoder.classes_ else src_ip_encoder.transform(["unknown"])[0]
            )
            features_df["dst_ip"] = features_df["dst_ip"].apply(
                lambda x: dst_ip_encoder.transform([x])[0] if x in dst_ip_encoder.classes_ else dst_ip_encoder.transform(["unknown"])[0]
            )

            # Convert remaining features to numeric
            features_df["packet_size"] = pd.to_numeric(features_df["packet_size"], errors="coerce")
            features_df["protocol"] = pd.to_numeric(features_df["protocol"], errors="coerce")
            features_df["time_interval"] = pd.to_numeric(features_df["time_interval"], errors="coerce")

            # Drop rows with invalid data
            features_df = features_df.dropna()

            # Perform real-time anomaly detection
            predictions = model.predict(features_df)
            for i, prediction in enumerate(predictions):
                if prediction == -1:  # Anomaly detected
                    print(f"Anomaly detected: {batch[i]}")
                    save_to_csv(batch[i], ANOMALY_FILE)
                else:
                    print(f"Normal traffic: {batch[i]}")
        except Exception as e:
            print(f"Error during batch processing: {e}")

# Start server
def start_server(mode):
    print(f"Server running in {mode} mode...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 8080))
    server.listen(5)

    batch = []  # Temporary storage for incoming data

    while True:
        client, address = server.accept()
        try:
            raw_data = client.recv(4096)  # Adjust buffer size for larger batches
            try:
                data = raw_data.decode('utf-8')  # Attempt to decode as UTF-8
            except UnicodeDecodeError:
                print("Warning: Received non-UTF-8 data. Processing as raw bytes.")
                data = raw_data.hex()  # Convert raw data to hex for readability

            if data:
                print(f"Received batch: {data}")
                packets = data.strip().split("\n")  # Split received batch into individual packets

                # Parse and add each packet to the batch
                for packet in packets:
                    features = packet.split(",")  # Example: ["1200", "6", "192.168.0.1", "10.0.0.1", "0.005"]

                    # Validate packet structure
                    if len(features) == 5:  # Ensure the packet has the correct number of features
                        batch.append(features)
                    else:
                        print(f"Invalid packet structure: {packet}")

                    # Process the batch when the size is reached
                    if len(batch) >= BATCH_SIZE:
                        process_batch(batch, mode)
                        batch = []  # Clear the batch after processing

        except Exception as e:
            print(f"Error while processing data from client {address}: {e}")
        finally:
            client.close()

# Start the server with the selected mode
start_server(MODE)
