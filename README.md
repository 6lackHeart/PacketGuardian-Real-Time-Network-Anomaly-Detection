# PacketGuardian-Real-Time-Network-Anomaly-Detection
ML model used for real time network anomaly detection. 


Real-Time Network Anomaly Detection
This repository contains a comprehensive project designed to monitor and analyze network traffic in real-time for anomalies using machine learning. The system integrates components for data collection, cleaning, anomaly simulation, training, and live traffic analysis.

Purpose
This project was created as a learning exercise to improve my C++ programming skills and to showcase my data analytics and machine learning engineering capabilities. It is designed as a portfolio project for my resume to demonstrate end-to-end system design and implementation skills.

Features
Real-Time Monitoring: A C++ packet sniffer captures network traffic and sends it to a Python socket server for real-time analysis.
Machine Learning Integration: An Isolation Forest model trained on processed and labeled data detects anomalous traffic patterns.
Data Cleaning: A Python script preprocesses and cleans raw network traffic data to ensure quality for model training.
Anomaly Simulation: Synthetic anomalies are injected into the dataset for robust model training and validation.
Customizable Analysis: Adjustable parameters for contamination level, modes (collection vs. real-time), and data processing pipelines.
Extensive Documentation: Well-documented scripts for training, cleaning, anomaly simulation, and real-time monitoring.

Project Structure
main.cpp: C++ packet sniffer that captures live network traffic.
PacketDataServer.py: Python socket server for real-time traffic analysis and anomaly detection.
NetworkDataTrafficCleaner.py: Data cleaning script for preprocessing raw network traffic data.
NetworkDataTrafficIsolationForest.py: Script to train the Isolation Forest model.
AnomalySimulator.py: Script to generate synthetic anomalies for training and testing.
models/: Directory to store trained .pkl files for the Isolation Forest model and related encoders.
data/: Placeholder for raw and processed CSV files (network_traffic.csv, anomalies.csv).

Setup and Usage

Prerequisites
Python 3.8+ with required libraries (scikit-learn, pandas, etc.).
C++ compiler to build the sniffer.
Windows/Linux environment for running the components.

Steps to Run
Packet Sniffer: Compile and run main.cpp to capture live network traffic.
Socket Server: Start PacketDataServer.py in either "collection" or "real-time" mode.
Data Cleaning: Use NetworkDataTrafficCleaner.py to preprocess collected data.
Model Training: Train a new model using NetworkDataTrafficIsolationForest.py with cleaned data.
Anomaly Simulation: Use AnomalySimulator.py to generate and inject synthetic anomalies for testing and evaluation.
Real-Time Analysis: Start the packet sniffer and socket server in real-time mode to detect anomalies live.

Example Outputs
The system categorizes each packet as either:

"Normal Traffic"
"Anomaly Detected"

Logs from the socket server provide a real-time feed of traffic analysis.

Applications
Network intrusion detection.
Security monitoring for anomalous activity.
Data preprocessing for larger-scale traffic analysis.
Contributing
Contributions are welcome! Feel free to open issues or submit pull requests.

License
This project is licensed under the MIT License.
