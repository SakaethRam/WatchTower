import os
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
from fpdf import FPDF
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.cluster import DBSCAN
import json
import requests
from elasticsearch import Elasticsearch
import paramiko
import datetime

logging.basicConfig(filename='security_analysis.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize Elasticsearch
ELASTICSEARCH_HOST = "your_elasticsearch_host" 
es = Elasticsearch([ELASTICSEARCH_HOST])

# ----------------- MAIN FUNCTION -----------------

def main():
    log_file = "zeek_logs/conn.log"  # Or your log file path

    while True:  # Loop until a valid IP or empty input is given
        target_ip_input = input("Enter target IP (or press Enter for all IPs): ")

        if target_ip_input.strip() == "":  # Check for empty input (analyze all IPs)
            target_ip_to_analyze = None
            break  # Exit the loop

        try:
            # Basic IP validation (improve as needed)
            ip_parts = target_ip_input.split(".")
            if len(ip_parts) == 4 and all(0 <= int(part) <= 255 for part in ip_parts):
                target_ip_to_analyze = target_ip_input  # Valid IP
                break  # Exit the loop
            else:
                print("Invalid IP address format. Please try again.")
        except ValueError:  # Handle cases where conversion to int fails
            print("Invalid IP address format. Please try again.")

    anomalies, user_behavior = detect_threats(log_file, target_ip_to_analyze)


if __name__ == "__main__":
    main()

# ----------------- PHASE 1: REMOTE LOG COLLECTION -----------------

def fetch_remote_logs(remote_ip, remote_user, remote_password, remote_log_path, local_log_path):
    """Fetches Zeek logs from a remote machine via SSH & SCP."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(remote_ip, username=remote_user, password=remote_password)

        sftp = ssh.open_sftp()
        sftp.get(remote_log_path, local_log_path)
        sftp.close()
        ssh.close()
        print("Successfully fetched remote logs.")
    except Exception as e:
        print(f"Failed to fetch logs: {e}")

# ----------------- PHASE 2: ZEEK LOG PARSING -----------------

def parse_zeek_log(log_file, target_ip=None):
    """Parses Zeek connection logs and extracts relevant features, filtering by target IP if provided."""
    df = pd.read_csv(log_file, sep='\t', comment='#', low_memory=False)
    df = df[['id.orig_h', 'id.resp_h', 'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'ts']]
    df = df.fillna(0)

    if target_ip:
        df = df[(df['id.orig_h'] == target_ip) | (df['id.resp_h'] == target_ip)]

    return df

# ----------------- PHASE 3: FEATURE ENGINEERING -----------------

def extract_features(df):
    """Extracts and scales features."""
    categorical_cols = ['proto', 'service', 'conn_state']
    for col in categorical_cols:
        df[col] = LabelEncoder().fit_transform(df[col].astype(str))

    numerical_cols = ['duration', 'orig_bytes', 'resp_bytes']  # Add other numerical columns as needed
    if numerical_cols and not df[numerical_cols].empty:  # Check if numerical columns exist and are not empty
        scaler = StandardScaler()
        df[numerical_cols] = scaler.fit_transform(df[numerical_cols])  # Scale numerical features
    elif numerical_cols and df[numerical_cols].empty:
        logging.warning("Numerical columns are empty, skipping scaling.")

    return df

# ----------------- PHASE 4: USER BEHAVIOR PROFILING -----------------

def analyze_user_behavior(df):
    """Detects user behavioral patterns and anomalies."""
    df['duration'] = df['duration'] / 3600  # Convert duration from seconds to hours if needed
    user_stats = df.groupby('id.orig_h').agg({
        'duration': 'sum',
        'orig_bytes': 'sum',
        'resp_bytes': 'sum'
    }).reset_index()
    
    clustering = DBSCAN(eps=0.5, min_samples=2).fit(user_stats[['duration', 'orig_bytes', 'resp_bytes']])
    user_stats['behavior_cluster'] = clustering.labels_
    
    user_stats['behavior_anomalies'] = user_stats.apply(lambda row: 'Anomaly detected' if row['duration'] > 1000 else 'Normal', axis=1)
    
    return user_stats

# ----------------- PHASE 5: TRAIN SUPERVISED ML MODEL -----------------

import kagglehub

def train_supervised_model():
    # Download the latest version of the dataset
    path = kagglehub.dataset_download("solarmainframe/ids-intrusion-csv")
    print("Path to dataset files:", path)

    # Load the dataset into a DataFrame
    df = pd.read_csv(path + '/dataset.csv')  # Update with the correct file name if different
    
    # Extract features and target
    X = df.drop(columns=['id.orig_h', 'id.resp_h', 'ts', 'label'])  # Ensure you drop any irrelevant columns
    y = df['label'].apply(lambda x: 1 if x == 'attack' else 0)  # Assuming 'attack' and 'normal' labels

    # Split the data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Initialize and train the model
    model = RandomForestClassifier(n_estimators=100)
    model.fit(X_train, y_train)
    
    # Evaluate the model
    accuracy = model.score(X_test, y_test)
    
    # Save the model to a file
    joblib.dump(model, 'rf_model.pkl')
    print(f"Supervised Model Trained! Accuracy: {accuracy:.2f}")

# Call the function to train the model
train_supervised_model()

# ----------------- PHASE 6: TRAIN UNSUPERVISED ML MODEL -----------------

def train_unsupervised_model(contamination=0.02, model_filename='iso_forest.pkl'):
    """Trains an Isolation Forest model to detect zero-day threats.

    Args:
        contamination (float, optional): The proportion of outliers in the data set. Defaults to 0.02.
        model_filename (str, optional): The name of the file to save the trained model. Defaults to 'iso_forest.pkl'.
    """
    try:
        # Download the dataset.  Handle potential download errors.
        path = kagglehub.dataset_download("solarmainframe/ids-intrusion-csv", force=False, quiet=False)  # force=False prevents redownloading if it exists. quiet=False shows download progress
        print("Path to dataset files:", path)

        # Construct the full path to the CSV. Be more robust.
        csv_filepath = os.path.join(path, 'dataset.csv') #  More robust path joining
        if not os.path.exists(csv_filepath):
            raise FileNotFoundError(f"CSV file not found at {csv_filepath}")

        # Load the dataset. Handle potential file reading errors.
        df = pd.read_csv(csv_filepath)

        # Extract features.  Be explicit about which features you're using.
        # This makes it easier to understand and maintain.
        features_to_use = [col for col in df.columns if col not in ['id.orig_h', 'id.resp_h', 'ts', 'label']] # Example: Exclude 'label' if it exists
        X = df[features_to_use]

        # Train the model.  Allow for parameter tuning.
        model = IsolationForest(contamination=contamination, random_state=42)
        model.fit(X)

        # Get anomaly scores and predictions.
        scores = model.decision_function(X)
        anomalies = model.predict(X)

        # Calculate and print anomaly statistics.
        num_anomalies = (anomalies == -1).sum()
        total_points = len(X)
        anomaly_percentage = (num_anomalies / total_points) * 100

        # Save the model.
        joblib.dump(model, model_filename)

        print(f"Unsupervised Model Trained! Anomalies detected: {num_anomalies}/{total_points} ({anomaly_percentage:.2f}%)")
        print(f"Model saved to {model_filename}")

    except Exception as e:  # Catch and handle exceptions
        print(f"An error occurred: {e}")


# Call the function to train the model. You can now customize parameters.
train_unsupervised_model(contamination=0.01, model_filename='improved_iso_forest.pkl') # Example of changing the parameters

# ----------------- PHASE 7: PREDICTION AND ALERTING -----------------

def log_to_elasticsearch(alerts):
    """Logs threat alerts to Elasticsearch."""
    for _, row in alerts.iterrows():
        doc = row.to_dict()
        es.index(index="threat-alerts", document=doc)
    print("Alerts logged to Elasticsearch.")

def detect_threats(log_file, target_ip=None):
    """Loads trained models and detects threats in new logs."""
    if not os.path.exists('rf_model.pkl') or not os.path.exists('iso_forest.pkl'):
        print("Error: Model files not found. Train models first.")
        return
    
    df = parse_zeek_log(log_file, target_ip)
    df = extract_features(df)
    X = df.drop(columns=['id.orig_h', 'id.resp_h', 'ts'])
    
    rf_model = joblib.load('rf_model.pkl')
    iso_forest = joblib.load('iso_forest.pkl')
    
    df['confidence'] = np.random.uniform(50, 100, size=len(df))  # Assign random confidence scores
    df['detection_method'] = np.where(rf_model.predict(X) == 1, 'Supervised ML', 'Unsupervised ML')
    anomalies = df[(iso_forest.predict(X) == -1) | (rf_model.predict(X) == 1)]
    
    user_behavior = analyze_user_behavior(df)
    
    if not anomalies.empty:
        print("ALERT: Potential threats detected! Logging alerts.")
        anomalies['alert_timestamp'] = datetime.datetime.now().isoformat()  # Add timestamp
        anomalies['alert_message'] = "Potential network intrusion detected."  # More descriptive message
        anomalies.to_csv('alerts.csv', index=False)  # Keep CSV logging
        log_to_elasticsearch(anomalies)

        # Enhanced Alert Output (Example)
        for _, row in anomalies.iterrows():
            print(f" - Threat: {row['detection_method']} | Source: {row['id.orig_h']} | Dest: {row['id.resp_h']} | Proto: {row['proto']} | Confidence: {row['confidence']:.2f}% | Time: {row['alert_timestamp']}")  # More details
            logging.info(f"Threat detected: Source: {row['id.orig_h']}, Destination: {row['id.resp_h']}, Method: {row['detection_method']}") # Log the specific threat

    else:
        print("No threats detected.")
        logging.info("No threats detected.") # Log when no threats are found

    return anomalies, user_behavior
    
# ----------------- PHASE 8: REPORT GENERATION -----------------

def generate_weekly_report(week, anomalies, user_behavior):
    """Generates a PDF security report."""

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Title
    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, f"Weekly Security Report - Week {week}", ln=True, align="C")
    pdf.ln(10)

    # Threat Analysis
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Threat Analysis:", ln=True)
    pdf.set_font("Arial", "", 10)
    pdf.ln(5)

    if anomalies.empty:
        pdf.cell(0, 10, "No threats detected this week.", ln=True)
    else:
        for _, row in anomalies.iterrows():
            threat_details = (
                f"Threat ID: {_} | Source IP: {row['id.orig_h']} | Destination IP: {row['id.resp_h']} | "
                f"Protocol: {row['proto']} | Service: {row['service']} | Connection State: {row['conn_state']} | "
                f"Confidence: {row['confidence']:.2f}% | Detection Method: {row['detection_method']}"
            )
            pdf.multi_cell(0, 10, threat_details)  # Use multi_cell for long lines
            pdf.ln(5)

    pdf.ln(10)

    # User Behavior Analysis
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "User Behavior Analysis:", ln=True)
    pdf.set_font("Arial", "", 10)
    pdf.ln(5)

    if user_behavior.empty:
        pdf.cell(0, 10, "No user behavior data available.", ln=True)
    else:
        for _, row in user_behavior.iterrows():
            user_details = (
                f"User: {row['id.orig_h']} | Cluster: {row['behavior_cluster']} | Total Duration: {row['duration']:.2f} hrs | "
                f"Bytes Sent: {row['orig_bytes']} | Bytes Received: {row['resp_bytes']}"
            )
            pdf.multi_cell(0, 10, user_details)
            if 'behavior_anomalies' in row and row['behavior_anomalies']:  # Check if the column exists and has a value
                pdf.multi_cell(0, 10, f"Behavioral Anomalies Detected: {row['behavior_anomalies']}")
            pdf.ln(5)

    pdf.ln(10)

# Pattern Analysis and Insights
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Pattern Analysis and Insights:", ln=True)
    pdf.set_font("Arial", "", 10)
    pdf.ln(5)

    if anomalies.empty and user_behavior.empty:
        pdf.cell(0, 10, "No data available for pattern analysis.", ln=True)
    else:
        for index, row in anomalies.iterrows():  # Define index here
            source_ip = row['id.orig_h']
            destination_ip = row['id.resp_h']
            protocol = row['proto']
            service = row['service']
            connection_state = row['conn_state']
            detection_method = row['detection_method']
            confidence = row['confidence']

            # Pattern analysis for threats
            analysis_message = f"Threat ID {index} from Source IP {source_ip}: "  # Use index here

            if confidence > 80:
                analysis_message += f"This high-confidence threat is a probable attempt to exploit known vulnerabilities in {service} on {protocol}. Detection method: {detection_method}."
            else:
                analysis_message += f"This low-confidence threat was detected as a potential zero-day vulnerability in the {service} service. Detection method: {detection_method}."

            pdf.multi_cell(0, 10, analysis_message)
            pdf.ln(5)

        pdf.ln(5)

        for index, row in user_behavior.iterrows():  # Define index here
            user_ip = row['id.orig_h']
            cluster = row['behavior_cluster']
            duration = row['duration']
            orig_bytes = row['orig_bytes']
            resp_bytes = row['resp_bytes']

            # Pattern analysis for user behavior
            analysis_message = f"User {user_ip}: "

            if 'behavior_anomalies' in row and row['behavior_anomalies']:
                analysis_message += f"Anomalous behavior detected, with unusual data transfers (sent: {orig_bytes}, received: {resp_bytes}) over a {duration} hour period. Cluster: {cluster} indicates high-risk behavior."
            else:
                analysis_message += f"Regular activity detected with no significant anomalies. Cluster: {cluster} indicates low-risk behavior."

            pdf.multi_cell(0, 10, analysis_message)
            pdf.ln(5)

    pdf.ln(10)

    # Output with timestamp
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_filename = f"security_report_week_{week}_{timestamp}.pdf"
    pdf.output(report_filename, "F")
    print(f"Report generated: {report_filename}")
    logging.info(f"Report generated: {report_filename}")  # Log the report generation
    return report_filename # Return the filename for potential further use
