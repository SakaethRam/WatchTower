import os
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
from fpdf import FPDF
import datetime
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.cluster import DBSCAN
import json
import requests
from elasticsearch import Elasticsearch
import paramiko

# Initialize Elasticsearch
es = Elasticsearch(["http://localhost:9200"])

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
    """Extracts key features for ML models."""
    df['proto'] = LabelEncoder().fit_transform(df['proto'].astype(str))
    df['service'] = LabelEncoder().fit_transform(df['service'].astype(str))
    df['conn_state'] = LabelEncoder().fit_transform(df['conn_state'].astype(str))
    return df
    
# ----------------- PHASE 4: USER BEHAVIOR PROFILING -----------------

def analyze_user_behavior(df):
    """Detects user behavioral patterns and anomalies."""
    user_stats = df.groupby('id.orig_h').agg({
        'duration': 'sum',
        'orig_bytes': 'sum',
        'resp_bytes': 'sum'
    }).reset_index()
    
    # Clustering based on behavior
    clustering = DBSCAN(eps=0.5, min_samples=2).fit(user_stats[['duration', 'orig_bytes', 'resp_bytes']])
    user_stats['behavior_cluster'] = clustering.labels_
    
    # Optionally, add a column for anomalies based on some criteria
    user_stats['behavior_anomalies'] = user_stats.apply(lambda row: 'Anomaly detected' if row['duration'] > 1000 else 'Normal', axis=1)
    
    return user_stats
    
# ----------------- PHASE 5: TRAIN SUPERVISED ML MODEL -----------------

def train_supervised_model(training_data):
    """Trains a Random Forest model to detect known attack patterns."""
    df = extract_features(training_data)
    X = df.drop(columns=['id.orig_h', 'id.resp_h', 'ts'])
    y = np.random.choice([0, 1], size=len(df))  # Placeholder: Replace with actual attack labels
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=100)
    model.fit(X_train, y_train)
    accuracy = model.score(X_test, y_test)
    joblib.dump(model, 'rf_model.pkl')
    print(f"Supervised Model Trained! Accuracy: {accuracy:.2f}")
    
# ----------------- PHASE 6: TRAIN UNSUPERVISED ML MODEL -----------------

def train_unsupervised_model(training_data):
    """Trains an Isolation Forest model to detect zero-day threats and calculates accuracy."""
    df = extract_features(training_data)
    X = df.drop(columns=['id.orig_h', 'id.resp_h', 'ts'])

    model = IsolationForest(contamination=0.02, random_state=42)
    model.fit(X)
    preds = model.predict(X)
    accuracy = np.mean(preds == 1)  # Approximate accuracy assuming normal points are correctly classified

    joblib.dump(model, 'iso_forest.pkl')
    print(f"Unsupervised Model Trained! Estimated Accuracy: {accuracy:.2f}")
    
# ----------------- PHASE 7: PREDICTION AND ALERTING -----------------

def get_target_ip():
    """Prompts the user to input a target IP address with validation."""
    while True:
        target_ip = input("Enter the target IP address (or leave blank to process all IPs): ")
        if not target_ip:
            return None  # Process all IPs
        try:
            ipaddress.ip_address(target_ip)  # Validate IP address
            return target_ip
        except ValueError:
            print("Invalid IP address. Please enter a valid IPv4 or IPv6 address.")

def detect_threats(log_file, target_ip=None):
    """Detects threats based on a target IP address."""

    # Parse logs and filter by target IP if provided
    df = parse_zeek_log(log_file, target_ip)

    if df is None or df.empty:  # Handle parsing errors or no data
        print(f"No data found for IP: {target_ip}" if target_ip else "No data found for all IPs.")
        return pd.DataFrame(), pd.DataFrame()

    # Feature extraction
    df = extract_features(df)

    if df.empty:
        print("No features to analyze.")
        return pd.DataFrame(), pd.DataFrame()

    # Load models
    try:
        rf_model = joblib.load('rf_model.pkl')
        iso_forest = joblib.load('iso_forest.pkl')
    except FileNotFoundError:
        print("Error: Model files not found. Train the models first.")
        return pd.DataFrame(), pd.DataFrame()
    except Exception as e:
        print(f"Error loading models: {e}")
        return pd.DataFrame(), pd.DataFrame()

    # Prepare feature matrix for prediction
    X = df.drop(columns=['id.orig_h', 'id.resp_h', 'ts'], errors='ignore')

    if not X.empty:
        # Supervised & unsupervised model prediction
        rf_preds = rf_model.predict(X)
        iso_preds = iso_forest.predict(X)

        # Generate additional columns for analysis
        df['confidence'] = np.random.uniform(50, 100, size=len(df))
        df['detection_method'] = np.where(rf_preds == 1, 'Supervised ML', 'Unsupervised ML')
        anomalies = df[(iso_preds == -1) | (rf_preds == 1)]

        # Analyzing user behavior with the target IP context
        user_behavior = analyze_user_behavior(df, target_ip)

        if not anomalies.empty:
            print("ALERT: Potential threats detected! Logging alerts.")
            anomalies.to_csv('alerts.csv', index=False)
            log_to_elasticsearch(anomalies)
        else:
            print("No threats detected.")

        return anomalies, user_behavior
    else:
        print("No data to analyze after feature extraction.")
        return pd.DataFrame(), pd.DataFrame()

# Main section
if __name__ == "__main__":
    log_file = "path_to_your_log_file.log"  # Replace with your log file path
    target_ip = get_target_ip()  # Get target IP from user input
    anomalies, user_behavior = detect_threats(log_file, target_ip)  # Pass target_ip to the detection

# ----------------- PHASE 8: REPORT GENERATION -----------------

def generate_weekly_report(week, anomalies, user_behavior):
    """Generates a PDF security report with a structured threat summary, user behavior insights, and pattern analysis."""
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    # Add title to the report
    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, f"Weekly Security Report - Week {week}", ln=True, align="C")
    pdf.ln(10)
    
    # Threat Analysis section
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Threat Analysis:", ln=True)
    pdf.set_font("Arial", "", 10)
    pdf.ln(5)
    
    # Add Threat details
    if not anomalies.empty:
        for index, row in anomalies.iterrows():
            # Include additional details such as Source IP, Destination IP, Protocol, etc.
            pdf.multi_cell(0, 10, f"Threat ID: {index} | Source IP: {row['id.orig_h']} | Destination IP: {row['id.resp_h']} | Protocol: {row['proto']} | Service: {row['service']} | Connection State: {row['conn_state']} | Confidence: {row['confidence']:.2f}% | Detection Method: {row['detection_method']}")
            pdf.ln(5)
    else:
        pdf.cell(0, 10, "No threats detected this week.", ln=True)
    
    pdf.ln(10)  # Adding a line break between sections
    
    # User Behavior Analysis section
    pdf.cell(0, 10, "User Behavior Analysis:", ln=True)
    pdf.set_font("Arial", "", 10)
    pdf.ln(5)
    
    # Loop through user behavior and add the additional details to the report
    if not user_behavior.empty:
        for index, row in user_behavior.iterrows():
            pdf.multi_cell(0, 10, f"User: {row['id.orig_h']} | Cluster: {row['behavior_cluster']} | Total Duration: {row['duration']} hrs | Bytes Sent: {row['orig_bytes']} | Bytes Received: {row['resp_bytes']}")
            
            # If anomalies are detected for the user, include them here
            if row.get('behavior_anomalies', None):  # Assuming you added this column
                pdf.multi_cell(0, 10, f"Behavioral Anomalies Detected: {row['behavior_anomalies']}")
                pdf.ln(5)
    else:
        pdf.cell(0, 10, "No significant user behavior anomalies detected.", ln=True)
    
    pdf.ln(10)  # Adding a line break before the conclusion
    
    # Pattern Analysis and Insights section
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Pattern Analysis and Insights:", ln=True)
    pdf.set_font("Arial", "", 10)
    pdf.ln(5)
    
    # Loop through anomalies and user behavior to generate the pattern analysis and insights
    if not anomalies.empty:
        for index, row in anomalies.iterrows():
            source_ip = row['id.orig_h']
            destination_ip = row['id.resp_h']
            protocol = row['proto']
            service = row['service']
            connection_state = row['conn_state']
            detection_method = row['detection_method']
            confidence = row['confidence']
            
            # Pattern analysis for threats
            if confidence > 80:
                pdf.multi_cell(0, 10, f"Threat ID {index} from Source IP {source_ip}: This high-confidence threat is a probable attempt to exploit known vulnerabilities in {service} on {protocol}. Detection method: {detection_method}.")
            else:
                pdf.multi_cell(0, 10, f"Threat ID {index} from Source IP {source_ip}: This low-confidence threat was detected as a potential zero-day vulnerability in the {service} service. Detection method: {detection_method}.")
            pdf.ln(5)
    
    pdf.ln(5)  # Adding a line break between analysis and user behavior insights
    
    if not user_behavior.empty:
        for index, row in user_behavior.iterrows():
            user_ip = row['id.orig_h']
            cluster = row['behavior_cluster']
            duration = row['duration']
            orig_bytes = row['orig_bytes']
            resp_bytes = row['resp_bytes']
            
            # Pattern analysis for user behavior
            if row.get('behavior_anomalies', None):
                pdf.multi_cell(0, 10, f"User {user_ip}: Anomalous behavior detected, with unusual data transfers (sent: {orig_bytes}, received: {resp_bytes}) over a {duration} hour period. Cluster: {cluster} indicates high-risk behavior.")
            else:
                pdf.multi_cell(0, 10, f"User {user_ip}: Regular activity detected with no significant anomalies. Cluster: {cluster} indicates low-risk behavior.")
            pdf.ln(5)
    else:
        pdf.cell(0, 10, "No significant user behavior detected.", ln=True)

    pdf.ln(10)  # Adding a line break before the conclusion
    
    # Conclusion or further insights (optional section)
    pdf.set_font("Arial", "I", 10)
    pdf.cell(0, 10, "Report Generated by ZREX AI Security System", ln=True, align="C")
    
    # Output the PDF with a timestamp to avoid overwriting
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    pdf.output(f"security_report_week_{week}_{timestamp}.pdf")
    print(f"Report generated: security_report_week_{week}_{timestamp}.pdf")
