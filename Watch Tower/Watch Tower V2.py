#pip install pandas numpy joblib matplotlib fpdf scikit-learn requests elasticsearch paramiko

import os
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
from fpdf import FPDF
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
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


# ----------------- PHASE 4: TRAIN SUPERVISED ML MODEL -----------------

def train_supervised_model(training_data):
    """Trains a Random Forest model to detect known attack patterns."""
    df = extract_features(training_data)
    X = df.drop(columns=['id.orig_h', 'id.resp_h', 'ts'])
    y = np.random.choice([0, 1], size=len(df))  # Placeholder: Replace with actual attack labels
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=100)
    model.fit(X_train, y_train)
    joblib.dump(model, 'rf_model.pkl')
    print("Supervised Model Trained!")


# ----------------- PHASE 5: TRAIN UNSUPERVISED ML MODEL -----------------

def train_unsupervised_model(training_data):
    """Trains an Isolation Forest model to detect zero-day threats."""
    df = extract_features(training_data)
    X = df.drop(columns=['id.orig_h', 'id.resp_h', 'ts'])

    model = IsolationForest(contamination=0.02, random_state=42)
    model.fit(X)
    joblib.dump(model, 'iso_forest.pkl')
    print("Unsupervised Model Trained!")


# ----------------- PHASE 6: PREDICTION AND ALERTING -----------------

def log_to_elasticsearch(alerts):
    """Logs threat alerts to Elasticsearch."""
    for index, row in alerts.iterrows():
        doc = row.to_dict()
        es.index(index="threat-alerts", body=doc)
    print("Alerts logged to Elasticsearch.")


def detect_threats(log_file, target_ip=None):
    """Loads trained models and detects threats in new logs filtered by target IP."""
    df = parse_zeek_log(log_file, target_ip)
    df = extract_features(df)
    X = df.drop(columns=['id.orig_h', 'id.resp_h', 'ts'])

    # Load models
    rf_model = joblib.load('rf_model.pkl')
    iso_forest = joblib.load('iso_forest.pkl')

    # Predictions
    rf_preds = rf_model.predict(X)
    iso_preds = iso_forest.predict(X)

    df['confidence'] = np.random.uniform(50, 100, size=len(df))  # Placeholder for confidence score
    df['detection_method'] = np.where(rf_preds == 1, 'Supervised ML', 'Unsupervised ML')
    anomalies = df[(iso_preds == -1) | (rf_preds == 1)]

    if not anomalies.empty:
        print("ALERT: Potential threats detected! Logging alerts.")
        anomalies.to_csv('alerts.csv', index=False)
        log_to_elasticsearch(anomalies)
    else:
        print("No threats detected.")


# ----------------- PHASE 7: REPORT GENERATION -----------------

def generate_weekly_report(week, anomalies):
    """Generates a PDF security report with a structured threat summary."""
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, f"Weekly Security Report - Week {week}", ln=True, align="C")
    pdf.ln(10)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Threat Analysis:", ln=True)
    pdf.set_font("Arial", "", 10)
    pdf.ln(5)

    # Table headers
    pdf.set_font("Arial", "B", 10)
    pdf.cell(30, 10, "Threat ID", border=1)
    pdf.cell(40, 10, "Source IP", border=1)
    pdf.cell(40, 10, "Destination IP", border=1)
    pdf.cell(30, 10, "Timestamp", border=1)
    pdf.cell(30, 10, "Confidence", border=1)
    pdf.cell(40, 10, "Detection Method", border=1, ln=True)
    pdf.set_font("Arial", "", 10)

    for index, row in anomalies.iterrows():
        pdf.cell(30, 10, str(index), border=1)
        pdf.cell(40, 10, row['id.orig_h'], border=1)
        pdf.cell(40, 10, row['id.resp_h'], border=1)
        pdf.cell(30, 10, str(row['ts']), border=1)
        pdf.cell(30, 10, f"{row['confidence']:.2f}%", border=1)
        pdf.cell(40, 10, row['detection_method'], border=1, ln=True)

    pdf.output(f"security_report_week_{week}.pdf")
    print(f"Report generated: security_report_week_{week}.pdf")
