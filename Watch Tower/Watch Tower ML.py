import os
import re
import json
import requests
import nmap
import scapy.all as scapy
import pandas as pd
import numpy as np
import time
import schedule
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from bs4 import BeautifulSoup
from fpdf import FPDF
import smtplib
from email.mime.text import MIMEText


# ----------------- PHASE 1: DATA COLLECTION -----------------
def passive_recon(domain):
    """Scrape OSINT data from public sources like Shodan and WHOIS."""
    shodan_api_key = "YOUR_SHODAN_API_KEY"
    url = f"https://api.shodan.io/dns/domain/{domain}?key={shodan_api_key}"

    try:
        response = requests.get(url)
        return response.json()
    except Exception as e:
        return {"error": str(e)}


def active_scan(ip):
    """Perform network scanning using Nmap."""
    scanner = nmap.PortScanner()
    scanner.scan(ip, arguments='-sV -O')
    return scanner[ip] if ip in scanner.all_hosts() else {}


def network_sniff(interface="eth0", duration=60):
    """Capture packets and extract visited websites for a given duration."""
    end_time = time.time() + duration
    packets = []
    domains = []

    while time.time() < end_time:
        sniffed_packets = scapy.sniff(iface=interface, count=10, timeout=5)
        for packet in sniffed_packets:
            if packet.haslayer(scapy.DNS) and packet.haslayer(scapy.IP):
                domains.append(packet[scapy.DNS].qd.qname.decode())
            packets.append(packet.summary())

    return list(set(domains)), packets


def get_geolocation(ip):
    """Fetch geolocation information for the target IP."""
    try:
        response = requests.get(f"https://ip-api.com/json/{ip}")
        return response.json()
    except Exception as e:
        return {"error": str(e)}


# ----------------- PHASE 2: FEATURE EXTRACTION -----------------
def extract_features(domain_data, scan_data, network_data):
    """Convert gathered data into structured features for ML training."""
    features = {
        "num_subdomains": len(domain_data.get("subdomains", [])),
        "open_ports": len(scan_data.get("tcp", {})),
        "unique_sites_visited": len(network_data[0])
    }
    return features


def calculate_risk_score(feature_data):
    """Calculate a security risk score based on reconnaissance data."""
    risk_score = 0
    if feature_data["open_ports"] > 10:
        risk_score += 30
    if feature_data["unique_sites_visited"] > 20:
        risk_score += 20
    return min(100, risk_score)


def send_alert(message):
    """Send real-time alerts via email."""
    sender_email = "your_email@example.com"
    receiver_email = "admin@example.com"
    subject = "Real-Time Security Alert"

    msg = MIMEText(message)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email

    try:
        with smtplib.SMTP("smtp.example.com", 587) as server:
            server.starttls()
            server.login(sender_email, "your_password")
            server.sendmail(sender_email, receiver_email, msg.as_string())
    except Exception as e:
        print(f"Failed to send alert: {e}")


# ----------------- PHASE 3: ML TRAINING -----------------
def train_ml_model(data, previous_data):
    """Train a Random Forest model on reconnaissance data and compare with previous data."""
    df = pd.DataFrame(data)

    if previous_data:
        prev_df = pd.DataFrame(previous_data)
        df = pd.concat([prev_df, df])

    le = LabelEncoder()
    if "category" in df.columns:
        df["category"] = le.fit_transform(df["category"])

    X = df.drop(columns=["label"])  # Features
    y = df["label"]  # Target

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=100)
    model.fit(X_train, y_train)

    accuracy = model.score(X_test, y_test)
    print(f"Model Accuracy: {accuracy * 100:.2f}%")

    return model, accuracy


# ----------------- PHASE 4: REPORT GENERATION -----------------
def generate_pdf_report(week, osint_data, scan_data, network_data, accuracy, previous_data, geolocation_data,
                        risk_score):
    """Generate a PDF report for the current week's analysis."""
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, f"Reconnaissance Report - Week {week}", ln=True, align="C")
    pdf.ln(10)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Geolocation Information:", ln=True)
    pdf.set_font("Arial", "", 10)
    pdf.cell(0, 10, f"Country: {geolocation_data.get('country', 'N/A')}", ln=True)
    pdf.cell(0, 10, f"ISP: {geolocation_data.get('isp', 'N/A')}", ln=True)
    pdf.ln(5)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Risk Score:", ln=True)
    pdf.set_font("Arial", "", 10)
    pdf.cell(0, 10, f"{risk_score}/100", ln=True)
    pdf.ln(5)

    pdf.output(f"week_{week}_report.pdf")


# ----------------- PHASE 5: EXECUTION -----------------
def monitor_and_generate_reports():
    week = 1
    previous_data = []

    has_domain = input("Does the target contain a domain and an IP? (yes/no): ").strip().lower()

    if has_domain == "yes":
        target_domain = input("Enter the domain name: ").strip()
        target_ip = input("Enter the IP address: ").strip()
    else:
        target_domain = ""
        target_ip = input("Enter the IP address: ").strip()

    while week <= 2:
        print(f"[*] Week {week}: Gathering reconnaissance data...")

        osint_data = passive_recon(target_domain) if target_domain else {}
        scan_data = active_scan(target_ip)
        network_data = network_sniff()
        geolocation_data = get_geolocation(target_ip)

        feature_data = extract_features(osint_data, scan_data, network_data)
        risk_score = calculate_risk_score(feature_data)

        generate_pdf_report(week, osint_data, scan_data, network_data, 95.2, previous_data, geolocation_data,
                            risk_score)

        if risk_score > 70:
            send_alert(f"High risk detected in Week {week}! Risk Score: {risk_score}/100")

        previous_data = feature_data
        week += 1


if __name__ == "__main__":
    monitor_and_generate_reports()
