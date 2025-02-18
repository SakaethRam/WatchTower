# Watch Tower - Zeek ML Pipeline

## Introduction
Watch Tower is a cutting-edge cybersecurity solution that leverages the power of Zeek logs, machine learning, and the ELK stack to provide comprehensive threat detection and analysis. Unlike traditional security systems, Watch Tower combines signature-based and anomaly-based detection methods to identify both known and unknown threats.

![WATCH TOWER](https://github.com/user-attachments/assets/5e654369-bb62-487e-87cb-12ed0e416448)

## Key Features

* **Hybrid Threat Detection:** Combines Random Forest and Isolation Forest models to detect known attacks and zero-day threats.
* **Automated Weekly Behaviour Analysis:** Identifies evolving attack patterns by comparing weekly network behavior.
* **Remote & Scalable Monitoring:** Collects and analyzes logs from remote machines, making it ideal for large-scale networks and cloud environments.
* **ELK Stack Integration:** Enables real-time log storage, threat visualization, and immediate alerting.
* **Continuous Learning & Adaptation:** The Isolation Forest model retrains as new logs are ingested, ensuring the system evolves and remains effective against emerging threats.
* **Robust Analysis & Reporting:** Generates detailed weekly reports with insights into detected threats and user behavior anomalies.

## Architecture

The Watch Tower pipeline consists of seven phases:

1. **Remote Log Collection:** Gathers Zeek logs from various sources.
2. **Zeek Log Parsing:** Processes and structures the collected logs.
3. **Feature Engineering:** Extracts relevant features from the parsed logs.
4. **Train Supervised ML Model:** Trains the Random Forest model for known attack detection.
5. **Train Unsupervised ML Model:** Trains the Isolation Forest model for unknown threat detection.
6. **Prediction and Alerting:** Detects threats and anomalies using the trained models and generates alerts.
7. **Report Generation:** Creates comprehensive weekly security reports.

## Getting Started

To set up and run Watch Tower, follow these steps:

1. **Install Dependencies:** Ensure you have all the required Python libraries installed.
2. **Configure Zeek Log Path:** Update the script with the correct path to your Zeek logs.
3. **Set up Elasticsearch:** Make sure your Elasticsearch instance is running.
4. **Train ML Models:** Run the script to train the Random Forest and Isolation Forest models.
5. **Configure Remote Monitoring (if needed):** Set up SSH for monitoring remote machines.

## Usage

1. **Run the Script:** Execute the main script to start the Watch Tower pipeline.
2. **Review Weekly Reports:** Check the generated weekly security reports for threat analysis and user behavior insights.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bug fixes, feature requests, or documentation improvements.
