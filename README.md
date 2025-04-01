# ZREX Watch Tower - Zeek ML Pipeline

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

![Architecture](https://github.com/user-attachments/assets/aecd722d-ad04-4767-9d82-afabbec44971)

## Getting Started

To set up and run Watch Tower, follow these steps:

1. **Install Dependencies:** Ensure you have all the required Python libraries installed.
2. **Configure Zeek Log Path:** Update the script with the correct path to your Zeek logs.
3. **Set up Elasticsearch:** Make sure your Elasticsearch instance is running.
4. **Train ML Models:** Run the script to train the Random Forest and Isolation Forest models.
5. **Configure Remote Monitoring (if needed):** Set up SSH for monitoring remote machines.

## Setup & Installation
The setup process is designed to be executed as cells within a Jupyter Notebook. Follow the steps below:

### 1. Install Dependencies
Execute the following command in a Jupyter Notebook cell:
```python
!pip install numpy pandas scikit-learn tensorflow keras matplotlib seaborn
```

### 2. Clone the Repository
```python
!git clone https://github.com/your-repo/network-threat-detection.git
%cd network-threat-detection
```

### 3. Load and Preprocess the Dataset
```python
import pandas as pd

# Load dataset
file_path = "path/to/dataset.csv"
df = pd.read_csv(file_path)

# Data preprocessing steps
df.dropna(inplace=True)
df = df.sample(frac=1).reset_index(drop=True)
```

### 4. Train the ML Models
```python
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

# Splitting dataset
X = df.drop(columns=['label'])
y = df['label']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Training RandomForest Model
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)
```

### 5. Evaluate the Model
```python
from sklearn.metrics import accuracy_score

# Predictions
y_pred = clf.predict(X_test)

# Model Accuracy
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy * 100:.2f}%")
```

### 6. Deploy the Model
```python
import joblib

# Save model
joblib.dump(clf, "network_threat_model.pkl")

# Load model
model = joblib.load("network_threat_model.pkl")
```

### 7. Real-Time Threat Detection
```python
def detect_threat(input_data):
    prediction = model.predict([input_data])
    return "Threat Detected" if prediction[0] == 1 else "No Threat"
```

## Usage

1. **Review Weekly Reports:** Check the generated weekly security reports for threat analysis and user behavior insights.
2. Trained the model using `CIC-IDS- 2018` dataset.
3. Use `detect_threat()` to classify new input data.
4. **Run the Script:** Execute the main script to start the Watch Tower pipeline.
5. **Deploy & Run the Script:** Deploy it to analyze network traffic.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bug fixes, feature requests, or documentation improvements.

## License
This project is licensed under the MIT License. See `LICENSE` for more details.
