# Ex.No: 13 Learning – Use Supervised Learning  
### DATE: 24/10/24                                                                           
### REGISTER NUMBER : 212221040061
### AIM:
To write a program to analyze potential security threats in a simulated dataset by identifying anomalies using the Isolation Forest algorithm.
###  Algorithm:
1.Import necessary libraries and generate a sample dataset with security-related fields.
2.Normalize the "Anomaly Scores" column using StandardScaler.
3.Apply the IsolationForest algorithm to detect anomalies, marking each entry as normal or an anomaly.
4.Generate random ground truth labels and calculate model accuracy.
5.Define a function to analyze each record for potential threats, checking for malware indicators, warnings, and detected anomalies.
6.Create a JSON report summarizing detected threats, severity levels, actions taken, and timestamps.
7.Visualize the anomaly scores and detected anomalies with plots for analysis.

### Program: 
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
import datetime
import json
import matplotlib.pyplot as plt

# Sample data structure
data = {
    "Timestamp": [datetime.datetime.now() for _ in range(10)],
    "Malware Indicators": np.random.randint(0, 2, 10),
    "Anomaly Scores": np.random.random(10),
    "Alerts/Warnings": np.random.randint(0, 2, 10),
    "Attack Type": ["SQL Injection"] * 5 + ["DDoS Attack"] * 5,
    "Attack Signature": ["sig1"] * 5 + ["sig2"] * 5,
    "Action Taken": ["Blocked"] * 5 + ["Mitigated"] * 5,
    "Severity Level": np.random.randint(1, 5, 10),
    "User Information": ["user1"] * 5 + ["user2"] * 5,
    "Device Information": ["device1"] * 5 + ["device2"] * 5,
    "Network Segment": ["segment1"] * 5 + ["segment2"] * 5,
    "Geo-location Data": ["location1"] * 5 + ["location2"] * 5,
    "Proxy Information": ["proxy1"] * 5 + ["proxy2"] * 5,
    "Firewall Logs": ["log1"] * 5 + ["log2"] * 5,
    "IDS/IPS Alerts": ["alert1"] * 5 + ["alert2"] * 5,
    "Log Source": ["source1"] * 5 + ["source2"] * 5
}

# Convert to DataFrame
df = pd.DataFrame(data)

# Data Preprocessing
scaler = StandardScaler()
df['Anomaly Scores'] = scaler.fit_transform(df[['Anomaly Scores']])

# Anomaly Detection using Isolation Forest
model = IsolationForest(contamination=0.1)
df['Anomaly'] = model.fit_predict(df[['Anomaly Scores']])

# Assume a ground truth for accuracy calculation (for demonstration purposes)
ground_truth = np.random.randint(-1, 2, 10)  # -1 for anomalies, 1 for normal
# Calculate accuracy
accuracy = accuracy_score(ground_truth, df['Anomaly'])
print(f"Model Accuracy: {accuracy * 100:.2f}%")

# Threat Intelligence Analysis
def analyze_threats(row):
    threats = []
    if row['Malware Indicators'] == 1:
        threats.append("Malware Detected")
    if row['Alerts/Warnings'] == 1:
        threats.append("Warning Issued")
    if row['Anomaly'] == -1:
        threats.append("Anomaly Detected")
    return threats

df['Threat Analysis'] = df.apply(analyze_threats, axis=1)

# Generate Reports
def generate_report(df):
    report = {}
    for index, row in df.iterrows():
        report[index] = {
            "Timestamp": row['Timestamp'],
            "Threats": row['Threat Analysis'],
            "Severity Level": row['Severity Level'],
            "Action Taken": row['Action Taken']
        }
    return json.dumps(report, default=str, indent=4)

report = generate_report(df)
print(report)

# Visualize Results
fig, axs = plt.subplots(2, 1, figsize=(10, 10))
# Plot Anomaly Scores
axs[0].bar(df.index, df['Anomaly Scores'], color='blue')
axs[0].set_title('Anomaly Scores')
axs[0].set_xlabel('Index')
axs[0].set_ylabel('Anomaly Score')

# Plot Detected Anomalies
anomalies = df[df['Anomaly'] == -1].index
axs[1].scatter(df.index, df['Anomaly'], color='green', label='Normal')
axs[1].scatter(anomalies, df.loc[anomalies, 'Anomaly'], color='red', label='Anomaly')
axs[1].set_title('Detected Anomalies')
axs[1].set_xlabel('Index')
axs[1].set_ylabel('Anomaly')
axs[1].legend()
plt.tight_layout()
plt.show()
### Output:
"C:\Users\jagan\OneDrive\Desktop\6cf5e952-ddee-4be1-9c41-bbb5e2ce5db6"
### Result:
Thus the system was trained successfully and the prediction was carried out.
