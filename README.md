# 🛡️ AI-Driven Multi-Cloud Threat Detection System

## 🚀 Overview
This project is an AI-powered security monitoring system designed to detect suspicious behavior across multi-cloud environments (AWS, Azure, GCP). It combines machine learning (Isolation Forest) with rule-based detection to identify anomalies in cloud logs and visualize threats in real time using an interactive dashboard.

---

## 🎯 Key Features
- 🔍 Anomaly detection using Isolation Forest (ML-based)
- ⚠️ Risk classification (Low, Medium, High) with confidence scoring
- 📊 Real-time monitoring dashboard built with Streamlit
- 📡 Manual log analysis + bulk log file processing
- 🔄 Hybrid detection (Machine Learning + Rule-based logic)
- ☁️ Multi-cloud support (AWS, Azure, GCP logs)

---

## 🧠 How It Works
1. Cloud logs (JSON format) are ingested into the system  
2. Each log is analyzed using:
   - Machine Learning model (Isolation Forest)
   - Rule-based threat classification  
3. The system assigns:
   - Threat type  
   - Risk level  
   - Confidence score  
4. Results are displayed in a real-time dashboard  

---

## 🖥️ Application Interface

The application provides two main modes:

### 🔍 Manual Detection
- Paste a single JSON log
- Instantly analyze threat level and recommendations  

### 📡 Real-Time Monitoring
- Upload a JSON file containing multiple logs  
- View threat analysis for each log  

---

## 🛠️ Tech Stack
- Python  
- Streamlit  
- Scikit-learn (Isolation Forest)  
- JSON Processing  
- Cloud Security Concepts  

---
