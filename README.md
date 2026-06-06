# SOC-Level Python SIEM (CustomTkinter + Flask API)

## Features
- Real-time log ingestion
- Rule-based + anomaly detection
- Incident database (SQLite)
- REST API (Flask)
- SOC Dashboard GUI (CustomTkinter)
- Attack simulation
- Basic ML anomaly scoring (z-score)

## Run

### 1. Install
pip install -r requirements.txt

### 2. Start API
python backend/api.py

### 3. Start GUI
python gui/app.py

## 🏗 System Architecture
```mermaid
graph TD
    A[Attack Source] -->|UDP 5555| B[SIEM Engine]
    B -->|Regex Parsing| C[(SQLite DB)]
    C --> D[Flask REST API]
    D --> E[PyQt6 Dashboard]
