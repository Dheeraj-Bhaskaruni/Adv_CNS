# EdgeShield: A Raspberry Pi Fog Security System for IoT

**EdgeShield** is a lightweight, real-time intrusion detection system designed for IoT environments. By processing network traffic directly on Raspberry Pis (fog nodes), it enables early threat detection at the edge — minimizing latency, conserving bandwidth, and boosting security without relying solely on the cloud.

---

## Project Overview
EdgeShield deploys:
- **2 Fog Nodes** (Raspberry Pi 4) to detect suspicious traffic using a pre-trained ML model.
- **1 Gateway** device to receive and display alerts from fog nodes for centralized monitoring.

---

## Key Features
- Real-time intrusion detection at the edge
- Lightweight ML model (e.g., Random Forest)
- Alerts via MQTT or HTTP
- Supports datasets like IoT-23 and TON_IoT for training
- Easy deployment on Raspberry Pi OS

---

## Requirements

### Hardware:
- 2 × Raspberry Pi 4 (2GB/4GB RAM) – **Fog Nodes**
- 1 × Raspberry Pi / Small Server – **Gateway**
- MicroSD Cards (≥16GB)
- Official power supplies (5V/3A)
- Network router or Wi-Fi access point
- Ethernet cables (if using wired setup)

### Software:
- Raspberry Pi OS
- Python 3 with the following libraries:
  - `numpy`, `pandas`, `scikit-learn` (or `tflite-runtime`)
  - `paho-mqtt` (for MQTT-based alerts)
  - Optional tools: `tcpdump`, `Suricata`, `Zeek` for real-time network capture

---

##  Dataset (Offline Training)
- [IoT-23 Dataset](https://www.stratosphereips.org/datasets-iot23): Contains labeled IoT traffic (e.g., Mirai, Gafgyt attacks).
- [TON_IoT Dataset (Optional)](https://research.unsw.edu.au/projects/toniot-datasets): Provides telemetry and network data for IoT scenarios.

---

## How It Works

### 1. Model Training (Offline)
- Download IoT-23 dataset.
- Convert PCAP files to flow data using tools like CICFlowMeter.
- Extract key features: flow duration, packet counts, average packet sizes, etc.
- Train a lightweight ML model (e.g., Random Forest).
- Export the model as a `.pkl` file.

### 2. Fog Node Deployment
- Setup Raspberry Pi OS and install required Python libraries.
- Run `fog_node.py` on each fog node:
  - Captures local network traffic.
  - Extracts real-time features.
  - Classifies traffic using the ML model.
  - Sends alert to gateway via MQTT or HTTP if malicious activity is detected.

### 3. Gateway Integration
- Run `gateway.py` on the Gateway device:
  - Receives and logs alerts from fog nodes.
  - Optionally displays alerts on a simple web dashboard.

---

## Project Structure (for now)

```
# TBD
EdgeShield/
├── fog_node.py        # Runs ML model & detects malicious traffic
├── gateway.py         # Collects alerts from fog nodes
├── attack_replay.py   # Replays attacks from PCAP files using tcpreplay
├── custom_attack.py   # Generates custom SYN flood attacks 
├── rf_model.pkl       # Pre-trained Random Forest ML model (TBD)
└── README.md          # This documentation
```



