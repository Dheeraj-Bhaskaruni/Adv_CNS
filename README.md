# EdgeShield: Real-Time Intrusion Detection System Using IoT-23 Dataset

**EdgeShield** is a lightweight, real-time intrusion detection system (IDS) designed for edge computing environments. By processing network traffic directly at edge nodes, EdgeShield provides immediate detection and response capabilities, minimizing latency and conserving network resources.

---

## Project Overview

EdgeShield deploys:
- **Sender Laptop (Attack Replay Node)**: Replays traffic from IoT-23 dataset.
- **Receiver Laptop (IDS Node)**: Captures replayed traffic and classifies it using a pre-trained ML model.

---

## Key Features

- Real-time intrusion detection at the edge
- Lightweight ML model (Random Forest)
- Real-time classification of benign vs. non-benign traffic
- Easy deployment using Ubuntu/Debian OS
- Traffic replay from IoT-23 dataset

---

## Requirements

### Hardware:

| Device | Hostname              | Ethernet NIC | MAC Address        | Role            | Static IP   |
|--------|-----------------------|--------------|--------------------|-----------------|-------------|
| Laptop | uday-Nitro-AN515-57   | enp2s0       | 00:00:00:00:00:00  | Traffic Replay  | 10.0.0.1/24 |
| Laptop | dhee-Stealth-15-A13VF | enp3s0       | 11:11:11:11:11:11  | IDS Monitoring  | 10.0.0.2/24 |

- CAT-5e/CAT-6 Ethernet cable

### Software:
- Ubuntu/Debian OS
- Python 3 with libraries:
  - `numpy`, `pandas`, `scikit-learn`, `pyshark`
- Network tools: `ethtool`, `tcpdump`, `tcpreplay`

---

## Dataset
- [IoT-23 Dataset](https://www.kaggle.com/datasets/engraqeel/iot23preprocesseddata): Preprocessed dataset for training and evaluating IDS models.

---

## Workflow

### 1. Dataset Acquisition and Preparation
- Download and preprocess IoT-23 dataset.
- Train Random Forest model using `model.py` script.
- Save trained model as `ids_rf_model.pkl`.

### 2. Traffic Replay Setup (Sender Node)
- Configure static IP address and disable hardware offloads.
- Rewrite MAC addresses in PCAP file to match sender/receiver NICs.

### 3. IDS Monitoring Setup (Receiver Node)
- Configure static IP address and enable promiscuous mode.
- Disable hardware offloads.
- Run `ids_live.py` to start real-time detection.

### 4. Replay Traffic and Classify
- Use `tcpreplay` to replay modified PCAP file.
- Real-time IDS classifies captured traffic instantly.

---

## Project Structure

```
EdgeShield/
├── model.py                 # Trains ML model on IoT-23 dataset
├── ids_live.py              # Real-time intrusion detection
├── ethernet_replay.pcap     # Modified replay file
├── ids_rf_model.pkl         # Pre-trained Random Forest ML model
└── README.md                # This documentation
```

---

## Results

- Real-time accurate detection of benign vs. malicious traffic.
- Validated IDS performance with realistic network attack scenarios.

---

## Contributing

Contributions are welcome! Please open issues or submit pull requests to suggest improvements or new features.

---

## License

- All attributable license holders.
