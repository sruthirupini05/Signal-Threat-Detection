# AI-Driven Wireless Signal Intelligence System

**Real-Time Threat Detection Using CNN and Isolation Forest**

A software-only wireless signal intelligence system that detects threats across WiFi and Bluetooth without relying on dedicated hardware like SDRs. It combines deep learning–based signal classification with unsupervised anomaly detection on live network traffic, all surfaced through a real-time Streamlit dashboard.


## Overview

Most wireless monitoring systems depend on Software Defined Radios (SDRs) — expensive, hard to deploy, and difficult to scale across environments. This project replaces that hardware dependency with a software-centric pipeline that fuses:

- **Signal-level analysis** — classifying raw IQ signal data by modulation type
- **Network-level analysis** — monitoring live packet traffic for behavioral anomalies
- **Device-level analysis** — scanning for nearby Bluetooth devices

The result is a low-cost, easily deployable system capable of real-time threat detection on standard computing hardware.

## Key Features

- 🔍 **Signal classification** — CNN trained on the RadioML 2018.01A dataset to identify modulation schemes from raw IQ data
- 📡 **Network monitoring** — raw-socket packet capture for real-time inspection of TCP/UDP/ICMP traffic
- 📶 **Bluetooth detection** — BLE scanning (via Bleak) to identify nearby devices and flag unknown/unauthorized ones
- 🚨 **Anomaly detection** — Isolation Forest flags abnormal traffic patterns (e.g. ICMP floods) with LOW/MEDIUM/HIGH severity scoring, no labeled data required
- 📊 **Live dashboard** — Streamlit interface for real-time visualization of signals, traffic, and alerts
- 🔒 **Privacy-by-design** — analyzes only metadata (packet size, protocol, frequency, duration); never inspects or stores communication content

## System Architecture

The system is organized into five interconnected modules, each feeding into the next for continuous, real-time processing:

1. **Signal Classification Module** — CNN-based modulation recognition from raw IQ data
2. **Network Packet Capture Module** — raw socket-based traffic monitoring
3. **Bluetooth Detection Module** — BLE scanning for nearby device discovery
4. **Anomaly Detection Module** — Isolation Forest evaluates extracted features for abnormal behavior
5. **Visualization Dashboard** — Streamlit front-end aggregating all module outputs

```
IQ Signal Data ──► CNN Classifier ──┐
                                     ├──► Streamlit Dashboard
Network Traffic ─► Feature Extract ─┤        (real-time)
                                     │
Bluetooth Scan ───► Isolation Forest┘
                    (anomaly scoring)
```

## Tech Stack

| Component | Technology |
|---|---|
| Language | Python |
| Signal Classification | TensorFlow, Keras |
| Anomaly Detection | Scikit-learn (Isolation Forest) |
| Network Monitoring | Scapy, Psutil |
| Bluetooth Scanning | Bleak (BLE) |
| Dashboard | Streamlit |
| Data Processing | NumPy, Pandas, SciPy |
| Visualization | Matplotlib, Seaborn |
| Dataset Handling | h5py (HDF5 format) |
| Utilities | tqdm, colorama |

## Dataset

**RadioML 2018.01A** — a standard benchmark for automatic modulation recognition.

- 24 distinct modulation schemes (analog + digital: AM, FM, PSK, QAM, etc.)
- Samples represented as IQ (In-phase/Quadrature) components
- Multiple SNR levels for robustness to noisy, real-world conditions

Preprocessing: normalization → reshaping for the CNN's sequential input → shuffling and train/test split → dropout/regularization during training to reduce overfitting.

## Model Details

**CNN (Signal Classification)**
- 1D convolutional layers extract local patterns (frequency variation, phase shifts) directly from raw IQ input
- Batch normalization for stable, faster convergence
- Dropout for generalization
- Fully connected layers → softmax output over 24 modulation classes
- Optimizer: Adam; typically trained for 20–50 epochs

**Isolation Forest (Anomaly Detection)**
- Unsupervised — no labeled attack data required
- Trained on ~10 features: packet count, packet size, protocol type, communication duration, source/destination frequency, byte rate, session duration
- Outputs an anomaly score per data point; lower scores indicate higher likelihood of anomaly
- Detected events bucketed into LOW / MEDIUM / HIGH severity

## Results Summary

- High classification accuracy across modulation classes, with minor confusion only between closely related schemes
- Training/validation curves show stable convergence with no significant overfitting
- Real-time test: successfully detected a live ICMP communication session (101 packets, ~7.3 KB) with no noticeable processing delay
- Detected an ICMP flood-like pattern and correctly flagged it as a low-severity anomaly

## Privacy & Ethics

- Only the *existence* and *metadata* of communication are analyzed — never message content, logins, or media
- No long-term data storage; processing is real-time and data is discarded after analysis
- Intended for use in **authorized environments only** (enterprise networks, research labs)

## Limitations

- Scapy has limited compatibility with newer Python versions (e.g. 3.13)
- Raw socket packet capture requires administrative/root privileges
- BLE scanning range is limited to roughly 10 meters
- CNN is trained on synthetic RadioML data, which may not fully capture real-world interference and hardware variation
- Anomaly detection may produce false positives in highly dynamic/noisy network conditions

## Future Work

- Extend signal classification to 5G New Radio (NR) modulation schemes
- Controlled Deep Packet Inspection (DPI) in secure environments
- Federated learning for privacy-preserving model training across devices
- Mobile (Android) deployment for portable monitoring
- Cloud deployment (AWS / Azure) for centralized, scalable monitoring
- SIEM integration (Splunk, ELK Stack) for automated alert correlation
- GPS-based localization for spatial tracking of detected devices

## Applications

- Enterprise network security and unauthorized device detection
- Smart city / IoT infrastructure monitoring
- Educational and research use for hands-on wireless security study
- Defense and surveillance contexts requiring early threat detection

## Citation

If you use this work, please cite the associated paper: *"AI-Driven Wireless Signal Intelligence System for Real-Time Threat Detection Using CNN and Isolation Forest"* (SRM University AP).
