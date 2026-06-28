<<<<<<< HEAD
# 📡 AI-Driven Wireless Signal Intelligence System

> Real-time WiFi + Bluetooth communication detection with AI-powered threat analysis

---

## 📁 Project Structure

```
signal-threat-detection/
├── data/
│   ├── dataset.pkl              ← RadioML dataset (from Kaggle)
│   ├── labels.pkl               ← Class label mapping (auto-generated)
│   ├── devices.json             ← Last network scan result
│   ├── bluetooth_devices.json   ← Last BT scan result
│   ├── traffic_snapshot.json    ← Last traffic capture snapshot
│   └── alert_log.json           ← Threat alert log
│
├── model/
│   ├── model.h5                 ← Trained CNN model (from Kaggle)
│   ├── anomaly_detector.pkl     ← Trained Isolation Forest
│   ├── training_curves.png      ← Accuracy/Loss plots
│   └── confusion_matrix.png     ← Confusion matrix plot
│
├── train.py                     ← CNN training (run on Kaggle)
├── network_scan.py              ← WiFi device discovery
├── communication_monitor.py     ← Packet monitoring between 2 devices
├── bluetooth_scan.py            ← Bluetooth scanning
├── anomaly_detection.py         ← Isolation Forest threat detection
├── app.py                       ← Streamlit dashboard (main entry)
├── requirements.txt
└── README.md
```

---

## 🚀 STEP-BY-STEP SETUP

### STEP 1 — Install Prerequisites on Your Laptop

```bash
# 1a. Create and activate virtual environment
python -m venv signal_env

# Windows:
signal_env\Scripts\activate

# Mac/Linux:
source signal_env/bin/activate

# 1b. Install all packages
pip install -r requirements.txt
```

**Windows only — Install Npcap (required for scapy packet capture):**
- Download from: https://npcap.com/#download
- Run the installer, tick "WinPcap API-compatible mode"
- Restart your machine

---

### STEP 2 — Train CNN on Kaggle

1. Go to https://www.kaggle.com
2. Create account → click **+ New Notebook**
3. Click **Add Data** → search `RadioML 2018.01A` → add it
4. Upload `train.py` to the notebook
5. Set **Accelerator → GPU T4** (Settings tab)
6. Run all cells — training takes ~20–40 minutes
7. After training, download:
   - `model/model.h5`
   - `data/labels.pkl`
   - `model/training_curves.png`
   - `model/confusion_matrix.png`
8. Place them in your local `model/` and `data/` folders

> **Note:** The system works without model.h5. The dashboard shows sample charts and the anomaly detector runs independently.

---

### STEP 3 — Prepare Your Demo Devices

**For WiFi detection:**
1. Enable mobile hotspot on your phone **OR** connect both devices to the same WiFi router
2. Note the IP address of both devices:
   - Phone: Go to Settings → WiFi → Your network → IP Address
   - Laptop: Run `ipconfig` (Windows) or `ifconfig` (Mac/Linux)

**For Bluetooth detection:**
1. Enable Bluetooth on both devices
2. Pair your phone with your laptop (do this in OS settings)
3. Keep both devices Bluetooth ON during the demo

---

### STEP 4 — Run the Dashboard

```bash
# Make sure virtual environment is active
# Run as Administrator on Windows (required for packet capture)

streamlit run app.py
```

The dashboard opens at: http://localhost:8501

---

### STEP 5 — Live Demo Walkthrough

#### 5a. Scan Network (WiFi)
1. In sidebar → click **🔍 Scan Network**
2. Both your phone and laptop appear in the device table
3. Select your phone as **Device A**, laptop as **Device B** (or vice versa)

#### 5b. Start Packet Capture
1. Click **▶ Start** in the sidebar
2. Generate traffic between devices:
   - Open a browser on your phone → go to any website
   - Ping from laptop: `ping <phone_ip>` in command prompt
   - Transfer a file via shared folder
3. Watch the WiFi Monitor tab — packets appear in real time
4. **COMMUNICATION ACTIVE** banner turns green

#### 5c. Bluetooth Demo
1. Make sure phone is paired with laptop
2. Click **🔵 Scan Bluetooth** in sidebar
3. Your phone appears in the device list
4. Send a file via Bluetooth during demo → status shows "Connected"
5. RSSI chart shows signal strength

#### 5d. Trigger a Threat Alert (for demo impact)
In a command prompt/terminal:
```bash
# Windows — heavy ping to trigger anomaly
ping -l 65500 -n 1000 <phone_ip>

# Mac/Linux
ping -s 65500 -c 1000 <phone_ip>
```
The anomaly detector triggers a **THREAT DETECTED** alert on the dashboard.

---

## 🔧 Individual Module Testing

Test each module independently before the full demo:

```bash
# Test network scanner
python network_scan.py

# Test communication monitor (replace IPs with your actual device IPs)
python communication_monitor.py 192.168.1.10 192.168.1.5

# Test Bluetooth scanner
python bluetooth_scan.py

# Test anomaly detector
python anomaly_detection.py
```

---

## 🖥️ Running Without Admin Privileges

If you can't run as admin (no packet capture):

The dashboard still works — it shows:
- Network device list (via ARP table — no admin needed)
- Bluetooth devices (via bleak — no admin needed)
- AI model classification results
- Anomaly detection on simulated data

For packet capture without admin: use **Wireshark** separately to capture a `.pcap` file, then analyze it offline.

---

## 🔵 Bluetooth Library Setup

### Option A: bleak (Recommended — works everywhere)
```bash
pip install bleak
```
No additional setup needed. Detects BLE devices.

### Option B: pybluez (Classic Bluetooth)
**Windows:**
```bash
pip install pybluez
```
Requires Bluetooth SDK. May need Visual C++ build tools.

**Linux:**
```bash
sudo apt-get install bluetooth libbluetooth-dev
pip install pybluez
```

**Mac:** Use bleak only (pybluez not supported on modern macOS).

---

## 📱 Android Phone Setup (for testing)

To make your phone's traffic more visible:
1. Connect phone to laptop's hotspot (or same WiFi)
2. Install **PingTools** app on Android
3. Ping your laptop's IP from the app
4. Your communication_monitor.py will immediately detect the packets

---

## 🚨 Troubleshooting

| Problem | Solution |
|---|---|
| `scapy: no interfaces found` | Install Npcap (Windows) or run as root (Linux/Mac) |
| `Permission denied` on packet capture | Run terminal/VS Code as Administrator |
| Bluetooth not detecting phone | Enable Bluetooth on both devices; pair first in OS settings |
| `bleak` not finding BLE devices | Ensure Bluetooth adapter is enabled; some adapters don't support BLE |
| Model.h5 not found | Run train.py on Kaggle first, download the file |
| Phone not showing in network scan | Use ping sweep: `python network_scan.py` — it auto-pings all IPs |
| Streamlit port busy | Use `streamlit run app.py --server.port 8502` |

---

## 🛠️ Technologies Used

| Component | Technology |
|---|---|
| Signal Classification | TensorFlow CNN (1D Conv) |
| Threat Detection | Scikit-learn Isolation Forest |
| Network Scanning | Scapy ARP + psutil |
| Packet Monitoring | Scapy sniff() |
| Bluetooth Detection | bleak (BLE) + pybluez (Classic) |
| Dashboard | Streamlit |
| Visualization | Matplotlib + Seaborn |
| Dataset | RadioML 2018.01A |

---

## 📊 Expected Demo Output

```
WiFi Communication:
  Device A (Phone):   192.168.1.10  Android-Phone
  Device B (Laptop):  192.168.1.5   MY-LAPTOP
  Status:             ● ACTIVE
  Packets:            1,247
  Data:               3.2 MB
  Duration:           45s
  Protocols:          TCP/443, UDP/53, ICMP

Bluetooth:
  Device:  Samsung Galaxy S23
  Address: AA:BB:CC:DD:EE:FF
  RSSI:    -54 dBm (Excellent)
  Status:  Connected
  
Anomaly Detection:
  Score:   -0.0312 (Normal)
  Status:  ✓ No threats
```
=======
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
>>>>>>> 4029fccbc2c9831190aad2b4675e779dcfd57eda
