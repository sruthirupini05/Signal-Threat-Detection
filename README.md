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
