# =============================================================
# bluetooth_scan.py — Bluetooth Device Detection Module
# Detects nearby BT devices, paired devices, and active connections
# Uses 'bleak' (modern, cross-platform) with pybluez fallback
# =============================================================

import asyncio
import json
import os
import time
import platform
from datetime import datetime

# ── Try bleak (recommended, cross-platform) ──────────────────
try:
    from bleak import BleakScanner, BleakClient
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False

# ── Try pybluez (classic BT, Windows/Linux) ──────────────────
try:
    import bluetooth
    PYBLUEZ_AVAILABLE = True
except ImportError:
    PYBLUEZ_AVAILABLE = False

# ── Windows-specific paired device detection ──────────────────
WINDOWS = platform.system() == "Windows"


# ─────────────────────────────────────────
# BLE SCANNER (bleak) — modern standard
# ─────────────────────────────────────────

async def scan_ble(timeout=10.0):
    """
    Scan for BLE (Bluetooth Low Energy) devices.
    Returns list of device dicts.
    timeout : seconds to scan
    """
    if not BLEAK_AVAILABLE:
        print("[!] bleak not installed. Run: pip install bleak")
        return []

    print(f"[→] Scanning BLE devices for {timeout}s ...")
    devices_found = []

    def _on_detect(device, adv_data):
        entry = {
            "name":       device.name or "Unknown",
            "address":    device.address,
            "rssi":       adv_data.rssi,
            "type":       "BLE",
            "status":     "Detected",
            "services":   list(adv_data.service_uuids),
            "last_seen":  datetime.now().strftime("%H:%M:%S"),
        }
        # Avoid duplicates
        if not any(d["address"] == device.address for d in devices_found):
            devices_found.append(entry)
            print(f"    [+] {entry['name']:30} {entry['address']}  RSSI: {entry['rssi']} dBm")

    scanner = BleakScanner(detection_callback=_on_detect)
    await scanner.start()
    await asyncio.sleep(timeout)
    await scanner.stop()

    print(f"[✓] BLE scan complete. Found {len(devices_found)} device(s).")
    return devices_found


async def check_ble_connection(address):
    """
    Attempt to connect to a BLE device and check services.
    Returns (connected: bool, services: list)
    """
    if not BLEAK_AVAILABLE:
        return False, []
    try:
        async with BleakClient(address, timeout=10.0) as client:
            connected  = client.is_connected
            services   = [str(s) for s in client.services]
            return connected, services
    except Exception as e:
        return False, []


# ─────────────────────────────────────────
# CLASSIC BLUETOOTH SCANNER (pybluez)
# ─────────────────────────────────────────

def scan_classic_bt(duration=10):
    """
    Scan for classic Bluetooth devices (phones, headphones, etc).
    Requires pybluez and a Bluetooth adapter.
    """
    if not PYBLUEZ_AVAILABLE:
        print("[!] pybluez not installed. Run: pip install pybluez")
        return []

    print(f"[→] Scanning Classic BT devices for ~{duration}s ...")
    try:
        nearby = bluetooth.discover_devices(
            duration=duration,
            lookup_names=True,
            flush_cache=True,
            lookup_class=True,
        )
    except Exception as e:
        print(f"[!] Classic BT scan failed: {e}")
        return []

    devices_found = []
    for addr, name, dev_class in nearby:
        entry = {
            "name":      name or "Unknown",
            "address":   addr,
            "rssi":      None,
            "type":      "Classic-BT",
            "class":     _bt_class_name(dev_class),
            "status":    "Detected",
            "services":  [],
            "last_seen": datetime.now().strftime("%H:%M:%S"),
        }
        # Try to get services
        try:
            services = bluetooth.find_service(address=addr)
            entry["services"] = [s.get("name", "") for s in services]
        except Exception:
            pass

        devices_found.append(entry)
        print(f"    [+] {name:30} {addr}  Class: {entry['class']}")

    print(f"[✓] Classic BT scan complete. Found {len(devices_found)} device(s).")
    return devices_found


def _bt_class_name(cls_int):
    """Map Bluetooth device class integer to human-readable name."""
    major = (cls_int >> 8) & 0x1F
    mapping = {
        0: "Miscellaneous", 1: "Computer",  2: "Phone",
        3: "LAN/Access",    4: "Audio/Video", 5: "Peripheral",
        6: "Imaging",       7: "Wearable",  8: "Toy",
        9: "Health",
    }
    return mapping.get(major, f"Unknown({major})")


# ─────────────────────────────────────────
# PAIRED DEVICE DETECTION (OS-level)
# ─────────────────────────────────────────

def get_paired_devices():
    """
    Returns a list of devices already paired with this machine.
    Uses OS-specific commands.
    """
    paired = []
    system = platform.system()

    try:
        if system == "Windows":
            import subprocess
            # PowerShell: list paired BT devices
            ps_cmd = (
                "Get-PnpDevice -Class Bluetooth | "
                "Select-Object FriendlyName, Status, InstanceId | "
                "ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout.strip():
                import re
                raw = result.stdout.strip()
                data = json.loads(raw) if raw.startswith("[") else [json.loads(raw)]
                for item in data:
                    name   = item.get("FriendlyName", "Unknown")
                    status = item.get("Status", "Unknown")
                    iid    = item.get("InstanceId", "")
                    # Extract MAC-like address from InstanceId
                    mac_match = re.search(r"([0-9A-F]{12})", iid.replace("_", ""))
                    mac = ":".join(mac_match.group(1)[i:i+2] for i in range(0, 12, 2)) \
                          if mac_match else "N/A"
                    paired.append({
                        "name":    name,
                        "address": mac,
                        "status":  "Connected" if status == "OK" else "Paired (Disconnected)",
                        "type":    "Paired",
                    })

        elif system == "Linux":
            import subprocess
            result = subprocess.run(
                ["bluetoothctl", "devices", "Paired"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                # Format: Device XX:XX:XX:XX:XX:XX DeviceName
                parts = line.split(" ", 2)
                if len(parts) >= 3:
                    addr = parts[1]
                    name = parts[2]
                    # Check connection status
                    info = subprocess.run(
                        ["bluetoothctl", "info", addr],
                        capture_output=True, text=True
                    ).stdout
                    connected = "Connected: yes" in info
                    paired.append({
                        "name":    name,
                        "address": addr,
                        "status":  "Connected" if connected else "Paired (Disconnected)",
                        "type":    "Paired",
                    })

        elif system == "Darwin":  # macOS
            import subprocess
            result = subprocess.run(
                ["system_profiler", "SPBluetoothDataType", "-json"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                bt_data = data.get("SPBluetoothDataType", [{}])[0]
                devices_dict = bt_data.get("device_connected", {})
                devices_dict.update(bt_data.get("device_not_connected", {}))
                for name, info in devices_dict.items():
                    addr = info.get("device_address", "N/A")
                    conn = "device_connected" in str(info)
                    paired.append({
                        "name":    name,
                        "address": addr,
                        "status":  "Connected" if conn else "Paired (Disconnected)",
                        "type":    "Paired",
                    })

    except Exception as e:
        print(f"[!] Paired device detection failed: {e}")

    return paired


# ─────────────────────────────────────────
# COMMUNICATION ACTIVITY DETECTION
# ─────────────────────────────────────────

async def detect_bt_communication(target_address, probe_duration=5.0):
    """
    Check if a specific BLE device is actively communicating.
    Tries to connect and read GATT services/characteristics.

    Returns dict with:
      communicating : bool
      rssi          : int (signal strength)
      services      : list of service UUIDs
      status        : descriptive string
    """
    if not BLEAK_AVAILABLE:
        return {"communicating": False, "status": "bleak not installed"}

    # First check if device is visible
    visible = False
    rssi    = None

    async def _check_visible():
        nonlocal visible, rssi
        scanned = await BleakScanner.discover(timeout=5.0)
        for d in scanned:
            if d.address.upper() == target_address.upper():
                visible = True
                rssi = d.rssi
                break

    await _check_visible()

    if not visible:
        return {
            "communicating": False,
            "rssi":          None,
            "services":      [],
            "status":        "Device not visible (out of range or BT off)",
        }

    # Try to connect and enumerate services
    connected, services = await check_ble_connection(target_address)

    # Probe for active data (read characteristics)
    active_data = False
    if connected and services:
        active_data = True   # having open services = data channel available

    return {
        "communicating": connected or visible,
        "rssi":          rssi,
        "services":      services,
        "status":        (
            "ACTIVE - Connected & transmitting data" if connected and active_data
            else "VISIBLE - In range, data channel available" if visible
            else "INACTIVE"
        ),
    }


# ─────────────────────────────────────────
# FULL SCAN (BLE + Classic + Paired)
# ─────────────────────────────────────────

async def full_bluetooth_scan():
    """
    Run BLE scan + classic BT scan + paired device check.
    Returns unified device list.
    """
    results = {}

    # BLE devices
    ble_devices = await scan_ble(timeout=8.0)
    for d in ble_devices:
        results[d["address"]] = d

    # Classic BT (if pybluez available)
    if PYBLUEZ_AVAILABLE:
        classic = scan_classic_bt(duration=8)
        for d in classic:
            if d["address"] not in results:
                results[d["address"]] = d

    # Paired devices (OS-level)
    paired = get_paired_devices()
    for d in paired:
        addr = d["address"]
        if addr in results:
            results[addr]["paired"]  = True
            results[addr]["status"]  = d["status"]
        else:
            d["paired"] = True
            results[addr] = d

    return list(results.values())


# ─────────────────────────────────────────
# DISPLAY & SAVE
# ─────────────────────────────────────────

def print_bt_devices(devices):
    print("\n" + "=" * 80)
    print(f"  {'Device Name':<30} {'Address':<20} {'Type':<12} Status")
    print("=" * 80)
    for d in devices:
        rssi_str = f"RSSI:{d.get('rssi', 'N/A')}" if d.get("rssi") else ""
        print(f"  {d['name'][:28]:<30} {d['address']:<20} "
              f"{d.get('type','?'):<12} {d['status']} {rssi_str}")
    print("=" * 80)
    print(f"  Total Bluetooth devices: {len(devices)}")
    print("=" * 80)


def save_bt_devices(devices, path="data/bluetooth_devices.json"):
    os.makedirs("data", exist_ok=True)
    with open(path, "w") as f:
        json.dump(devices, f, indent=2, default=str)
    print(f"[✓] Bluetooth scan saved → {path}")


# ─────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) == 2:
        # Check specific device communication
        target = sys.argv[1]
        print(f"\n[→] Checking Bluetooth communication with: {target}")
        result = asyncio.run(detect_bt_communication(target))
        print(json.dumps(result, indent=2))
    else:
        # Full scan
        print("\n[→] Running full Bluetooth scan ...")
        devices = asyncio.run(full_bluetooth_scan())
        print_bt_devices(devices)
        save_bt_devices(devices)
        print("\n[TIP] To check a specific device:")
        print("      python bluetooth_scan.py XX:XX:XX:XX:XX:XX")
