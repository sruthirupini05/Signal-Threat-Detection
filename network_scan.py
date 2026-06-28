# =============================================================
# network_scan.py — WiFi Device Discovery Module
# Detects all devices on the same local network
# Run locally (requires Npcap on Windows, root on Linux/Mac)
# =============================================================

import socket
import subprocess
import platform
import re
import json
import time
import ipaddress
from datetime import datetime

try:
    import psutil
except ImportError:
    psutil = None

try:
    from scapy.all import ARP, Ether, srp, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ─────────────────────────────────────────
# HELPER: Get local machine info
# ─────────────────────────────────────────

def get_local_ip():
    """Return the local machine's IP on the active network."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def get_network_range(local_ip=None):
    """Return CIDR network range e.g. 192.168.1.0/24"""
    ip = local_ip or get_local_ip()
    parts = ip.rsplit(".", 1)
    return f"{parts[0]}.0/24"


def get_own_mac():
    """Return the MAC of the active interface."""
    if psutil is None:
        return "Unknown"
    local_ip = get_local_ip()
    for iface, addrs in psutil.net_if_addrs().items():
        ip_match = any(a.address == local_ip for a in addrs
                       if a.family == socket.AF_INET)
        if ip_match:
            for a in addrs:
                if a.family == psutil.AF_LINK:
                    return a.address.upper()
    return "Unknown"


# ─────────────────────────────────────────
# METHOD 1: ARP Scan via Scapy (most accurate)
# ─────────────────────────────────────────

def arp_scan(network_range=None):
    """
    Send ARP broadcast to discover all hosts on the subnet.
    Requires scapy + Npcap (Windows) or root (Linux/Mac).
    """
    if not SCAPY_AVAILABLE:
        print("[!] Scapy not available. Falling back to ARP table scan.")
        return []

    target = network_range or get_network_range()
    print(f"[→] ARP scanning {target} ...")

    conf.verb = 0  # suppress scapy output
    arp_req  = ARP(pdst=target)
    ether    = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet   = ether / arp_req

    answered, _ = srp(packet, timeout=3, retry=1)

    devices = []
    for sent, recv in answered:
        hostname = _resolve_hostname(recv.psrc)
        devices.append({
            "ip":       recv.psrc,
            "mac":      recv.hwsrc.upper(),
            "hostname": hostname,
            "method":   "ARP",
            "status":   "Connected",
            "last_seen": datetime.now().strftime("%H:%M:%S"),
        })

    return devices


# ─────────────────────────────────────────
# METHOD 2: ARP Table (no scapy needed)
# ─────────────────────────────────────────

def read_arp_table():
    """
    Parse the OS ARP cache — works without scapy or root.
    Returns list of {ip, mac} dicts.
    """
    devices = []
    system  = platform.system()

    try:
        if system == "Windows":
            out = subprocess.check_output("arp -a", shell=True).decode(errors="ignore")
            pattern = r"(\d+\.\d+\.\d+\.\d+)\s+([\w-]+(?::[\w-]+){5})"
            for ip, mac in re.findall(pattern, out):
                if not ip.endswith(".255") and not ip.startswith("224."):
                    mac_clean = mac.replace("-", ":").upper()
                    devices.append({
                        "ip":       ip,
                        "mac":      mac_clean,
                        "hostname": _resolve_hostname(ip),
                        "method":   "ARP-Table",
                        "status":   "Connected",
                        "last_seen": datetime.now().strftime("%H:%M:%S"),
                    })
        else:  # Linux / Mac
            out = subprocess.check_output(["arp", "-n"], stderr=subprocess.DEVNULL).decode()
            pattern = r"(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([\w:]+)"
            for ip, mac in re.findall(pattern, out):
                if mac != "00:00:00:00:00:00" and mac != "<incomplete>":
                    devices.append({
                        "ip":       ip,
                        "mac":      mac.upper(),
                        "hostname": _resolve_hostname(ip),
                        "method":   "ARP-Table",
                        "status":   "Connected",
                        "last_seen": datetime.now().strftime("%H:%M:%S"),
                    })
    except Exception as e:
        print(f"[!] ARP table read failed: {e}")

    return devices


# ─────────────────────────────────────────
# METHOD 3: Ping sweep (populate ARP cache)
# ─────────────────────────────────────────

def ping_sweep(network_range=None):
    """
    Ping every host in the subnet to populate ARP cache.
    Then read_arp_table() will find them.
    Fast because pings run in parallel via subprocess.
    """
    local_ip = get_local_ip()
    base = ".".join(local_ip.split(".")[:3])
    system = platform.system()
    print(f"[→] Ping sweeping {base}.1-254 ...")

    procs = []
    for i in range(1, 255):
        ip = f"{base}.{i}"
        if system == "Windows":
            cmd = ["ping", "-n", "1", "-w", "300", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]
        procs.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL))

    # Wait for all pings (max 5 seconds)
    for p in procs:
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()

    print("[✓] Ping sweep complete")


# ─────────────────────────────────────────
# HOSTNAME RESOLVER
# ─────────────────────────────────────────

_hostname_cache = {}

def _resolve_hostname(ip):
    if ip in _hostname_cache:
        return _hostname_cache[ip]
    try:
        name = socket.gethostbyaddr(ip)[0]
    except Exception:
        name = ip
    _hostname_cache[ip] = name
    return name


# ─────────────────────────────────────────
# MAIN SCAN FUNCTION (combines all methods)
# ─────────────────────────────────────────

def scan_network(use_ping_sweep=False):
    """
    Full network scan. Returns deduplicated list of devices.
    """
    local_ip  = get_local_ip()
    local_mac = get_own_mac()

    print(f"\n[✓] Local Machine  IP : {local_ip}")
    print(f"[✓] Local Machine MAC : {local_mac}")
    print(f"[✓] Network Range     : {get_network_range(local_ip)}\n")

    devices = {}

    # Step 1: Try ARP scan (most reliable)
    if SCAPY_AVAILABLE:
        for d in arp_scan():
            devices[d["ip"]] = d

    # Step 2: Optionally ping sweep to populate ARP cache
    if use_ping_sweep or not SCAPY_AVAILABLE:
        ping_sweep()

    # Step 3: Read ARP table (catches anything missed)
    for d in read_arp_table():
        if d["ip"] not in devices:
            devices[d["ip"]] = d

    # Add self
    devices[local_ip] = {
        "ip":       local_ip,
        "mac":      local_mac,
        "hostname": socket.gethostname(),
        "method":   "Self",
        "status":   "Connected (This Device)",
        "last_seen": datetime.now().strftime("%H:%M:%S"),
    }

    result = list(devices.values())
    result.sort(key=lambda d: tuple(int(x) for x in d["ip"].split(".")))
    return result


# ─────────────────────────────────────────
# DISPLAY
# ─────────────────────────────────────────

def print_devices(devices):
    print("\n" + "=" * 70)
    print(f"  {'IP Address':<18} {'MAC Address':<20} {'Hostname':<22} Status")
    print("=" * 70)
    for d in devices:
        print(f"  {d['ip']:<18} {d['mac']:<20} {d['hostname'][:20]:<22} {d['status']}")
    print("=" * 70)
    print(f"  Total devices found: {len(devices)}")
    print("=" * 70)


def save_devices(devices, path="data/devices.json"):
    import os
    os.makedirs("data", exist_ok=True)
    with open(path, "w") as f:
        json.dump(devices, f, indent=2)
    print(f"[✓] Device list saved → {path}")


# ─────────────────────────────────────────
# CONTINUOUS MONITOR MODE
# ─────────────────────────────────────────

def monitor_loop(interval=30):
    """
    Repeatedly scan and detect new/missing devices.
    """
    known = {}
    print(f"[→] Starting continuous network monitor (every {interval}s) ...")
    while True:
        current = {d["ip"]: d for d in scan_network()}

        # Detect new devices
        for ip, dev in current.items():
            if ip not in known:
                print(f"[+] NEW DEVICE    : {dev['hostname']} ({ip}) [{dev['mac']}]")

        # Detect disconnected devices
        for ip, dev in known.items():
            if ip not in current:
                print(f"[-] DISCONNECTED  : {dev['hostname']} ({ip}) [{dev['mac']}]")

        known = current
        print_devices(list(current.values()))
        save_devices(list(current.values()))
        print(f"\n[→] Next scan in {interval}s ...\n")
        time.sleep(interval)


# ─────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────

if __name__ == "__main__":
    import sys
    mode = sys.argv[1] if len(sys.argv) > 1 else "once"

    if mode == "monitor":
        monitor_loop(interval=30)
    else:
        devices = scan_network(use_ping_sweep=True)
        print_devices(devices)
        save_devices(devices)
