# =============================================================
# communication_monitor.py — WiFi Communication Detection
# Monitors whether two specific devices are exchanging packets
# Run locally with admin/root privileges
# =============================================================

import time
import json
import threading
import os
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not installed. Run: pip install scapy")

# ─────────────────────────────────────────
# SHARED STATE (thread-safe via lock)
# ─────────────────────────────────────────

_lock   = threading.Lock()
_state  = defaultdict(lambda: {
    "packet_count":   0,
    "bytes_total":    0,
    "protocols":      defaultdict(int),
    "first_seen":     None,
    "last_seen":      None,
    "active":         False,
    "sessions":       [],
})

# Key format: tuple(sorted([ip_a, ip_b]))
# So (A→B) and (B→A) are merged into one entry


def _pair_key(ip_a, ip_b):
    return tuple(sorted([ip_a, ip_b]))


# ─────────────────────────────────────────
# PACKET HANDLER
# ─────────────────────────────────────────

_watched_pairs = set()   # set of _pair_key tuples to watch
_capture_all   = False   # if True, capture all pairs


def packet_handler(pkt):
    """Called for every captured packet. Updates _state."""
    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    key = _pair_key(src, dst)

    if not _capture_all and key not in _watched_pairs:
        return

    size = len(pkt)
    proto = "OTHER"
    if pkt.haslayer(TCP):
        proto = f"TCP/{pkt[TCP].dport}"
    elif pkt.haslayer(UDP):
        proto = f"UDP/{pkt[UDP].dport}"
    elif pkt.haslayer(ICMP):
        proto = "ICMP"

    now = datetime.now().strftime("%H:%M:%S")

    with _lock:
        entry = _state[key]
        entry["packet_count"]  += 1
        entry["bytes_total"]   += size
        entry["protocols"][proto] += 1
        entry["last_seen"]      = now
        entry["active"]         = True

        if entry["first_seen"] is None:
            entry["first_seen"] = now
            entry["sessions"].append({"start": now, "end": None})
        elif entry["sessions"]:
            entry["sessions"][-1]["end"] = now


# ─────────────────────────────────────────
# ACTIVITY DECAY (mark inactive after timeout)
# ─────────────────────────────────────────

def _decay_loop(timeout=10):
    """Mark a pair inactive if no packet seen in `timeout` seconds."""
    last_counts = {}
    while True:
        time.sleep(timeout)
        with _lock:
            for key, entry in _state.items():
                prev = last_counts.get(key, 0)
                curr = entry["packet_count"]
                if curr == prev and entry["active"]:
                    entry["active"] = False
                    if entry["sessions"] and entry["sessions"][-1]["end"] is None:
                        entry["sessions"][-1]["end"] = datetime.now().strftime("%H:%M:%S")
                last_counts[key] = curr


# ─────────────────────────────────────────
# SNIFFER THREAD
# ─────────────────────────────────────────

_sniffer_thread = None
_stop_event     = threading.Event()


def start_capture(ip_pairs=None, iface=None, capture_all=False):
    """
    Start packet capture in a background thread.

    Parameters
    ----------
    ip_pairs : list of (ip_a, ip_b) tuples to watch. None = watch all.
    iface    : network interface name. None = auto-detect.
    capture_all : if True, capture every IP pair (builds traffic map).
    """
    global _sniffer_thread, _capture_all

    if not SCAPY_AVAILABLE:
        print("[!] Scapy required. pip install scapy")
        return

    _capture_all = capture_all

    if ip_pairs:
        for a, b in ip_pairs:
            _watched_pairs.add(_pair_key(a, b))
        print(f"[✓] Watching {len(_watched_pairs)} IP pair(s): {list(_watched_pairs)}")
    else:
        _capture_all = True
        print("[✓] Capturing ALL traffic (any pair)")

    # BPF filter: only IP packets (faster)
    bpf = "ip"

    # Interface selection
    if iface is None:
        iface = _auto_iface()
    print(f"[✓] Interface: {iface}")

    conf.verb = 0

    def _run():
        sniff(
            iface=iface,
            filter=bpf,
            prn=packet_handler,
            store=False,
            stop_filter=lambda p: _stop_event.is_set(),
        )

    _stop_event.clear()
    _sniffer_thread = threading.Thread(target=_run, daemon=True, name="Sniffer")
    _sniffer_thread.start()

    decay_t = threading.Thread(target=_decay_loop, args=(10,), daemon=True)
    decay_t.start()

    print("[✓] Capture started. Call get_status(ip_a, ip_b) to check communication.\n")


def stop_capture():
    _stop_event.set()
    print("[✓] Capture stopped.")


def _auto_iface():
    """Pick the best interface automatically."""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        import psutil
        for iface, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and a.address == local_ip:
                    return iface
    except Exception:
        pass

    ifaces = get_if_list()
    preferred = [i for i in ifaces if any(k in i.lower()
                 for k in ["eth", "wlan", "wi-fi", "en0", "en1"])]
    return preferred[0] if preferred else ifaces[0]


# ─────────────────────────────────────────
# PUBLIC QUERY API
# ─────────────────────────────────────────

def get_status(ip_a, ip_b):
    """
    Return communication status between ip_a and ip_b.

    Returns dict with:
      status        : "ACTIVE" | "INACTIVE" | "NO_DATA"
      packet_count  : int
      bytes_total   : int (bytes)
      protocols     : dict of protocol → count
      duration_secs : float (approx session time)
      first_seen    : str
      last_seen     : str
    """
    key = _pair_key(ip_a, ip_b)
    with _lock:
        entry = dict(_state[key])

    if entry["packet_count"] == 0:
        return {
            "status":       "NO_DATA",
            "packet_count": 0,
            "bytes_total":  0,
            "protocols":    {},
            "duration_secs": 0,
            "first_seen":   None,
            "last_seen":    None,
        }

    # Calculate duration from sessions
    total_secs = 0.0
    for sess in entry["sessions"]:
        if sess["start"] and sess["end"]:
            fmt = "%H:%M:%S"
            try:
                t0 = datetime.strptime(sess["start"], fmt)
                t1 = datetime.strptime(sess["end"],   fmt)
                total_secs += (t1 - t0).total_seconds()
            except Exception:
                pass

    return {
        "status":        "ACTIVE" if entry["active"] else "INACTIVE",
        "packet_count":  entry["packet_count"],
        "bytes_total":   entry["bytes_total"],
        "bytes_human":   _fmt_bytes(entry["bytes_total"]),
        "protocols":     dict(entry["protocols"]),
        "duration_secs": total_secs,
        "first_seen":    entry["first_seen"],
        "last_seen":     entry["last_seen"],
        "sessions":      entry["sessions"],
    }


def get_all_pairs():
    """Return status for every observed IP pair."""
    with _lock:
        keys = list(_state.keys())
    return {f"{k[0]} ↔ {k[1]}": get_status(k[0], k[1]) for k in keys}


def _fmt_bytes(n):
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


# ─────────────────────────────────────────
# SAVE SNAPSHOT
# ─────────────────────────────────────────

def save_snapshot(path="data/traffic_snapshot.json"):
    os.makedirs("data", exist_ok=True)
    data = get_all_pairs()
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"[✓] Snapshot saved → {path}")


# ─────────────────────────────────────────
# STANDALONE DEMO / ENTRY POINT
# ─────────────────────────────────────────

def _demo(ip_a, ip_b):
    print(f"\n[DEMO] Monitoring communication: {ip_a} ↔ {ip_b}")
    print("       Generate traffic (ping / file transfer) between these devices.\n")

    start_capture(ip_pairs=[(ip_a, ip_b)])

    try:
        while True:
            time.sleep(5)
            status = get_status(ip_a, ip_b)
            tag = "🟢 ACTIVE" if status["status"] == "ACTIVE" else "🔴 INACTIVE"
            print(f"  [{datetime.now().strftime('%H:%M:%S')}] {tag} | "
                  f"Packets: {status['packet_count']:>6} | "
                  f"Data: {status['bytes_human']:>10} | "
                  f"Protocols: {status['protocols']}")
    except KeyboardInterrupt:
        stop_capture()
        save_snapshot()
        print("\n[✓] Monitoring stopped.")


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 3:
        _demo(sys.argv[1], sys.argv[2])
    else:
        print("Usage: python communication_monitor.py <IP_A> <IP_B>")
        print("Example: python communication_monitor.py 192.168.1.10 192.168.1.5")
