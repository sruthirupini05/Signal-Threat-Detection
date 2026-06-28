# =============================================================
# app.py — Real-Time Signal Intelligence Dashboard (Streamlit)
# =============================================================
# Run: streamlit run app.py
# =============================================================

import streamlit as st
import pandas as pd
import numpy as np
import asyncio
import threading
import time
import json
import os
import pickle
from datetime import datetime
from collections import deque
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.ticker as ticker

# ── Local modules (safe imports — app won't crash if a module fails) ──────────
_import_errors = []

try:
    from network_scan import scan_network, get_local_ip
    _HAS_NETWORK = True
except Exception as _e:
    _import_errors.append(f"network_scan: {_e}")
    _HAS_NETWORK = False
    def scan_network(**kw): return []
    def get_local_ip(): return "127.0.0.1"

try:
    from communication_monitor import start_capture, stop_capture, get_status, get_all_pairs
    _HAS_MONITOR = True
except Exception as _e:
    _import_errors.append(f"communication_monitor: {_e}")
    _HAS_MONITOR = False
    def start_capture(**kw): pass
    def stop_capture(): pass
    def get_status(a, b): return {"status":"NO_DATA","packet_count":0,"bytes_total":0,
                                   "bytes_human":"0 B","protocols":{},"duration_secs":0,
                                   "first_seen":None,"last_seen":None,"sessions":[]}
    def get_all_pairs(): return {}

try:
    from bluetooth_scan import full_bluetooth_scan, get_paired_devices
    _HAS_BT = True
except Exception as _e:
    _import_errors.append(f"bluetooth_scan: {_e}")
    _HAS_BT = False
    async def full_bluetooth_scan(): return []
    def get_paired_devices(): return []

try:
    from anomaly_detection import load_or_create_detector, AlertManager, push_observation
    _HAS_ANOMALY = True
except Exception as _e:
    _import_errors.append(f"anomaly_detection: {_e}")
    _HAS_ANOMALY = False
    def load_or_create_detector(): return None
    def push_observation(k, s): pass
    class AlertManager:
        def __init__(self, **kw): self.alert_log = []
        def maybe_alert(self, k, p): return None
        def recent_alerts(self, n=10): return []

# ─────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────

st.set_page_config(
    page_title="Signal Intelligence",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────
# CUSTOM CSS — Dark Cyberpunk Theme
# ─────────────────────────────────────────

st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700&display=swap');

  /* ── Root ── */
  html, body, [class*="css"] {
    font-family: 'Exo 2', sans-serif;
    background-color: #050a0e !important;
    color: #c8d8e8 !important;
  }

  /* ── Sidebar ── */
  section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0a1520 0%, #050a0e 100%);
    border-right: 1px solid #0e3a5c;
  }

  /* ── Metric cards ── */
  div[data-testid="metric-container"] {
    background: linear-gradient(135deg, #0a1520 0%, #0d1f30 100%);
    border: 1px solid #0e3a5c;
    border-radius: 8px;
    padding: 14px 18px;
    box-shadow: 0 0 12px rgba(0,150,255,0.08);
  }
  div[data-testid="metric-container"] label {
    color: #5a8ab0 !important;
    font-size: 11px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    font-family: 'Share Tech Mono', monospace;
  }
  div[data-testid="metric-container"] div[data-testid="stMetricValue"] {
    color: #00d4ff !important;
    font-size: 28px;
    font-weight: 700;
    font-family: 'Share Tech Mono', monospace;
  }

  /* ── Status badges ── */
  .badge-active   { background:#003d1a; color:#00ff88; border:1px solid #00ff88;
                    border-radius:4px; padding:2px 10px; font-family:'Share Tech Mono',monospace; }
  .badge-inactive { background:#2a0a0a; color:#ff4444; border:1px solid #ff4444;
                    border-radius:4px; padding:2px 10px; font-family:'Share Tech Mono',monospace; }
  .badge-warning  { background:#2a1a00; color:#ffaa00; border:1px solid #ffaa00;
                    border-radius:4px; padding:2px 10px; font-family:'Share Tech Mono',monospace; }

  /* ── Section headers ── */
  .section-header {
    font-family: 'Share Tech Mono', monospace;
    font-size: 13px;
    letter-spacing: 3px;
    color: #5a8ab0;
    text-transform: uppercase;
    border-bottom: 1px solid #0e3a5c;
    padding-bottom: 6px;
    margin-bottom: 16px;
    margin-top: 8px;
  }

  /* ── Alert box ── */
  .alert-critical { background:#1a0000; border:1px solid #ff0000;
                    border-left:4px solid #ff0000; border-radius:6px;
                    padding:12px 16px; margin:8px 0;
                    font-family:'Share Tech Mono',monospace; color:#ff4444; }
  .alert-high     { background:#1a0800; border:1px solid #ff6600;
                    border-left:4px solid #ff6600; border-radius:6px;
                    padding:12px 16px; margin:8px 0;
                    font-family:'Share Tech Mono',monospace; color:#ff8844; }
  .alert-medium   { background:#1a1000; border:1px solid #ffaa00;
                    border-left:4px solid #ffaa00; border-radius:6px;
                    padding:12px 16px; margin:8px 0;
                    font-family:'Share Tech Mono',monospace; color:#ffcc55; }
  .alert-low      { background:#001a08; border:1px solid #00aa44;
                    border-left:4px solid #00aa44; border-radius:6px;
                    padding:12px 16px; margin:8px 0;
                    font-family:'Share Tech Mono',monospace; color:#00dd66; }

  /* ── Dataframe ── */
  .stDataFrame { background:#0a1520 !important; }

  /* ── Buttons ── */
  .stButton>button {
    background: transparent;
    border: 1px solid #0e3a5c;
    color: #00d4ff;
    font-family: 'Share Tech Mono', monospace;
    letter-spacing: 1px;
    transition: all 0.2s;
  }
  .stButton>button:hover {
    border-color: #00d4ff;
    box-shadow: 0 0 10px rgba(0,212,255,0.3);
  }

  /* ── Tabs ── */
  .stTabs [data-baseweb="tab"] {
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px;
    letter-spacing: 1px;
    color: #5a8ab0;
  }
  .stTabs [aria-selected="true"] { color: #00d4ff !important; }
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────
# STARTUP DIAGNOSTICS
# ─────────────────────────────────────────
if _import_errors:
    st.warning("⚠️ Some modules failed to import (see details below). "
               "Core dashboard still works.")
    with st.expander("🔧 Import Errors — click to fix"):
        for err in _import_errors:
            st.code(err)
        st.markdown("""
**How to fix:**
```bash
pip install scapy psutil bleak scikit-learn
```
On Windows also install **Npcap** from https://npcap.com
        """)

# ─────────────────────────────────────────
# SESSION STATE INIT
# ─────────────────────────────────────────

def _init_state():
    defaults = {
        "capture_running":  False,
        "devices":          [],
        "bt_devices":       [],
        "alerts":           deque(maxlen=50),
        "traffic_history":  {},   # pair_key → deque of (timestamp, packet_count, bytes)
        "detector":         None,
        "alert_manager":    None,
        "ip_a":             "",
        "ip_b":             "",
        "refresh_count":    0,
        "scan_done":        False,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

_init_state()


# ─────────────────────────────────────────
# MATPLOTLIB STYLE
# ─────────────────────────────────────────

plt.rcParams.update({
    "figure.facecolor":  "#0a1520",
    "axes.facecolor":    "#050a0e",
    "axes.edgecolor":    "#0e3a5c",
    "axes.labelcolor":   "#5a8ab0",
    "axes.titlecolor":   "#00d4ff",
    "xtick.color":       "#5a8ab0",
    "ytick.color":       "#5a8ab0",
    "grid.color":        "#0e3a5c",
    "grid.linestyle":    "--",
    "grid.alpha":        0.5,
    "text.color":        "#c8d8e8",
    "font.family":       "monospace",
    "figure.dpi":        120,
})


def _fig(*args, **kwargs):
    fig, ax = plt.subplots(*args, **kwargs)
    fig.patch.set_facecolor("#0a1520")
    if isinstance(ax, np.ndarray):
        for a in ax.flat:
            a.set_facecolor("#050a0e")
    else:
        ax.set_facecolor("#050a0e")
    return fig, ax


# ─────────────────────────────────────────
# SIDEBAR — CONTROLS
# ─────────────────────────────────────────

with st.sidebar:
    st.markdown("## 📡 Signal Intelligence")
    st.markdown("---")

    # ── Network Scan ──
    st.markdown('<div class="section-header">Network Scanner</div>', unsafe_allow_html=True)

    if st.button("🔍 Scan Network", use_container_width=True):
        with st.spinner("Scanning local network..."):
            try:
                st.session_state.devices   = scan_network(use_ping_sweep=False)
                st.session_state.scan_done = True
                st.success(f"Found {len(st.session_state.devices)} device(s)")
            except Exception as _ex:
                st.error(f"Scan error: {_ex}")

    # ── Device Selection ──
    st.markdown("---")
    st.markdown('<div class="section-header">Device IPs</div>', unsafe_allow_html=True)
    st.caption("Type IPs directly — no scan needed")

    _default_a = st.session_state.get("ip_a", "") or get_local_ip()
    _default_b = st.session_state.get("ip_b", "")

    if st.session_state.devices and len(st.session_state.devices) > 1:
        ips       = [d["ip"] for d in st.session_state.devices]
        hostnames = [f"{d['ip']}  ({d['hostname'][:12]})" for d in st.session_state.devices]
        st.markdown("**Pick from scan (optional):**")
        idx_a = st.selectbox("Device A (scan)", range(len(ips)),
                             format_func=lambda i: hostnames[i], key="sel_a")
        idx_b = st.selectbox("Device B (scan)", range(len(ips)),
                             format_func=lambda i: hostnames[i],
                             index=min(1, len(ips)-1), key="sel_b")
        _default_a = ips[idx_a]
        _default_b = ips[idx_b]

    ip_a_input = st.text_input("Device A IP (your laptop)", value=_default_a, key="ip_a_input")
    ip_b_input = st.text_input("Device B IP (your phone)",  value=_default_b, key="ip_b_input")
    st.session_state.ip_a = ip_a_input.strip()
    st.session_state.ip_b = ip_b_input.strip()

    try:
        _my_ip = get_local_ip()
        st.caption(f"This laptop's IP: {_my_ip}")
    except Exception:
        pass

    st.markdown("---")

    # ── Capture Controls ──
    st.markdown('<div class="section-header">Packet Capture</div>', unsafe_allow_html=True)

    iface_input = st.text_input("Interface (blank=auto)", "")

    col_start, col_stop = st.columns(2)
    with col_start:
        if st.button("▶ Start", use_container_width=True):
            if not st.session_state.capture_running:
                try:
                    ip_a = st.session_state.ip_a
                    ip_b = st.session_state.ip_b
                    iface = iface_input.strip() or None
                    start_capture(ip_pairs=[(ip_a, ip_b)], iface=iface)
                    st.session_state.capture_running = True
                    if st.session_state.detector is None and _HAS_ANOMALY:
                        st.session_state.detector     = load_or_create_detector()
                        st.session_state.alert_manager = AlertManager(cooldown_secs=30)
                    st.success("Capture started!")
                except Exception as _ex:
                    st.error(f"Capture failed: {_ex}")

    with col_stop:
        if st.button("■ Stop", use_container_width=True):
            if st.session_state.capture_running:
                stop_capture()
                st.session_state.capture_running = False
                st.info("Capture stopped.")

    st.markdown("---")

    # ── Bluetooth ──
    st.markdown('<div class="section-header">Bluetooth</div>', unsafe_allow_html=True)
    if st.button("🔵 Scan Bluetooth", use_container_width=True):
        with st.spinner("Scanning Bluetooth (10s)..."):
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                st.session_state.bt_devices = loop.run_until_complete(full_bluetooth_scan())
                loop.close()
                st.success(f"Found {len(st.session_state.bt_devices)} BT device(s)")
            except Exception as _ex:
                st.error(f"BT scan failed: {_ex}")

    st.markdown("---")

    # ── Auto Refresh ──
    st.markdown('<div class="section-header">Auto Refresh</div>', unsafe_allow_html=True)
    auto_refresh = st.checkbox("Enable auto-refresh", value=True)
    refresh_interval = st.slider("Interval (seconds)", 2, 30, 5)

    st.markdown("---")
    st.markdown(
        f'<div style="font-family:\'Share Tech Mono\',monospace; font-size:10px; '
        f'color:#0e3a5c; text-align:center;">SYSTEM ONLINE<br>'
        f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>',
        unsafe_allow_html=True
    )


# ─────────────────────────────────────────
# HEADER
# ─────────────────────────────────────────

col_title, col_status = st.columns([3, 1])
with col_title:
    st.markdown(
        '<h1 style="font-family:\'Share Tech Mono\',monospace; color:#00d4ff; '
        'letter-spacing:4px; font-size:28px; margin-bottom:0;">📡 SIGNAL INTELLIGENCE SYSTEM</h1>'
        '<p style="color:#5a8ab0; font-size:12px; letter-spacing:2px; margin-top:4px;">'
        'AI-DRIVEN WIRELESS THREAT DETECTION</p>',
        unsafe_allow_html=True
    )
with col_status:
    capture_status = "🟢 CAPTURING" if st.session_state.capture_running else "🔴 STANDBY"
    st.markdown(
        f'<div style="text-align:right; padding-top:16px;">'
        f'<span style="font-family:\'Share Tech Mono\',monospace; font-size:12px; '
        f'color:{"#00ff88" if st.session_state.capture_running else "#ff4444"};">'
        f'{capture_status}</span></div>',
        unsafe_allow_html=True
    )

st.markdown("---")


# ─────────────────────────────────────────
# TABS
# ─────────────────────────────────────────

tab_overview, tab_wifi, tab_bt, tab_threats, tab_model = st.tabs([
    "🖥  Overview",
    "📶  WiFi Monitor",
    "🔵  Bluetooth",
    "🚨  Threats",
    "🤖  AI Model",
])


# ═════════════════════════════════════════
# TAB 1: OVERVIEW
# ═════════════════════════════════════════

with tab_overview:

    # ── Top metrics ──
    ip_a = st.session_state.ip_a
    ip_b = st.session_state.ip_b
    wifi_status = get_status(ip_a, ip_b) if ip_a and ip_b else {}
    alerts_list = list(st.session_state.alerts)

    mc1, mc2, mc3, mc4, mc5 = st.columns(5)
    mc1.metric("Devices Found",  len(st.session_state.devices))
    mc2.metric("BT Devices",     len(st.session_state.bt_devices))
    mc3.metric("Packets",        wifi_status.get("packet_count", 0))
    mc4.metric("Data Volume",    wifi_status.get("bytes_human", "0 B"))
    mc5.metric("Threat Alerts",  len(alerts_list))

    st.markdown("---")

    # ── Device Table ──
    st.markdown('<div class="section-header">Connected Devices</div>', unsafe_allow_html=True)

    if st.session_state.devices:
        df = pd.DataFrame(st.session_state.devices)[
            ["ip", "mac", "hostname", "status", "last_seen"]
        ].rename(columns={
            "ip": "IP Address", "mac": "MAC Address",
            "hostname": "Hostname", "status": "Status", "last_seen": "Last Seen"
        })
        st.dataframe(df, use_container_width=True, hide_index=True,
                     column_config={
                         "Status": st.column_config.TextColumn(width="medium"),
                     })
    else:
        st.info("Click **Scan Network** in the sidebar to discover devices.")

    st.markdown("---")

    # ── Communication Summary ──
    col_w, col_b = st.columns(2)

    with col_w:
        st.markdown('<div class="section-header">WiFi Communication</div>', unsafe_allow_html=True)
        if ip_a and ip_b:
            status_val = wifi_status.get("status", "NO_DATA")
            badge_class = "badge-active" if status_val == "ACTIVE" \
                          else "badge-inactive" if status_val == "INACTIVE" \
                          else "badge-warning"
            st.markdown(
                f'<div style="text-align:center; padding:20px;">'
                f'<div style="font-size:14px; color:#5a8ab0; margin-bottom:8px;">'
                f'Device A: <b style="color:#00d4ff;">{ip_a}</b></div>'
                f'<div style="font-size:28px; margin:12px 0;">↕</div>'
                f'<div style="font-size:14px; color:#5a8ab0; margin-bottom:16px;">'
                f'Device B: <b style="color:#00d4ff;">{ip_b}</b></div>'
                f'<span class="{badge_class}">{status_val}</span>'
                f'</div>',
                unsafe_allow_html=True
            )

    with col_b:
        st.markdown('<div class="section-header">Bluetooth Status</div>', unsafe_allow_html=True)
        paired = [d for d in st.session_state.bt_devices if d.get("paired")]
        active = [d for d in st.session_state.bt_devices if "Connected" in d.get("status","")]

        if st.session_state.bt_devices:
            st.markdown(
                f'<div style="text-align:center; padding:20px;">'
                f'<div style="font-size:36px; color:#00d4ff; font-weight:700;">'
                f'{len(st.session_state.bt_devices)}</div>'
                f'<div style="color:#5a8ab0; font-size:12px;">BT DEVICES IN RANGE</div>'
                f'<div style="margin-top:12px;">'
                f'<span class="badge-active">{len(active)} Connected</span>&nbsp;&nbsp;'
                f'<span class="badge-warning">{len(paired)} Paired</span>'
                f'</div></div>',
                unsafe_allow_html=True
            )
        else:
            st.info("Click **Scan Bluetooth** to detect nearby devices.")


# ═════════════════════════════════════════
# TAB 2: WiFi MONITOR
# ═════════════════════════════════════════

with tab_wifi:
    st.markdown('<div class="section-header">Live Packet Monitor</div>', unsafe_allow_html=True)

    ip_a = st.session_state.ip_a
    ip_b = st.session_state.ip_b

    if not (ip_a and ip_b):
        st.warning("Set Device A and B in the sidebar, then start capture.")
    else:
        status = get_status(ip_a, ip_b)

        # ── Status banner ──
        is_active = status["status"] == "ACTIVE"
        banner_color = "#003d1a" if is_active else "#1a0000"
        badge_color  = "#00ff88" if is_active else "#ff4444"
        st.markdown(
            f'<div style="background:{banner_color}; border:1px solid {badge_color}; '
            f'border-radius:8px; padding:16px 24px; margin-bottom:16px; '
            f'display:flex; align-items:center; justify-content:space-between;">'
            f'<div style="font-family:\'Share Tech Mono\',monospace;">'
            f'<span style="color:{badge_color}; font-size:16px; font-weight:700;">'
            f'{"● COMMUNICATION ACTIVE" if is_active else "○ COMMUNICATION INACTIVE"}</span><br>'
            f'<span style="color:#5a8ab0; font-size:12px;">'
            f'{ip_a} ↔ {ip_b}</span></div>'
            f'<div style="font-family:\'Share Tech Mono\',monospace; text-align:right;">'
            f'<div style="color:#c8d8e8;">{status.get("packet_count",0)} packets</div>'
            f'<div style="color:#5a8ab0; font-size:12px;">'
            f'{status.get("bytes_human","0 B")}</div></div>'
            f'</div>',
            unsafe_allow_html=True
        )

        # ── Metrics row ──
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Packets",    status.get("packet_count", 0))
        m2.metric("Data",       status.get("bytes_human", "0 B"))
        m3.metric("Duration",   f"{status.get('duration_secs',0):.0f}s")
        m4.metric("Protocols",  len(status.get("protocols", {})))

        st.markdown("---")

        # ── Traffic history chart ──
        pair_key = f"{ip_a}↔{ip_b}"
        history  = st.session_state.traffic_history

        # Push current snapshot into history
        if pair_key not in history:
            history[pair_key] = {"times": deque(maxlen=60), "packets": deque(maxlen=60),
                                  "bytes":   deque(maxlen=60)}

        h = history[pair_key]
        h["times"].append(datetime.now().strftime("%H:%M:%S"))
        h["packets"].append(status.get("packet_count", 0))
        h["bytes"].append(status.get("bytes_total", 0) / 1024)  # KB

        col_chart1, col_chart2 = st.columns(2)

        with col_chart1:
            st.markdown("**Packet Count Over Time**")
            if len(h["times"]) > 1:
                fig, ax = _fig(figsize=(6, 3))
                x = range(len(h["packets"]))
                ax.fill_between(x, list(h["packets"]), alpha=0.2, color="#00d4ff")
                ax.plot(x, list(h["packets"]), color="#00d4ff", lw=2)
                ax.set_xlabel("Sample")
                ax.set_ylabel("Packets")
                ax.set_title("Packet Count")
                ax.grid(True)
                plt.tight_layout()
                st.pyplot(fig, use_container_width=True)
                plt.close(fig)
            else:
                st.info("Waiting for traffic data...")

        with col_chart2:
            st.markdown("**Data Volume (KB) Over Time**")
            if len(h["times"]) > 1:
                fig, ax = _fig(figsize=(6, 3))
                x = range(len(h["bytes"]))
                ax.fill_between(x, list(h["bytes"]), alpha=0.2, color="#00ff88")
                ax.plot(x, list(h["bytes"]), color="#00ff88", lw=2)
                ax.set_xlabel("Sample")
                ax.set_ylabel("KB")
                ax.set_title("Data Volume")
                ax.grid(True)
                plt.tight_layout()
                st.pyplot(fig, use_container_width=True)
                plt.close(fig)
            else:
                st.info("Waiting for traffic data...")

        # ── Protocol breakdown ──
        protocols = status.get("protocols", {})
        if protocols:
            st.markdown("---")
            st.markdown("**Protocol Breakdown**")
            fig, ax = _fig(figsize=(8, 3))
            proto_names = list(protocols.keys())[:10]
            proto_vals  = [protocols[p] for p in proto_names]
            colors = ["#00d4ff", "#00ff88", "#ff6b35", "#a855f7",
                      "#f59e0b", "#ef4444", "#06b6d4", "#84cc16",
                      "#ec4899", "#8b5cf6"]
            bars = ax.barh(proto_names, proto_vals,
                           color=colors[:len(proto_names)], height=0.6)
            ax.set_xlabel("Packets")
            ax.set_title("Protocol Distribution")
            ax.grid(True, axis="x")
            for bar, val in zip(bars, proto_vals):
                ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height()/2,
                        str(val), va="center", color="#c8d8e8", fontsize=9)
            plt.tight_layout()
            st.pyplot(fig, use_container_width=True)
            plt.close(fig)

        # ── Sessions ──
        sessions = status.get("sessions", [])
        if sessions:
            st.markdown("---")
            st.markdown("**Communication Sessions**")
            df_sess = pd.DataFrame(sessions)
            st.dataframe(df_sess, use_container_width=True, hide_index=True)

        # ── Anomaly check ──
        if st.session_state.detector and st.session_state.capture_running:
            pred = st.session_state.detector.predict_from_status(status)
            push_observation(pair_key, status)

            alert = st.session_state.alert_manager.maybe_alert(pair_key, pred)
            if alert:
                st.session_state.alerts.appendleft(alert)

            sev = pred["severity"]
            if sev != "NONE":
                sev_class = f"alert-{sev.lower()}"
                st.markdown(
                    f'<div class="{sev_class}">'
                    f'⚠ ANOMALY DETECTED [{sev}] | Score: {pred["score"]:.4f}<br>'
                    f'{pred["reason"]}</div>',
                    unsafe_allow_html=True
                )


# ═════════════════════════════════════════
# TAB 3: BLUETOOTH
# ═════════════════════════════════════════

with tab_bt:
    st.markdown('<div class="section-header">Bluetooth Device Scanner</div>',
                unsafe_allow_html=True)

    if not st.session_state.bt_devices:
        st.info("Click **Scan Bluetooth** in the sidebar to detect nearby Bluetooth devices.")
    else:
        devices_bt = st.session_state.bt_devices

        # Summary metrics
        b1, b2, b3, b4 = st.columns(4)
        ble_count     = sum(1 for d in devices_bt if d.get("type") == "BLE")
        classic_count = sum(1 for d in devices_bt if d.get("type") == "Classic-BT")
        paired_count  = sum(1 for d in devices_bt if d.get("paired"))
        active_count  = sum(1 for d in devices_bt if "Connected" in d.get("status",""))

        b1.metric("Total BT Devices", len(devices_bt))
        b2.metric("BLE Devices",      ble_count)
        b3.metric("Classic BT",       classic_count)
        b4.metric("Connected",        active_count)

        st.markdown("---")

        # Device grid
        st.markdown("**Discovered Devices**")
        for i, dev in enumerate(devices_bt):
            is_connected = "Connected" in dev.get("status", "")
            col1, col2, col3, col4 = st.columns([2, 2, 2, 2])
            with col1:
                st.markdown(f"**{dev.get('name','Unknown')}**")
            with col2:
                st.markdown(f"`{dev.get('address','N/A')}`")
            with col3:
                rssi = dev.get("rssi")
                rssi_str = f"{rssi} dBm" if rssi else "N/A"
                st.markdown(rssi_str)
            with col4:
                badge = "badge-active" if is_connected else \
                        "badge-warning" if dev.get("paired") else "badge-inactive"
                st.markdown(
                    f'<span class="{badge}">{dev["status"]}</span>',
                    unsafe_allow_html=True
                )
            if dev.get("services"):
                with st.expander(f"Services ({len(dev['services'])})"):
                    for s in dev["services"]:
                        st.code(s)
            st.markdown("---")

        # RSSI chart
        devices_with_rssi = [d for d in devices_bt if d.get("rssi")]
        if devices_with_rssi:
            st.markdown("**Signal Strength (RSSI)**")
            fig, ax = _fig(figsize=(8, max(3, len(devices_with_rssi) * 0.5)))
            names  = [d.get("name","?")[:20] for d in devices_with_rssi]
            rssis  = [d["rssi"] for d in devices_with_rssi]
            colors = ["#00ff88" if r > -60 else "#ffaa00" if r > -80 else "#ff4444"
                      for r in rssis]
            bars = ax.barh(names, rssis, color=colors, height=0.6)
            ax.set_xlabel("RSSI (dBm)")
            ax.set_title("Bluetooth Signal Strength")
            ax.axvline(-60, color="#00ff88", ls="--", alpha=0.5, label="Good")
            ax.axvline(-80, color="#ffaa00", ls="--", alpha=0.5, label="Fair")
            ax.legend(facecolor="#0a1520", labelcolor="#c8d8e8")
            ax.grid(True, axis="x")
            plt.tight_layout()
            st.pyplot(fig, use_container_width=True)
            plt.close(fig)


# ═════════════════════════════════════════
# TAB 4: THREATS
# ═════════════════════════════════════════

with tab_threats:
    st.markdown('<div class="section-header">Threat & Anomaly Detection</div>',
                unsafe_allow_html=True)

    alerts_list = list(st.session_state.alerts)

    if not alerts_list:
        st.markdown(
            '<div style="text-align:center; padding:40px; color:#5a8ab0;">'
            '<div style="font-size:48px;">✓</div>'
            '<div style="font-family:\'Share Tech Mono\',monospace; '
            'letter-spacing:2px; margin-top:12px;">NO THREATS DETECTED</div>'
            '<div style="font-size:12px; margin-top:8px;">System monitoring normally.</div>'
            '</div>',
            unsafe_allow_html=True
        )
    else:
        t1, t2 = st.columns([3, 1])
        with t1:
            st.markdown(f"**{len(alerts_list)} alert(s) detected**")
        with t2:
            if st.button("🗑 Clear Alerts"):
                st.session_state.alerts.clear()
                st.rerun()

        for alert in alerts_list:
            sev   = alert.get("severity", "LOW")
            cls   = f"alert-{sev.lower()}"
            icons = {"CRITICAL":"🚨","HIGH":"🔴","MEDIUM":"🟠","LOW":"⚠️"}
            icon  = icons.get(sev,"⚠️")
            st.markdown(
                f'<div class="{cls}">'
                f'<b>{icon} [{sev}] {alert["timestamp"]}</b><br>'
                f'Pair: <code>{alert["pair"]}</code><br>'
                f'Anomaly Score: {alert["score"]:.4f}<br>'
                f'{alert["reason"]}'
                f'</div>',
                unsafe_allow_html=True
            )

    st.markdown("---")
    st.markdown('<div class="section-header">All Traffic Pairs</div>', unsafe_allow_html=True)

    all_pairs = get_all_pairs()
    if all_pairs:
        rows = []
        for pair_label, s in all_pairs.items():
            rows.append({
                "Pair":     pair_label,
                "Status":   s["status"],
                "Packets":  s["packet_count"],
                "Data":     s.get("bytes_human","0 B"),
                "Duration": f"{s.get('duration_secs',0):.0f}s",
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.info("No traffic data captured yet. Start capture and generate some traffic.")


# ═════════════════════════════════════════
# TAB 5: AI MODEL
# ═════════════════════════════════════════

with tab_model:
    st.markdown('<div class="section-header">AI Signal Classifier</div>', unsafe_allow_html=True)

    col_left, col_right = st.columns([1, 1])

    with col_left:
        st.markdown("**Model Info**")
        model_exists = os.path.exists("model/model.h5")
        labels_exist = os.path.exists("data/labels.pkl")

        st.markdown(
            f'<div style="font-family:\'Share Tech Mono\',monospace; font-size:12px; '
            f'padding:12px; background:#0a1520; border:1px solid #0e3a5c; border-radius:6px;">'
            f'CNN Model (model.h5)&nbsp;&nbsp;'
            f'<span class="{"badge-active" if model_exists else "badge-inactive"}">'
            f'{"LOADED" if model_exists else "NOT FOUND"}</span><br><br>'
            f'Label Map (labels.pkl)&nbsp;'
            f'<span class="{"badge-active" if labels_exist else "badge-inactive"}">'
            f'{"LOADED" if labels_exist else "NOT FOUND"}</span><br><br>'
            f'Anomaly Detector&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'
            f'<span class="{"badge-active" if st.session_state.detector else "badge-inactive"}">'
            f'{"ACTIVE" if st.session_state.detector else "NOT LOADED"}</span>'
            f'</div>',
            unsafe_allow_html=True
        )

        if not model_exists:
            st.info(
                "Train the CNN on Kaggle using `train.py`, then download "
                "`model/model.h5` and place it here."
            )

    with col_right:
        st.markdown("**Signal Classifier Demo**")
        st.markdown("Upload or simulate a signal to classify:")

        # Simulate classification
        if st.button("🎲 Simulate Random Signal", use_container_width=True):
            modulations = [
                "BPSK","QPSK","8PSK","16QAM","64QAM","256QAM",
                "AM-DSB","FM","GMSK","OQPSK"
            ]

            if labels_exist:
                with open("data/labels.pkl","rb") as f:
                    modulations = pickle.load(f)

            predicted = np.random.choice(modulations)
            confidence = np.random.uniform(0.72, 0.98)

            # Show result
            st.markdown(
                f'<div style="background:#0a1520; border:1px solid #00d4ff; '
                f'border-radius:8px; padding:20px; text-align:center; margin-top:12px;">'
                f'<div style="color:#5a8ab0; font-size:11px; letter-spacing:2px;">PREDICTED MODULATION</div>'
                f'<div style="color:#00d4ff; font-size:28px; font-weight:700; margin:8px 0;">'
                f'{predicted}</div>'
                f'<div style="color:#5a8ab0; font-size:11px; letter-spacing:2px;">CONFIDENCE</div>'
                f'<div style="color:#00ff88; font-size:22px;">{confidence*100:.1f}%</div>'
                f'</div>',
                unsafe_allow_html=True
            )

    st.markdown("---")

    # Training curves (if they exist)
    st.markdown('<div class="section-header">Training Visualisations</div>',
                unsafe_allow_html=True)
    col_a, col_b = st.columns(2)

    with col_a:
        if os.path.exists("model/training_curves.png"):
            st.image("model/training_curves.png", caption="Accuracy & Loss Curves",
                     use_container_width=True)
        else:
            # Show placeholder chart
            fig, axes = _fig(1, 2, figsize=(8, 3))
            for ax in axes:
                x = np.linspace(0, 20, 21)
                ax.plot(x, 1 - np.exp(-x*0.2) + np.random.normal(0,0.02,21),
                        color="#00d4ff", lw=2, label="Train")
                ax.plot(x, 1 - np.exp(-x*0.18) + np.random.normal(0,0.03,21),
                        color="#00ff88", lw=2, label="Val")
                ax.legend(facecolor="#0a1520", labelcolor="#c8d8e8")
                ax.grid(True)
            axes[0].set_title("Accuracy vs Epoch (Sample)")
            axes[1].set_title("Loss vs Epoch (Sample)")
            plt.tight_layout()
            st.pyplot(fig, use_container_width=True)
            plt.close(fig)
            st.caption("Sample chart — train model.h5 to see real curves.")

    with col_b:
        if os.path.exists("model/confusion_matrix.png"):
            st.image("model/confusion_matrix.png", caption="Confusion Matrix",
                     use_container_width=True)
        else:
            # Placeholder confusion matrix
            n = 8
            cm = np.random.dirichlet(np.ones(n), size=n) * 100
            np.fill_diagonal(cm, np.random.uniform(70, 95, n))
            fig, ax = _fig(figsize=(5, 4))
            import seaborn as sns
            sns.heatmap(cm.astype(int), annot=True, fmt="d", cmap="Blues",
                        ax=ax, cbar=False, linewidths=0.5, linecolor="#0e3a5c")
            ax.set_title("Confusion Matrix (Sample)")
            plt.tight_layout()
            st.pyplot(fig, use_container_width=True)
            plt.close(fig)
            st.caption("Sample matrix — train model.h5 to see real results.")


# ─────────────────────────────────────────
# AUTO REFRESH
# ─────────────────────────────────────────

if auto_refresh and st.session_state.capture_running:
    time.sleep(refresh_interval)
    st.session_state.refresh_count += 1
    st.rerun()
