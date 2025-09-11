
# dashboard.py
import streamlit as st
from scapy.all import sniff, IP, TCP, Raw
import pandas as pd
import threading
import time
import csv
import io
import signal

st.set_page_config(layout="wide", page_title="SilentSnare - MITM Dashboard")
st.title("SilentSnare — MITM Visualization (Scenario 1 & 2)")

# -------------------------
# Globals / session state
# -------------------------
if "packets" not in st.session_state:
    st.session_state.packets = []   # list of dicts: src,dst,proto,length,payload,ts
if "capturing" not in st.session_state:
    st.session_state.capturing = False
if "stop_event" not in st.session_state:
    st.session_state.stop_event = threading.Event()
if "sniffer_thread" not in st.session_state:
    st.session_state.sniffer_thread = None

# -------------------------
# Packet callback
# -------------------------
def packet_callback(pkt):
    # minimal safety checks
    try:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        src = pkt[IP].src if IP in pkt else ""
        dst = pkt[IP].dst if IP in pkt else ""
        proto = ""
        payload = ""
        length = len(pkt)
        if TCP in pkt:
            proto = "TCP"
            if Raw in pkt:
                payload = bytes(pkt[Raw]).decode(errors="ignore")
                # optionally trim payload to show small snippet
                if len(payload) > 1000:
                    payload = payload[:1000] + "...(truncated)"
        else:
            proto = pkt.summary()
        entry = {"ts": ts, "src": src, "dst": dst, "proto": proto, "length": length, "payload": payload}
        st.session_state.packets.append(entry)
    except Exception as e:
        # ignore parse errors
        pass

# -------------------------
# Sniffing thread target
# -------------------------
def sniff_target(iface, bpf_filter, count):
    # reset stop_event
    st.session_state.stop_event.clear()
    # sniff until count or stop_event set
    def stopfilter(x):
        return st.session_state.stop_event.is_set()
    try:
        sniff(iface=iface, filter=bpf_filter if bpf_filter else None,
              prn=packet_callback, stop_filter=stopfilter, store=False, timeout=None)
    except Exception as e:
        # scapy error -> append a message
        st.session_state.packets.append({"ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                                         "src": "", "dst": "", "proto": "ERROR",
                                         "length": 0, "payload": f"Sniff error: {e}"})

# -------------------------
# UI - Sidebar controls
# -------------------------
st.sidebar.header("Setup & Controls")
iface = st.sidebar.text_input("Interface (e.g., eth0)", value="eth0")
scenario = st.sidebar.selectbox("Select Scenario", ("Scenario 1 — MITM (HTTP vs HTTPS)", "Scenario 2 — Email Hijacking (SMTP)"))
bpf = ""
if scenario.startswith("Scenario 1"):
    st.sidebar.markdown("**Scenario 1:** Start ARP spoof (Ettercap) separately; then capture HTTP/HTTPS traffic.")
    bpf = st.sidebar.text_input("BPF filter (leave blank for all)", value="tcp port 80 or tcp port 443")
else:
    st.sidebar.markdown("**Scenario 2:** Start gateway spoof (bettercap) separately; then capture SMTP / SMTPS.")
    bpf = st.sidebar.text_input("BPF filter (leave blank for all)", value="tcp port 25 or tcp port 587 or tcp port 465 or tcp port 993")
pkt_count = st.sidebar.number_input("Max packets to capture (0 = unlimited until Stop)", value=0, min_value=0, step=1)

col1, col2 = st.sidebar.columns(2)
with col1:
    start_btn = st.button("Start Capture")
with col2:
    stop_btn = st.button("Stop Capture")

# -------------------------
# Start / Stop logic
# -------------------------
if start_btn and not st.session_state.capturing:
    # clear previous
    st.session_state.packets = []
    st.session_state.stop_event.clear()
    st.session_state.capturing = True
    # start background thread
    thread = threading.Thread(target=sniff_target, args=(iface, bpf if bpf else None, pkt_count), daemon=True)
    st.session_state.sniffer_thread = thread
    thread.start()
    st.success("Sniffer started. Run ARP/gateway spoof from attacker terminal now.")

if stop_btn and st.session_state.capturing:
    st.session_state.stop_event.set()
    st.session_state.capturing = False
    st.success("Stop signal sent. Sniffer will exit shortly.")

# -------------------------
# Display main area
# -------------------------
st.header(f"Live Capture — {scenario}")
left, right = st.columns([2,1])

with left:
    st.subheader("Captured Packets (latest first)")
    # show latest 100 packets
    df = pd.DataFrame(st.session_state.packets[::-1])  # reverse to show latest first
    if not df.empty:
        st.dataframe(df.head(200), use_container_width=True)
    else:
        st.info("No packets yet. Start capture and run ARP/gateway spoofing from another terminal.")

with right:
    st.subheader("Summary & Alerts")
    total = len(st.session_state.packets)
    st.metric("Total Packets Captured", total)
    # top protocols
    if total > 0:
        proto_counts = pd.Series([p["proto"] for p in st.session_state.packets]).value_counts().head(10)
        st.bar_chart(proto_counts)
        # detect suspicious external IPs (simple heuristic)
        srcs = pd.Series([p["src"] for p in st.session_state.packets if p["src"]])
        top_srcs = srcs.value_counts().head(10)
        st.write("Top sources:")
        st.write(top_srcs)
        # basic suspicious detection: external public IPs / too many packets
        suspicious = []
        for ip, cnt in top_srcs.items():
            # ignore local NAT IPs like 10.*, 192.168.*, 172.16-31.*
            if not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.")):
                if cnt > 2:
                    suspicious.append(ip)
        if suspicious:
            st.error(f"Suspicious activity detected from: {suspicious}")
        else:
            st.success("No suspicious external IPs detected (local traffic only).")

# -------------------------
# Payload inspector & export
# -------------------------
st.subheader("Payload Inspector / Export")
sel_idx = st.number_input("Show packet index (0 = newest)", min_value=0, max_value=max(0, len(st.session_state.packets)-1), value=0, step=1)
if st.session_state.packets:
    pkt = st.session_state.packets[::-1][sel_idx]
    st.write(pkt)
    if pkt.get("payload"):
        st.code(pkt["payload"][:4000])
# Export CSV
export_buffer = io.StringIO()
if st.button("Export CSV of captured packets"):
    df_export = pd.DataFrame(st.session_state.packets)
    df_export.to_csv(export_buffer, index=False)
    st.download_button("Download CSV", data=export_buffer.getvalue(), file_name="silent_snare_capture.csv", mime="text/csv")

st.markdown("---")
st.info("Notes: Run ARP spoofing (Scenario 1) or gateway spoofing (Scenario 2) from attacker terminal.\nRun Streamlit with sudo and venv streamlit binary so scapy can create raw sockets.")
