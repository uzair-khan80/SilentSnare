import streamlit as st
from scapy.all import sniff, IP
import pandas as pd
import matplotlib.pyplot as plt

st.set_page_config(page_title="SilentSnare Ultimate Dashboard", layout="wide")
st.title("SilentSnare: Ultimate MITM Visualization Dashboard")

# Global packet log
if "packet_logs" not in st.session_state:
    st.session_state.packet_logs = []

# Packet capture callback
def packet_callback(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        length = len(packet)
        st.session_state.packet_logs.append({
            "src": src,
            "dst": dst,
            "proto": proto,
            "length": length
        })

# Buttons for capturing
col1, col2 = st.columns(2)
with col1:
    if st.button("Start Capture (50 Packets)"):
        sniff(count=50, prn=packet_callback)
        st.success("Capture complete!")

with col2:
    if st.button("Clear Logs"):
        st.session_state.packet_logs = []
        st.warning("Logs cleared!")

# Show packet logs
if st.session_state.packet_logs:
    df = pd.DataFrame(st.session_state.packet_logs)
    st.subheader("Captured Packets")
    st.dataframe(df)

    # Packets per protocol
    st.subheader("Packets per Protocol")
    proto_count = df['proto'].value_counts()
    st.bar_chart(proto_count)

    # Packet size graph
    st.subheader("Packet Sizes")
    st.line_chart(df['length'])

    # Source → Destination Summary
    st.subheader("Traffic Flow: Source → Destination")
    traffic_summary = df.groupby(['src', 'dst']).size().reset_index(name='count')
    st.dataframe(traffic_summary)

    # Live Alerts for suspicious activity (example: >10 packets from same source)
    st.subheader("Alerts")
    suspicious = traffic_summary[traffic_summary['count'] > 10]
    if not suspicious.empty:
        st.error(f"Suspicious activity detected from: {list(suspicious['src'])}")
    else:
        st.success("No suspicious activity detected")

# Secure vs Insecure Demo (HTTP vs HTTPS)
st.subheader("Secure vs Insecure Traffic Example")
st.info("HTTP packets can be intercepted → readable\nHTTPS packets are encrypted → safe")


