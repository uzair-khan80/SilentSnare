#!/bin/bash
echo "Starting Packet Capture..."
sudo tshark -i eth0 -w ~/SilentSnare/Videos/capture.pcap
echo "Packet capture saved at ~/SilentSnare/Videos/capture.pcap"
