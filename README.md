# SilentSnare 🔒

SilentSnare is a **network security monitoring and detection tool** for ethical hacking competitions.  
It combines **packet sniffing**, **ARP spoof detection**, and a **real-time web dashboard** built with Streamlit.

---

## 🚀 Features
- Live packet capture using **Scapy**
- Suspicious IP detection & logging
- Real-time dashboard with **Start/Stop capture**
- Integration with **Bettercap** for ARP/gateway spoof testing
- Modular design (Scripts + Dashboard)

---

## 📂 Project Structure
SilentSnare/
│── dashboard/ # Streamlit dashboard
│ └── dashboard.py
│
│── Scripts/ # Sniffer + utility scripts
│ └── sniffer.py
│
│── requirements.txt # Python dependencies
│── README.md # Project overview + commands

yaml
Copy code

---

## ⚡ Setup & Usage

### 1. Clone Repository
```bash
git clone https://github.com/uzair-khan80/SilentSnare.git
cd SilentSnare
2. Create Virtual Environment
bash
Copy code
python3 -m venv venv
source venv/bin/activate     # Linux / Mac
venv\Scripts\activate        # Windows (PowerShell)
3. Install Dependencies
bash
Copy code
pip install -r requirements.txt
4. Run Dashboard
bash
Copy code
cd dashboard
streamlit run dashboard.py
👉 Open browser → http://localhost:8501

5. Run Sniffer Script
(New terminal, venv activate karna na bhoolo)

bash
Copy code
cd Scripts
sudo python3 sniffer.py
6. Run Bettercap (Attacker Terminal)
Check your interface:

bash
Copy code
ip a
Start ARP spoof:

bash
Copy code
sudo bettercap -iface eth0 -eval "set arp.spoof.targets VICTIM_IP; arp.spoof on; net.sniff on"
7. Stop Everything
Stop Streamlit: CTRL + C

Stop Sniffer: CTRL + C

Stop Bettercap: CTRL + C

