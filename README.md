# 🛡️ CyberGuard Elite - Advanced Threat Intelligence System

![Project Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-1.30%2B-red)

**CyberGuard Elite** is a Next-Gen Hybrid Threat Detection Platform. It integrates **Real-time Threat Intelligence**, **Network Forensics**, and **AI-driven Behavioral Analysis** to identify Phishing URLs and Malware with high precision.

---

## 🚀 Key Features

### 🌐 1. Intelligent URL Forensics
- **Real-time Whitelisting:** Automatically syncs with Tranco Top 1M domains every 24h.
- **Typosquatting Detection:** Identifies brand impersonation (e.g., `g0ogle.com` vs `google.com`).
- **Deep Network Probing:**
  - **SSL Inspection:** Detects free/insecure certificates (Let's Encrypt).
  - **Redirect Tracking:** Traces hidden redirect chains used in phishing.
  - **Server Fingerprinting:** Identifies backend technologies.
- **Heuristic Engine:** Flags Raw IPs, Non-standard ports (:8080), and Malicious payloads (.exe, .sh).

### 📂 2. Malware Deep Scan
- **Static Analysis:** Safe, non-execution based analysis.
- **Deep Forensics:**
  - **Entropy Analysis:** Detects packed/encrypted malware code.
  - **API Inspection:** Flags dangerous Windows API calls (Injection/Keylogging).
  - **Time-stomping Check:** Identifies forged compilation timestamps.
- **AI Prediction:** LightGBM model trained on EMBER (400k samples).

---

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.8 or higher.
- Git.

### Step 1: Clone Repository
```bash
git clone <https://github.com/DucDo-634/URL_detector.git>
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Run
```bash
streamlit run app.py
```

