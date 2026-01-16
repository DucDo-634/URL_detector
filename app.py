import streamlit as st
import sys
import os
import time
import numpy as np
import lightgbm as lgb
import pickle
import pandas as pd
import requests
import zipfile
import io
import datetime
import re
import math
import lief
import socket
import ssl
from urllib.parse import urlparse
from difflib import SequenceMatcher

# --- 1. CONFIGURATION & IMPORTS ---
try: np.int = int
except: pass

BASE_DIR = os.getcwd()
MODELS_DIR = os.path.join(BASE_DIR, 'models')
DATA_DIR = os.path.join(BASE_DIR, 'data')
EMBER_LIB = os.path.join(BASE_DIR, 'ember_master')

if not os.path.exists(DATA_DIR): os.makedirs(DATA_DIR)
if os.path.exists(EMBER_LIB): sys.path.append(EMBER_LIB); import ember

FILE_MODEL_PATH = os.path.join(MODELS_DIR, 'model_lgbm_400k_max.txt')
URL_MODEL_PATH = os.path.join(MODELS_DIR, 'url_model.pkl')
URL_VECT_PATH = os.path.join(MODELS_DIR, 'url_vectorizer.pkl')
TOP_DOMAINS_PATH = os.path.join(DATA_DIR, 'top_1m.csv')

# --- 2. MODULE: REAL-TIME DATA ---
def get_file_age_hours(filepath):
    if not os.path.exists(filepath): return 9999
    return (time.time() - os.path.getmtime(filepath)) / 3600

def update_database():
    try:
        url = "https://tranco-list.eu/top-1m.csv.zip"
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=15)
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            with z.open('top-1m.csv') as f:
                df = pd.read_csv(f, header=None, names=['rank', 'domain'])
        df.to_csv(TOP_DOMAINS_PATH, index=False)
        return True, len(df)
    except Exception as e: return False, str(e)

@st.cache_data(ttl=3600)
def read_data_from_disk():
    try:
        if os.path.exists(TOP_DOMAINS_PATH):
            df = pd.read_csv(TOP_DOMAINS_PATH)
            return df['domain'].head(50000).tolist()
    except: pass
    return []

def ensure_database_is_fresh(force_update=False):
    if force_update or get_file_age_hours(TOP_DOMAINS_PATH) > 24:
        with st.spinner("🌍 Syncing with Global Threat Database..."):
            success, msg = update_database()
            if success:
                st.toast(f"Update Success: {msg:,} domains loaded.", icon="✅")
                read_data_from_disk.clear()

# --- 3. MODULE: DEEP FORENSICS (FILE & URL) ---

# [FILE] Deep PE Analysis
def analyze_pe_deeply(file_bytes):
    report = []
    risk_indicators = 0
    try:
        binary = lief.PE.parse(list(file_bytes))
        
        # Entropy Check
        entropy = 0
        if file_bytes:
            for x in range(256):
                p_x = float(list(file_bytes).count(x)) / len(file_bytes)
                if p_x > 0: entropy += - p_x * math.log(p_x, 2)
        
        report.append(f"**Shannon Entropy:** `{entropy:.2f}`")
        if entropy > 7.2:
            risk_indicators += 1
            report.append("⚠️ **Packed/Encrypted:** High entropy detected.")
            
        # Sections Check
        suspicious_sections = [s.name for s in binary.sections if s.entropy > 7.0]
        if suspicious_sections:
            report.append(f"⚠️ **Suspicious Sections:** `{', '.join(suspicious_sections)}`")
            
        # API Imports Check
        risky_imports = ['VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread', 'ShellExecute', 'URLDownloadToFile', 'IsDebuggerPresent', 'InternetOpen']
        found_imports = []
        for lib in binary.imports:
            for entry in lib.entries:
                if entry.name in risky_imports: found_imports.append(entry.name)
        
        if found_imports:
             risk_indicators += 1
             report.append(f"🚨 **Dangerous API Calls:** `{', '.join(found_imports)}`")
        
        # Compile Time Check
        ts = datetime.datetime.fromtimestamp(binary.header.time_date_stamps)
        report.append(f"🕒 **Compilation Year:** {ts.year}")
        if ts.year < 2010 or ts.year > 2030:
            report.append("⚠️ **Forged Timestamp:** Compilation date looks suspicious.")

    except Exception as e: report.append(f"❌ Analysis Error: {str(e)}")
    return report, risk_indicators

# [URL] Network Forensics & SSL Check
def scan_url_deep_forensics(url):
    report = []
    risk_score = 0
    
    if not url.startswith(('http://', 'https://')):
        target_url = 'https://' + url
    else:
        target_url = url
        
    try:
        parsed = urlparse(target_url)
        domain = parsed.netloc.split(':')[0] # Bỏ port nếu có
    except:
        return ["❌ Invalid URL Format"], 0
    
    # 1. SSL Certificate Check
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3.0)
            s.connect((domain, 443))
            cert = s.getpeercert()
            
            issuer = dict(x[0] for x in cert['issuer'])
            common_name = issuer.get('commonName', 'Unknown')
            report.append(f"🔒 **SSL Issuer:** `{common_name}`")
            
            if "Let's Encrypt" in common_name or "R3" in common_name:
                report.append("ℹ️ **Free SSL Detected:** Commonly used by phishing sites.")
            else:
                report.append("✅ **Business SSL:** Certificate appears reputable.")
            
            notAfter = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_left = (notAfter - datetime.datetime.utcnow()).days
            report.append(f"📅 **SSL Expiry:** {days_left} days remaining.")
            
    except Exception:
        pass # Ignore SSL errors for scoring

    # 2. Server Response
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        }
        r = requests.get(target_url, headers=headers, timeout=5)
        report.append(f"📡 **Status Code:** `{r.status_code}`")
        
        if r.history:
            chain = " -> ".join([resp.url for resp in r.history])
            report.append(f"🔄 **Redirect Chain:** `{chain}`")
            if len(r.history) > 2:
                report.append("⚠️ **Excessive Redirects:** Suspicious behavior.")
                risk_score += 1
                
        server_header = r.headers.get('Server', 'Hidden')
        report.append(f"🖥️ **Server Tech:** `{server_header}`")
        
    except requests.exceptions.RequestException:
        report.append(f"❌ **Connection Failed:** Site offline or blocking scan.")
        
    return report, risk_score

# [URL] Combined Risk Explanation (UPDATED LOGIC)
def explain_url_risk_combined(url, ai_score, is_typo, target_real, deep_report, net_risk, is_whitelisted):
    explanations = []
    risk_level = "LOW"
    
    # Parse URL
    target_url = url if "://" in url else "http://" + url
    try:
        parsed = urlparse(target_url)
        domain = parsed.netloc.split(':')[0]
        port = parsed.port
        path = parsed.path
    except:
        domain = ""
        port = None
        path = ""

    # --- 1. CRITICAL THREAT DETECTION ---
    
    # [RULE A] Raw IP Address Detection
    is_ip = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain)
    if is_ip:
        explanations.append("🚨 **Raw IP Address:** Using an IP address instead of a domain name is highly suspicious.")
        
    # [RULE B] Malicious File Extensions
    risky_exts = ['.sh', '.bin', '.exe', '.dll', '.bat', '.cmd', '.apk', '.jar']
    if any(path.endswith(ext) for ext in risky_exts):
        explanations.append(f"💣 **Malicious Payload:** URL points to an executable file (`{path.split('.')[-1]}`).")

    # [RULE C] Suspicious Ports
    if port and port not in [80, 443, 8080]:
        explanations.append(f"⚠️ **Non-standard Port:** Connection to unusual port `{port}`.")

    # --- 2. STANDARD CHECKS ---
    if len(url) > 75: explanations.append("⚠️ **Suspicious Length:** URL > 75 chars.")
    if sum(c.isdigit() for c in domain) > 3 and not is_ip: explanations.append("⚠️ **DGA Pattern:** Domain contains random numbers.")
    risky_tlds = ['.ru', '.xyz', '.top', '.cn', '.club', '.work']
    if any(domain.endswith(tld) for tld in risky_tlds): explanations.append(f"⚠️ **High-Risk TLD:** `{domain.split('.')[-1]}` is often abused.")
    
    if net_risk > 0: explanations.append("⚠️ **Network Anomaly:** SSL or Connection issues detected.")
    
    # --- 3. FINAL VERDICT LOGIC ---
    
    # Priority 1: Direct Threats (IP / Payload) -> CRITICAL
    if is_ip or any(path.endswith(ext) for ext in risky_exts):
        risk_level = "CRITICAL"
        explanations.insert(0, "🛑 **Direct Malware/IP Threat:** High certainty of malicious intent.")
        return risk_level, explanations, deep_report

    # Priority 2: Whitelist (Safe)
    if is_whitelisted:
        risk_level = "LOW"
        explanations.insert(0, "✅ **Verified Domain:** Site is in Top 1M Whitelist.")
        if not explanations: explanations.append("✅ **Clean Structure.**")
        return risk_level, explanations, deep_report

    # Priority 3: Typosquatting
    if is_typo:
        risk_level = "CRITICAL"
        explanations.insert(0, f"🛑 **Impersonation Attack:** Mimicking **{target_real}**.")

    # Priority 4: AI & Network
    elif ai_score > 0.6 or net_risk > 1:
        risk_level = "HIGH"
        explanations.insert(0, f"🤖 **AI/Network Verdict:** Malicious indicators confirmed.")
        
    # Priority 5: Medium Risk (Warning)
    elif ai_score > 0.4 or port:
        risk_level = "MEDIUM"
        explanations.insert(0, "⚠️ **Suspicious Activity:** Unusual patterns detected.")
        
    else:
        if not explanations: explanations.append("✅ **Clean Structure & Network Integrity.**")

    return risk_level, explanations, deep_report

# --- 4. LOAD MODELS ---
def make_tokens(f):
    tokens_by_slash = str(f).split('/')
    total_tokens = []
    for i in tokens_by_slash:
        tokens = str(i).split('-')
        tokens_dot = []
        for j in range(0,len(tokens)):
            temp_tokens = str(tokens[j]).split('.')
            tokens_dot = tokens_dot + temp_tokens
        total_tokens = total_tokens + tokens + tokens_dot
    return list(set(total_tokens))

@st.cache_resource
def load_models():
    file_model = None
    if os.path.exists(FILE_MODEL_PATH): file_model = lgb.Booster(model_file=FILE_MODEL_PATH)
    
    url_model, url_vectorizer = None, None
    if os.path.exists(URL_MODEL_PATH): url_model = pickle.load(open(URL_MODEL_PATH, 'rb'))
    if os.path.exists(URL_VECT_PATH): url_vectorizer = pickle.load(open(URL_VECT_PATH, 'rb'))
    return file_model, url_model, url_vectorizer

FILE_MODEL, URL_MODEL, URL_VECTORIZER = load_models()

def check_typosquatting(url, top_domains):
    clean_url = url.lower().replace("https://", "").replace("http://", "").replace("www.", "")
    domain = clean_url.split('/')[0].split(':')[0]
    
    if domain in top_domains: return False, None, 0.0, True
    
    candidates = [d for d in top_domains if abs(len(str(d)) - len(domain)) <= 2]
    max_score, best_match = 0, None
    for real in candidates:
        score = SequenceMatcher(None, domain, str(real)).ratio()
        if score > 0.85 and score > max_score: max_score, best_match = score, real
        
    if max_score > 0.85: return True, best_match, max_score, False
    return False, None, 0.0, False

def predict_url(url):
    try:
        vec = URL_VECTORIZER.transform([url])
        return URL_MODEL.predict_proba(vec)[0][1]
    except: return 0.0

def predict_file(file_bytes):
    try:
        extractor = ember.PEFeatureExtractor(2)
        features = np.array(extractor.feature_vector(file_bytes)).reshape(1, -1)
        return FILE_MODEL.predict(features)[0]
    except: return None

# --- 5. UI & FRONTEND (PREMIUM UPGRADE) ---
st.set_page_config(page_title="CyberGuard Elite", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Roboto+Mono:wght@300;400&display=swap');

    /* Animated Background */
    @keyframes gradient {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }
    
    .stApp { 
        background: linear-gradient(-45deg, #0b0f19, #16213e, #1a1a2e, #0f3460);
        background-size: 400% 400%;
        animation: gradient 15s ease infinite;
        color: #e2e8f0;
        font-family: 'Roboto Mono', monospace;
    }
    
    h1, h2, h3 { font-family: 'Orbitron', sans-serif !important; letter-spacing: 2px; }
    
    .main-title {
        background: -webkit-linear-gradient(0deg, #00f260, #0575E6);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        font-size: 64px; font-weight: 900; text-align: center; 
        text-shadow: 0 0 50px rgba(5, 117, 230, 0.5);
        margin-bottom: 5px;
        margin-top: -20px;
    }
    
    .glass-card {
        background: rgba(255, 255, 255, 0.04);
        backdrop-filter: blur(16px);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 16px;
        padding: 24px;
        margin-bottom: 20px;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
        transition: transform 0.3s ease;
    }
    .glass-card:hover { transform: translateY(-5px); border-color: rgba(255,255,255,0.2); }
    
    .risk-box { padding: 14px; border-radius: 8px; margin-bottom: 10px; border-left: 6px solid; background: rgba(0,0,0,0.4); font-size: 15px; }
    .risk-LOW { border-color: #00ff00; color: #ccffcc; } 
    .risk-MEDIUM { border-color: orange; color: #ffebcc; }
    .risk-HIGH { border-color: #ff4b4b; color: #ffcccc; } 
    .risk-CRITICAL { border-color: #ff0000; box-shadow: 0 0 15px rgba(255, 0, 0, 0.4); color: #fff; }
    
    .stButton>button {
        background: linear-gradient(90deg, #00C9FF 0%, #92FE9D 100%);
        color: #000; border: none; font-weight: 800; height: 55px; border-radius: 10px;
        font-family: 'Orbitron', sans-serif; letter-spacing: 1.5px; text-transform: uppercase;
    }
    .stButton>button:hover { transform: scale(1.02); box-shadow: 0 0 30px rgba(0, 201, 255, 0.6); }
    
    .rec-box {
        padding: 30px; text-align: center; border-radius: 16px; margin-top: 10px; margin-bottom: 25px; 
        font-weight: 800; font-size: 24px; font-family: 'Orbitron', sans-serif; letter-spacing: 1px;
    }
    .rec-SAFE { background: rgba(0, 255, 0, 0.15); border: 2px solid #00ff00; color: #00ff00; text-shadow: 0 0 15px rgba(0,255,0,0.6); }
    .rec-WARNING { background: rgba(255, 165, 0, 0.15); border: 2px solid orange; color: orange; text-shadow: 0 0 15px rgba(255, 165, 0, 0.6); }
    .rec-DANGER { background: rgba(255, 0, 0, 0.15); border: 2px solid #ff0000; color: #ff4b4b; text-shadow: 0 0 20px rgba(255,0,0,0.8); animation: pulse 1.5s infinite; }
    
    @keyframes pulse {
        0% { box-shadow: 0 0 0 0 rgba(255, 0, 0, 0.6); }
        70% { box-shadow: 0 0 0 15px rgba(255, 0, 0, 0); }
        100% { box-shadow: 0 0 0 0 rgba(255, 0, 0, 0); }
    }
</style>
""", unsafe_allow_html=True)

# --- SIDEBAR ---
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/9662/9662369.png", width=100)
    st.markdown("<h2 style='text-align: center; font-size: 24px;'>CONTROL PANEL</h2>", unsafe_allow_html=True)
    
    st.markdown("### 📡 SYSTEM MONITOR")
    if 'refresh_db' not in st.session_state: st.session_state.refresh_db = False
    ensure_database_is_fresh(st.session_state.refresh_db)
    TOP_DOMAINS = read_data_from_disk()
    st.session_state.refresh_db = False
    
    if os.path.exists(TOP_DOMAINS_PATH): st.success(f"DB Online: {len(TOP_DOMAINS):,} nodes")
    else: st.error("❌ DB Offline")
    
    if st.button("🔄 FORCE SYNC", use_container_width=True): 
        st.session_state.refresh_db = True; st.rerun()
    
    st.divider()
    st.markdown("### 📘 PROTOCOLS")
    with st.expander("Detection Methodology"):
        st.info("Layer 1: Real-time Threat Intel")
        st.info("Layer 2: Network Forensics")
        st.info("Layer 3: AI Heuristics")

# --- MAIN LAYOUT ---
st.markdown('<p class="main-title">CYBER GUARD ELITE</p>', unsafe_allow_html=True)
st.markdown("<div style='text-align:center; color:#a0aec0; margin-bottom:50px; font-size:16px; letter-spacing: 3px; font-weight:300;'>NEXT-GEN THREAT INTELLIGENCE PLATFORM</div>", unsafe_allow_html=True)

tab_url, tab_file = st.tabs(["🌐 URL DEEP SCAN", "📂 FILE MALWARE SCAN"])

# --- URL TAB ---
with tab_url:
    col_input, col_action = st.columns([3, 1])
    url_in = col_input.text_input("Target URL", placeholder="http://42.57.189.23/bin.sh", label_visibility="collapsed")
    
    if col_action.button("SCAN TARGET", use_container_width=True) and url_in:
        with st.spinner("🚀 Initializing Cyber-Forensics Modules..."):
            
            # Pipeline
            is_typo, real, ratio, is_whitelisted = check_typosquatting(url_in, TOP_DOMAINS)
            ai_prob = predict_url(url_in)
            net_report, net_risk = scan_url_deep_forensics(url_in)
            
            # Logic giải thích
            risk, reasons, deep_log = explain_url_risk_combined(url_in, ai_prob, is_typo, real, net_report, net_risk, is_whitelisted)
            
            st.divider()
            
            # Recommendation Logic (FIXED: MEDIUM IS NOW UNSAFE)
            if risk in ["HIGH", "CRITICAL"]:
                st.markdown(f"""
                <div class="rec-box rec-DANGER">
                    🛑 RECOMMENDATION: BLOCK ACCESS<br>
                    <span style="font-size:16px; font-weight:normal; opacity:0.9">CRITICAL THREAT DETECTED. DO NOT PROCEED.</span>
                </div>
                """, unsafe_allow_html=True)
            elif risk == "MEDIUM":
                st.markdown(f"""
                <div class="rec-box rec-WARNING">
                    ⚠️ RECOMMENDATION: UNSAFE DETECTED<br>
                    <span style="font-size:16px; font-weight:normal; opacity:0.9">Suspicious patterns found. Proceed with extreme caution.</span>
                </div>
                """, unsafe_allow_html=True)
            else:
                 st.markdown(f"""
                <div class="rec-box rec-SAFE">
                    ✅ RECOMMENDATION: SAFE TO PROCEED<br>
                    <span style="font-size:16px; font-weight:normal; opacity:0.9">Domain verified. No threats found.</span>
                </div>
                """, unsafe_allow_html=True)

            # Dashboard
            c1, c2 = st.columns([1.2, 2])
            color = "#00ff00"
            if risk == "MEDIUM": color = "orange"
            if risk in ["HIGH", "CRITICAL"]: color = "#ff4b4b"
            
            display_prob = 0 if is_whitelisted and risk == "LOW" else int(ai_prob*100)
            
            with c1:
                st.markdown(f"""
                <div class="glass-card" style="text-align:center; height: 100%; display:flex; flex-direction:column; justify-content:center;">
                    <h3 style="margin:0; color:#aaa; font-size:16px; letter-spacing:1px;">THREAT PROBABILITY</h3>
                    <h1 style="color:{color}; font-size:100px; margin:10px 0; text-shadow: 0 0 30px {color};">{display_prob}%</h1>
                    <div style="background:{color}; color:#000; padding:8px 16px; border-radius:6px; font-weight:900; display:inline-block; font-family:'Orbitron'; letter-spacing:2px;">{risk}</div>
                </div>
                """, unsafe_allow_html=True)
            
            with c2:
                st.markdown(f"""
                <div class="glass-card" style="height: 100%;">
                    <h3 style="margin-top:0; border-bottom:1px solid rgba(255,255,255,0.1); padding-bottom:10px;">🧠 INTELLIGENCE REPORT</h3>
                    {''.join([f"<div class='risk-box risk-{risk}'>{r}</div>" for r in reasons])}
                </div>
                """, unsafe_allow_html=True)
            
            # Logs
            with st.expander("📡 NETWORK FORENSICS DATA STREAM"):
                st.caption("Real-time telemetry from target server:")
                c_a, c_b = st.columns(2)
                for i, line in enumerate(deep_log):
                    if i % 2 == 0: c_a.markdown(f"- {line}")
                    else: c_b.markdown(f"- {line}")

# --- FILE TAB ---
with tab_file:
    uploaded = st.file_uploader("Upload PE File (.exe, .dll)", type=["exe", "dll"])
    if uploaded and st.button("INITIATE DEEP SCAN", use_container_width=True):
        with st.spinner("Decompiling Binary & Analyzing PE Structure..."):
            bytes_data = uploaded.read()
            score = predict_file(bytes_data)
            deep_report, risk_count = analyze_pe_deeply(bytes_data)
            
            if score is not None:
                st.divider()
                final_verdict = "SAFE"
                if score > 0.5 or risk_count >= 2: final_verdict = "MALWARE"
                
                if final_verdict == "MALWARE":
                    st.markdown("""<div class="rec-box rec-DANGER">🚫 RECOMMENDATION: ISOLATE & DELETE</div>""", unsafe_allow_html=True)
                else:
                    st.markdown("""<div class="rec-box rec-SAFE">✅ RECOMMENDATION: FILE APPEARS CLEAN</div>""", unsafe_allow_html=True)

                sc1, sc2 = st.columns(2)
                with sc1:
                    st.markdown(f"""<div class="glass-card" style="text-align:center;"><h3>AI PROBABILITY</h3><h1 style="color:{'#ff4b4b' if score > 0.5 else '#00ff00'}; font-size:60px; text-shadow: 0 0 20px {'#ff4b4b' if score > 0.5 else '#00ff00'};">{score*100:.2f}%</h1></div>""", unsafe_allow_html=True)
                with sc2:
                    status_color = "risk-HIGH" if final_verdict == "MALWARE" else "risk-LOW"
                    st.markdown(f"""<div class="glass-card" style="text-align:center; height:100%; display:flex; align-items:center; justify-content:center;"><div class='risk-box {status_color}' style="width:100%; font-size:24px; padding:20px;"><b>{final_verdict}</b></div></div>""", unsafe_allow_html=True)
                
                with st.expander("🔬 DEEP TECHNICAL FORENSICS", expanded=True):
                    for line in deep_report: st.markdown(f"- {line}")