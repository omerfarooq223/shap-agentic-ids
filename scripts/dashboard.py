import streamlit as st
import requests
import pandas as pd
import time

st.set_page_config(page_title="Agentic IDS Dashboard", layout="wide")

st.title("🛡️ SHAP-Explained Agentic IDS Dashboard")
st.markdown("Monitor network flows, view SHAP feature attributions, and track LangGraph agent reasoning.")

# Sidebar for testing
st.sidebar.header("Simulate Network Flow")
st.sidebar.markdown("Submit a flow to the Flask API for detection.")

real_attack_vector = {"Destination Port":1998,"Flow Duration":35,"Total Fwd Packets":1,"Total Backward Packets":1,"Total Length of Fwd Packets":2,"Total Length of Bwd Packets":6,"Fwd Packet Length Max":2,"Fwd Packet Length Min":2,"Fwd Packet Length Mean":2.0,"Fwd Packet Length Std":0.0,"Bwd Packet Length Max":6,"Bwd Packet Length Min":6,"Bwd Packet Length Mean":6.0,"Bwd Packet Length Std":0.0,"Flow Bytes/s":228571.4286,"Flow Packets/s":57142.85714,"Flow IAT Mean":35.0,"Flow IAT Std":0.0,"Flow IAT Max":35,"Flow IAT Min":35,"Fwd IAT Total":0,"Fwd IAT Mean":0.0,"Fwd IAT Std":0.0,"Fwd IAT Max":0,"Fwd IAT Min":0,"Bwd IAT Total":0,"Bwd IAT Mean":0.0,"Bwd IAT Std":0.0,"Bwd IAT Max":0,"Bwd IAT Min":0,"Fwd PSH Flags":0,"Bwd PSH Flags":0,"Fwd URG Flags":0,"Bwd URG Flags":0,"Fwd Header Length":24,"Bwd Header Length":20,"Fwd Packets/s":28571.42857,"Bwd Packets/s":28571.42857,"Min Packet Length":2,"Max Packet Length":6,"Packet Length Mean":3.333333333,"Packet Length Std":2.309401077,"Packet Length Variance":5.333333333,"FIN Flag Count":0,"SYN Flag Count":0,"RST Flag Count":0,"PSH Flag Count":1,"ACK Flag Count":0,"URG Flag Count":0,"CWE Flag Count":0,"ECE Flag Count":0,"Down/Up Ratio":1,"Average Packet Size":5.0,"Avg Fwd Segment Size":2.0,"Avg Bwd Segment Size":6.0,"Fwd Header Length.1":24,"Fwd Avg Bytes/Bulk":0,"Fwd Avg Packets/Bulk":0,"Fwd Avg Bulk Rate":0,"Bwd Avg Bytes/Bulk":0,"Bwd Avg Packets/Bulk":0,"Bwd Avg Bulk Rate":0,"Subflow Fwd Packets":1,"Subflow Fwd Bytes":2,"Subflow Bwd Packets":1,"Subflow Bwd Bytes":6,"Init_Win_bytes_forward":1024,"Init_Win_bytes_backward":0,"act_data_pkt_fwd":0,"min_seg_size_forward":24,"Active Mean":0.0,"Active Std":0.0,"Active Max":0,"Active Min":0,"Idle Mean":0.0,"Idle Std":0.0,"Idle Max":0,"Idle Min":0}

dummy_flow = {
    "src_ip": st.sidebar.text_input("Source IP", "205.174.165.73"),
    "dst_ip": st.sidebar.text_input("Dest IP", "192.168.10.50"),
    "dst_port": st.sidebar.number_input("Dest Port", 1998)
}
dummy_flow.update(real_attack_vector)

if st.sidebar.button("Analyze Flow"):
    with st.spinner("Agent is analyzing flow..."):
        try:
            # Send to Flask API
            start_time = time.time()
            res = requests.post("http://localhost:5005/detect", json={"flow": dummy_flow})
            latency = (time.time() - start_time) * 1000
            
            if res.status_code == 200:
                data = res.json()
                
                if not data.get("anomaly"):
                    st.success(f"✅ Flow is BENIGN (Confidence: {data.get('ml_confidence', 0):.2f})")
                else:
                    st.error(f"🚨 ANOMALY DETECTED (Risk Score: {data.get('risk_score')}/10)")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.subheader("🤖 Agent Reasoning")
                        st.write(f"**Threat Classification:** `{str(data.get('threat_type')).upper()}`")
                        st.write(f"**AbuseIPDB Score:** {data.get('threat_intel', {}).get('abuse_score')}/100")
                        st.write(f"**MITRE ATT&CK:** {data.get('threat_intel', {}).get('mitre_tactic')}")
                        st.info(f"**Recommendation:** {data.get('recommendation')}")
                        st.write(f"**Latency:** {latency:.0f}ms")
                        
                    with col2:
                        st.subheader("📊 SHAP Explainability (Top 5 Features)")
                        shap_data = data.get("shap_explanation", [])
                        if shap_data:
                            df_shap = pd.DataFrame(shap_data)
                            st.dataframe(df_shap.set_index("feature"))
            else:
                st.error(f"API Error: {res.text}")
        except requests.exceptions.ConnectionError:
            st.error("Cannot connect to API. Is Flask running? (Run: `python src/app.py`)")
