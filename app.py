import streamlit as st
import json
import time
from scripts.threat_classifier import classify_threat

# -------------------------------------------------
# Page Config
# -------------------------------------------------
st.set_page_config(
    page_title="AI-Driven Multi-Cloud Threat Detection",
    page_icon="🛡️",
    layout="wide"
)

# -------------------------------------------------
# Custom CSS (Dark SOC Theme)
# -------------------------------------------------
st.markdown("""
<style>
html, body {
    background-color: #0e1117;
    color: #e5e7eb;
    font-family: 'Inter', sans-serif;
}

/* Title */
.main-title {
    font-size: 2.6rem;
    font-weight: 700;
    background: linear-gradient(90deg, #22d3ee, #6366f1);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background-color: #020617;
    border-right: 1px solid rgba(255,255,255,0.1);
}

/* Cards */
.card {
    background: rgba(255, 255, 255, 0.06);
    border-radius: 18px;
    padding: 20px;
    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
    margin-bottom: 15px;
}

/* Risk colors */
.low { color: #22c55e; font-weight: 700; }
.medium { color: #f59e0b; font-weight: 700; }
.high { color: #ef4444; font-weight: 700; }

/* Pulse */
.pulse {
    animation: pulse 1.5s infinite;
}
@keyframes pulse {
    0% { transform: scale(1); }
    50% { transform: scale(1.05); }
    100% { transform: scale(1); }
}

/* Button */
.stButton button {
    background: linear-gradient(90deg, #6366f1, #22d3ee);
    color: white;
    border-radius: 12px;
    padding: 10px 20px;
    font-weight: 600;
    border: none;
}
section[data-testid="stSidebar"] * {
    color: white !important;
}

</style>
""", unsafe_allow_html=True)

# -------------------------------------------------
# Helper
# -------------------------------------------------
def risk_class(level):
    if level.lower() == "low":
        return "low"
    if level.lower() == "medium":
        return "medium"
    return "high"

# -------------------------------------------------
# SIDEBAR (SOC Navigation)
# -------------------------------------------------
# -------------------------------------------------
# SIDEBAR (REFINED SOC NAVIGATION)
# -------------------------------------------------
with st.sidebar:
    st.markdown(
        """
        <h2 style="color:white;">🛡️ AI-Driven Multi-Cloud Threat Detection</h2>
        <p style="color:#9ca3af;">Real-Time Security Monitoring</p>
        """,
        unsafe_allow_html=True
    )

    page = st.radio(
        "",
        ["🔍 Manual Detection", "📡 Real-Time Monitoring"],
        label_visibility="collapsed"
    )

    st.divider()

    st.markdown(
        "<h4 style='color:white;'>System Status</h4>",
        unsafe_allow_html=True
    )

    st.success("Model Loaded")
    st.info("Anomaly Detection: Active")

# -------------------------------------------------
# MANUAL DETECTION PAGE
# -------------------------------------------------
if page == "🔍 Manual Detection":
    st.markdown("<div class='main-title'>Manual Log Analysis</div>", unsafe_allow_html=True)

    log_input = st.text_area(
        "Paste a single cloud log (JSON format)",
        height=260
    )

    if st.button("🔍 Analyze Log"):
        try:
            log = json.loads(log_input)

            with st.spinner("Analyzing log using ML + rules..."):
                time.sleep(0.8)
                result = classify_threat(log)

            rc = risk_class(result["risk_level"])

            st.markdown(f"""
            <div class="card">
                <p><b>Status:</b> <span class="pulse {rc}">{result['detected_threat']}</span></p>
                <p><b>Risk Level:</b> <span class="{rc}">{result['risk_level']}</span></p>
                <p><b>Confidence:</b> {result['confidence']}</p>
                <p><b>Recommended Action:</b> {result['recommended_action']}</p>
            </div>
            """, unsafe_allow_html=True)

        except Exception as e:
            st.error(f"Invalid JSON input: {e}")

# -------------------------------------------------
# FILE DETECTION PAGE
# -------------------------------------------------
elif page == "📡 Real-Time Monitoring":
    st.markdown("<div class='main-title'>Log File Analysis</div>", unsafe_allow_html=True)

    uploaded_file = st.file_uploader("Upload cloud logs (JSON)", type=["json"])

    if uploaded_file:
        try:
            logs = json.load(uploaded_file)

            with st.spinner("Processing logs in real time..."):
                time.sleep(1)

            st.success(f"Loaded {len(logs)} logs")

            for i, log in enumerate(logs):
                result = classify_threat(log)
                rc = risk_class(result["risk_level"])

                st.markdown(f"""
                <div class="card">
                    <p><b>Log #{i+1}</b></p>
                    <p>Cloud: {log.get('cloud_provider')}</p>
                    <p>Operation: {log.get('operation')}</p>
                    <p>User: {log.get('user')}</p>
                    <p>Status: <span class="pulse {rc}">{result['detected_threat']}</span></p>
                    <p>Risk: <span class="{rc}">{result['risk_level']}</span> | Confidence: {result['confidence']}</p>
                </div>
                """, unsafe_allow_html=True)

            st.success("Detection completed")

        except Exception as e:
            st.error(f"Failed to process file: {e}")

