# 🦅 dashboard.py
# ---------------------------------------------------------
# SentinelHawk SOC Dashboard — Live Threat Feed with Detailed PDF Export
# ---------------------------------------------------------

import streamlit as st
import time
import os
from datetime import datetime
try:
    from fpdf import FPDF
except ImportError:
    FPDF = None

try:
    from nest.ingestion import LogIngestion
    from nest.event_normalizer import EventNormalizer
    from nest.baseline_engine import BaselineEngine
    from nest.correlation_engine import CorrelationEngine
    from nest.talonscore import TalonScore
    from report_engine import ReportEngine
except ImportError:
    st.error("Please run streamlit from the root directory: `streamlit run dashboard.py`")

st.set_page_config(layout="wide", page_title="SentinelHawk SOC")
st.title("🦅 SentinelHawk — Autonomous Threat Monitoring & Response AI")

# Initialize engines
@st.cache_resource
def get_engines():
    return {
        "ingestion": LogIngestion(),
        "baseline": BaselineEngine(),
        "correlation": CorrelationEngine(),
        "scorer": TalonScore(),
        "reporter": ReportEngine()
    }

engines = get_engines()

def get_color_from_score(scoring):
    """Get color information from the scoring data"""
    return {
        "risk_color": scoring.get("risk_color", {}).get("hex", "#FFD700"),
        "confidence_color": scoring.get("confidence_color", {}).get("hex", "#FFD700"),
        "severity": scoring.get("severity", "MEDIUM")
    }

def generate_detailed_pdf_report(threats, filename=None):
    """Generate a detailed PDF report from threat feed data with proper formatting"""
    if not FPDF:
        st.error("PDF generation requires fpdf2. Install with: pip install fpdf2")
        return None
    
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"SentinelHawk_Threat_Report_{timestamp}.pdf"
    
    try:
        pdf = FPDF()
        pdf.add_page()
        
        # ===== TITLE =====
        pdf.set_font("Arial", style="B", size=16)
        pdf.cell(0, 12, txt="SentinelHawk SOC Threat Report", ln=True, align="C")
        
        # ===== TIMESTAMP =====
        pdf.set_font("Arial", size=10)
        pdf.cell(0, 10, txt=f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        pdf.ln(5)
        
        # ===== SUMMARY STATISTICS =====
        pdf.set_font("Arial", style="B", size=12)
        pdf.cell(0, 10, txt=f"Total Threats Detected: {len(threats)}", ln=True)
        
        critical_count = sum(1 for t in threats if t.get("severity") == "CRITICAL")
        high_count = sum(1 for t in threats if t.get("severity") == "HIGH")
        medium_count = sum(1 for t in threats if t.get("severity") == "MEDIUM")
        low_count = sum(1 for t in threats if t.get("severity") == "LOW")
        
        pdf.set_font("Arial", size=10)
        pdf.cell(0, 8, txt=f"Critical: {critical_count} | High: {high_count} | Medium: {medium_count} | Low: {low_count}", ln=True)
        
        if threats:
            avg_risk = sum(t.get("risk", 0) for t in threats) / len(threats)
            pdf.cell(0, 8, txt=f"Average Risk Score: {avg_risk:.2f}", ln=True)
        
        pdf.ln(5)
        
        # ===== DETAILED THREAT INFORMATION WITH PAGE BREAKS =====
        pdf.set_font("Arial", style="B", size=11)
        pdf.cell(0, 8, txt="Detailed Threat Analysis:", ln=True)
        pdf.set_font("Arial", size=8)
        
        for i, threat in enumerate(threats, 1):
            if pdf.will_page_break(20):
                pdf.add_page()
            
            # Threat header
            pdf.set_font("Arial", style="B", size=9)
            severity = threat.get("severity", "N/A")
            risk = threat.get("risk", "N/A")
            pdf.cell(0, 7, txt=f"Threat #{i} - [{severity}] Risk Score: {risk}", ln=True)
            
            # Threat details
            pdf.set_font("Arial", size=7)
            event_name = str(threat.get("event_name", "N/A")).encode('latin-1', 'replace').decode('latin-1')
            event_id = str(threat.get("event_id", "N/A")).encode('latin-1', 'replace').decode('latin-1')
            user = str(threat.get("user", "N/A")).encode('latin-1', 'replace').decode('latin-1')
            host = str(threat.get("host", "N/A")).encode('latin-1', 'replace').decode('latin-1')
            ip = str(threat.get("ip", "N/A")).encode('latin-1', 'replace').decode('latin-1')
            confidence = threat.get("confidence", "N/A")
            
            pdf.multi_cell(0, 5, txt=f"Event Name: {event_name}")
            pdf.multi_cell(0, 5, txt=f"Event ID: {event_id}")
            pdf.multi_cell(0, 5, txt=f"User: {user}")
            pdf.multi_cell(0, 5, txt=f"Host: {host}")
            pdf.multi_cell(0, 5, txt=f"IP Address: {ip}")
            pdf.multi_cell(0, 5, txt=f"Confidence Level: {confidence}")
            
            pdf.ln(2)
        
        # ===== RECOMMENDATIONS PAGE =====
        pdf.add_page()
        pdf.set_font("Arial", style="B", size=11)
        pdf.cell(0, 8, txt="Recommendations:", ln=True)
        pdf.set_font("Arial", size=9)
        
        if critical_count > 0:
            pdf.multi_cell(180, 5, txt=f"- IMMEDIATE ACTION: {critical_count} critical threat(s) detected. Investigate immediately.")
        if high_count > 0:
            pdf.multi_cell(180, 5, txt=f"- PRIORITY: {high_count} high-risk threat(s) should be addressed within 24 hours.")
        if medium_count > 0:
            pdf.multi_cell(180, 5, txt=f"- REVIEW: {medium_count} medium-risk threat(s) for assessment.")
        pdf.multi_cell(180, 5, txt="- Continue monitoring for suspicious activity patterns.")
        
        # ===== FOOTER =====
        pdf.ln(5)
        pdf.set_font("Arial", style="I", size=8)
        pdf.cell(0, 8, txt="SentinelHawk Autonomous Threat Monitoring Dashboard", ln=True, align="C")
        
        # Save to reports folder
        reports_dir = "reports"
        os.makedirs(reports_dir, exist_ok=True)
        filepath = os.path.join(reports_dir, filename)
        
        try:
            pdf.output(filepath)
            return filepath
        except Exception as e:
            st.error(f"Failed to save PDF: {e}")
            return None
    
    except Exception as e:
        st.error(f"PDF Generation Error: {e}")
        return None

# Sidebar for controls
st.sidebar.title("Controls")
refresh_interval = st.sidebar.slider("Auto-refresh interval (seconds)", 5, 60, 10)

st.subheader("Live Threat Feed")

col1, col2, col3 = st.columns([3, 1, 1])

with col1:
    run_btn = st.button("Refresh Feed", key="refresh_btn")

with col2:
    export_pdf = st.button("Export PDF", key="export_pdf")

with col3:
    export_report = st.button("Full Report", key="export_report")

# Store threats in session state for export
if "threats" not in st.session_state:
    st.session_state.threats = []

if run_btn:
    with st.spinner("Fetching logs..."):
        events = engines["ingestion"].fetch_logs()
        st.session_state.threats = []
        
        for raw in events:
            event = EventNormalizer.normalize(raw)
            anomaly = engines["baseline"].analyze(event)
            corr = engines["correlation"].analyze(event)

            scoring = engines["scorer"].score({
                "event": event,
                "anomaly_score": anomaly,
                "correlation_score": corr,
                "mitre": []
            })

            colors = get_color_from_score(scoring)
            severity = scoring.get("severity", "MEDIUM")
            risk_color = colors["risk_color"]
            confidence_color = colors["confidence_color"]
            
            threat_data = {
                "id": scoring.get('id', 'N/A'),
                "timestamp": datetime.now().isoformat(),
                "event": event,
                "severity": severity,
                "risk": scoring['risk'],
                "confidence": scoring['confidence'],
                "mitre": scoring.get('mitre', []),
                "risk_color": risk_color,
                "confidence_color": confidence_color
            }
            st.session_state.threats.append(threat_data)
            
            with st.container():
                st.markdown(
                    f"""
                    <div style="border-left: 5px solid {risk_color}; background-color: #262730; padding: 10px; margin-bottom: 10px; border-radius: 5px;">
                        <h3 style="color: {risk_color}; margin: 0;">{severity} | Risk Score: {scoring['risk']}</h3>
                        <p><b>Event:</b> {event.get('event_name')} ({event.get('event_id')})<br>
                        <b>User:</b> {event.get('user')} | <b>Host:</b> {event.get('host')} | <b>IP:</b> {event.get('ip')}</p>
                        <p style="font-size: 0.8em; color: {confidence_color};">Confidence: {scoring['confidence']}</p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

# Export quick PDF
if export_pdf and st.session_state.threats:
    pdf_path = generate_detailed_pdf_report(st.session_state.threats)
    if pdf_path:
        st.success(f"PDF Report generated: {pdf_path}")
        with open(pdf_path, "rb") as f:
            st.download_button(
                label="Download PDF Report",
                data=f.read(),
                file_name=os.path.basename(pdf_path),
                mime="application/pdf"
            )
elif export_pdf and not st.session_state.threats:
    st.warning("No threats to export. Refresh the feed first.")

# Generate full detailed report using ReportEngine
if export_report:
    if st.session_state.threats:
        st.info("Generating comprehensive report with decision memory...")
        try:
            reporter = engines["reporter"]
            reporter.generate(st.session_state.threats)
            reporter.generate_dashboard_pdf(st.session_state.threats)
            reporter.generate_decision_memory_txt(st.session_state.threats)
            reporter.generate_decision_memory_pdf(st.session_state.threats)
            st.success(f"Full reports (TXT, JSON, PDF) generated in: {reporter.base_dir}")
        except Exception as e:
            st.error(f"Error generating full report: {e}")
    else:
        st.warning("No threats to report. Refresh the feed first.")

st.sidebar.info(f"Feed updates every {refresh_interval}s when in live mode")
