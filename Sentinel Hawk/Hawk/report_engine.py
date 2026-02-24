# 🦅 report_engine.py
# ---------------------------------------------------------
# SentinelHawk — Reporting Engine
# Generates TXT, JSON, and THREE distinct PDF types
# ---------------------------------------------------------
import os
import json
import re
from datetime import datetime
from models import Colors

try:
    from fpdf import FPDF
except ImportError:
    FPDF = None


class ReportEngine:
    """Main reporting engine for SentinelHawk SOC"""

    def __init__(self):
        """Initialize report engine with dated directory"""
        self.today = datetime.now().strftime("%m-%d-%Y")
        self.base_dir = f"reports/{self.today}_Report_Logs"
        os.makedirs(self.base_dir, exist_ok=True)
        # Use a fixed timestamp for the entire run to avoid duplicate files
        self.run_id = datetime.now().strftime("%H%M%S")

    def _get_path(self, prefix, ext):
        """Helper to get standardized report path"""
        return f"{self.base_dir}/{self.today}_{prefix}_{self.run_id}.{ext}" if self.run_id else f"{self.base_dir}/{self.today}_{prefix}.{ext}"

    def generate(self, incidents):
        """Generate TXT, JSON, and Full Report PDF"""

        print(Colors.bold_colored("\n=== SentinelHawk Report Generation ===", Colors.AQUA))
        
        # TXT
        try:
            txt_path = self._generate_txt_report(incidents)
            print(f"  [+] TXT Report: {os.path.basename(txt_path)}")
        except Exception as e:
            print(f"  [-] TXT Report Failed: {e}")

        # JSON
        try:
            json_path = self._generate_json_data(incidents)
            print(f"  [+] JSON Data:  {os.path.basename(json_path)}")
        except Exception as e:
            print(f"  [-] JSON Data Failed: {e}")

        # PDF
        try:
            pdf_path = self._generate_full_report_pdf(incidents)
            if pdf_path:
                print(f"  [+] Full PDF:   {os.path.basename(pdf_path)}")
            else:
                print(f"  [-] Full PDF Failed (check logs)")
        except Exception as e:
            print(f"  [-] Full PDF Error: {e}")
        
        print(f"\nReports saved to: {self.base_dir}")

    def _generate_txt_report(self, incidents):
        """Generate detailed human-readable TXT report"""
        txt_path = self._get_path("Report", "TXT")
        
        with open(txt_path, "w", encoding='utf-8') as f:
            f.write("=" * 120 + "\n")
            f.write("SENTINELHAWK SOC DETAILED INCIDENT REPORT\n")
            f.write("=" * 120 + "\n")
            f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Report Period: {self.today}\n")
            f.write(f"Total Incidents Analyzed: {len(incidents)}\n")
            f.write("=" * 120 + "\n\n")
            
            if incidents:
                # Calculate counts using a helper or loop
                critical = 0
                high = 0
                medium = 0
                low = 0
                total_risk = 0
                
                for incident in incidents:
                    data = incident.to_dict() if hasattr(incident, 'to_dict') else (incident if isinstance(incident, dict) else vars(incident))
                    risk = data.get('risk', 0)
                    total_risk += risk
                    if risk >= 80: critical += 1
                    elif risk >= 60: high += 1
                    elif risk >= 40: medium += 1
                    else: low += 1

                f.write("EXECUTIVE SUMMARY\n")
                f.write("-" * 120 + "\n")
                f.write(f"Total Incidents:         {len(incidents)}\n")
                f.write(f"Critical Risk (>=80):    {critical}\n")
                f.write(f"High Risk (60-79):       {high}\n")
                f.write(f"Medium Risk (40-59):     {medium}\n")
                f.write(f"Low Risk (<40):          {low}\n")
                f.write(f"Average Risk Score:      {total_risk / len(incidents):.2f}\n" if incidents else f"Average Risk Score:      0.00\n")
                f.write("\n" + "=" * 120 + "\n\n")
                
                f.write("DETAILED INCIDENT ANALYSIS\n")
                f.write("-" * 120 + "\n\n")
                
                for idx, incident in enumerate(incidents, 1):
                    f.write(f"INCIDENT #{idx}\n")
                    f.write("-" * 120 + "\n")
                    
                    incident_data = incident.to_dict() if hasattr(incident, 'to_dict') else (incident if isinstance(incident, dict) else vars(incident))
                    
                    for key, value in incident_data.items():
                        if isinstance(value, dict):
                            for k, v in value.items():
                                sub_key = f"{key} {k}".replace('_', ' ').title()
                                f.write(f"  {sub_key:<50}: {v}\n")
                        else:
                            formatted_key = key.replace('_', ' ').title()
                            f.write(f"  {formatted_key:<50}: {value}\n")
                    
                    f.write("\n")
                
                f.write("=" * 120 + "\n\n")
                f.write("RECOMMENDATIONS\n")
                f.write("-" * 120 + "\n")
                if critical > 0:
                    f.write(f"- IMMEDIATE ACTION REQUIRED: {critical} critical incidents require immediate investigation and response.\n")
                f.write("- Continue monitoring for suspicious activity patterns.\n")
            return txt_path

    def _generate_json_data(self, incidents):
        """Generate JSON data file"""
        json_path = self._get_path("Data", "JSON")
        
        try:
            incident_records = []
            for incident in incidents:
                if hasattr(incident, 'to_dict'):
                    incident_records.append(incident.to_dict())
                else:
                    incident_records.append(incident if isinstance(incident, dict) else vars(incident))
            
            critical_count = sum(1 for r in incident_records if r.get('risk', 0) >= 80)
            high_count = sum(1 for r in incident_records if 60 <= r.get('risk', 0) < 80)
            medium_count = sum(1 for r in incident_records if 40 <= r.get('risk', 0) < 60)
            low_count = sum(1 for r in incident_records if r.get('risk', 0) < 40)
            
            json_data = {
                "metadata": {
                    "generated": datetime.now().isoformat(),
                    "report_date": self.today,
                    "total_incidents": len(incident_records),
                    "system": "SentinelHawk SOC"
                },
                "summary": {
                    "critical_count": critical_count,
                    "high_count": high_count,
                    "medium_count": medium_count,
                    "low_count": low_count
                },
                "incidents": incident_records
            }
            
            with open(json_path, "w", encoding='utf-8') as f:
                json.dump(json_data, f, indent=4)
            return json_path
        except Exception as e:
            print(f"Error generating JSON: {e}")

    def _generate_full_report_pdf(self, incidents):
        """Generate FULL REPORT PDF - Comprehensive incident analysis with MITRE, detailed context, and remediation"""
        if not FPDF:
            print("ERROR: fpdf2 not installed")
            return None
        
        try:
            pdf = FPDF(format='A4')
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()
            
            # TITLE PAGE
            pdf.set_font("Arial", style="B", size=18)
            pdf.cell(0, 12, txt="SENTINELHAWK FULL REPORT", ln=True, align="C")
            pdf.set_font("Arial", style="B", size=11)
            pdf.cell(0, 10, txt="Comprehensive Incident Analysis with Remediation Guidance", ln=True, align="C")
            pdf.set_font("Arial", size=9)
            pdf.cell(0, 8, txt="For SOC Analysts, Incident Responders, Auditors & Compliance Teams", ln=True, align="C")
            pdf.ln(5)
            pdf.cell(0, 6, txt=f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
            pdf.cell(0, 6, txt=f"Run ID: {self.run_id}", ln=True, align="C")
            pdf.ln(8)
            
            # EXECUTIVE SUMMARY
            pdf.set_font("Arial", style="B", size=12)
            pdf.cell(0, 8, txt="EXECUTIVE SUMMARY", ln=True)
            pdf.ln(2)
            
            pdf.set_font("Arial", size=10)
            pdf.cell(0, 6, txt=f"Total Incidents Detected: {len(incidents)}", ln=True)
            
            if incidents:
                critical = 0; high = 0; medium = 0; low = 0; total_risk = 0
                for i in incidents:
                    data = i.to_dict() if hasattr(i, 'to_dict') else (i if isinstance(i, dict) else vars(i))
                    r = data.get('risk', 0)
                    total_risk += r
                    if r >= 80: critical += 1
                    elif r >= 60: high += 1
                    elif r >= 40: medium += 1
                    else: low += 1
                
                avg_risk = total_risk / len(incidents)
                
                pdf.set_text_color(220, 0, 0)
                pdf.cell(0, 5, txt=f"Critical: {critical}", ln=True)
                pdf.set_text_color(255, 94, 14)
                pdf.cell(0, 5, txt=f"High: {high}", ln=True)
                pdf.set_text_color(220, 180, 0)
                pdf.cell(0, 5, txt=f"Medium: {medium}", ln=True)
                pdf.set_text_color(0, 150, 0)
                pdf.cell(0, 5, txt=f"Low: {low}", ln=True)
                pdf.set_text_color(0, 0, 0)
                pdf.cell(0, 5, txt=f"Average Risk Score: {avg_risk:.2f}", ln=True)
            
            pdf.ln(5)
            
            # THREAT LANDSCAPE
            pdf.set_font("Arial", style="B", size=12)
            pdf.cell(0, 8, txt="THREAT LANDSCAPE & CONTEXT", ln=True)
            pdf.ln(2)
            
            pdf.set_font("Arial", size=9)
            pdf.multi_cell(0, 4, txt="This report analyzes detected security incidents based on event data from Azure Log Analytics. Each incident has been scored, analyzed, and classified according to the MITRE ATT&CK framework to identify attack techniques and tactics. This provides the forensic clarity required for immediate response and long-term security posture improvement.")
            pdf.ln(5)
            
            # DETAILED INCIDENTS
            pdf.set_font("Arial", style="B", size=12)
            pdf.cell(0, 8, txt="DETAILED INCIDENT ANALYSIS", ln=True)
            pdf.ln(3)
            
            for idx, incident in enumerate(incidents, 1):
                if pdf.get_y() > 240:
                    pdf.add_page()
                
                # Incident header
                pdf.set_font("Arial", style="B", size=11)
                pdf.set_text_color(0, 0, 0)
                pdf.cell(0, 7, txt=f"Incident #{idx}", ln=True)
                
                # Risk level with color
                data = incident.to_dict() if hasattr(incident, 'to_dict') else (incident if isinstance(incident, dict) else vars(incident))
                incident_data = json.loads(json.dumps(data)) # Copy
                risk = incident_data.get('risk', 0)
                risk_level = "CRITICAL" if risk >= 80 else "HIGH" if risk >= 60 else "MEDIUM" if risk >= 40 else "LOW"
                
                if risk >= 80:
                    pdf.set_text_color(220, 0, 0)
                elif risk >= 60:
                    pdf.set_text_color(255, 94, 14)
                elif risk >= 40:
                    pdf.set_text_color(220, 180, 0)
                else:
                    pdf.set_text_color(0, 150, 0)
                
                pdf.cell(0, 6, txt=f"[{risk_level}] Risk Score: {risk}", ln=True)
                pdf.ln(2)
                
                # Core details
                pdf.set_text_color(0, 0, 0)
                status_value = incident_data.pop('status', "N/A")
                raw_log = incident_data.pop('raw', None)
                if not raw_log and isinstance(incident_data.get('event'), dict):
                    raw_log = incident_data.get('event').pop('raw', None)

                # MITRE Mapping
                mitre_tags = incident_data.get('mitre', [])
                if mitre_tags and isinstance(mitre_tags, list):
                    pdf.set_font("Arial", style="B", size=9)
                    pdf.cell(0, 5, txt="MITRE ATT&CK MAPPING:", ln=True)
                    pdf.set_font("Arial", size=9)
                    pdf.write(4, f"Techniques detected: {', '.join(map(str, mitre_tags))}\n")
                    pdf.ln(2)

                # Basic Fields (No truncation)
                for key, value in incident_data.items():
                    if pdf.get_y() > 260:
                        pdf.add_page()
                    
                    if isinstance(value, dict):
                        for k, v in value.items():
                            sub_key = f"{key} {k}".replace('_', ' ').title()
                            pdf.set_font("Arial", style="B", size=9)
                            pdf.set_text_color(80, 80, 80)
                            pdf.write(4.5, f"{sub_key}: ")
                            pdf.set_font("Arial", size=9)
                            pdf.set_text_color(0, 0, 0)
                            pdf.write(4.5, f"{v}\n")
                    else:
                        formatted_key = key.replace('_', ' ').title()
                        safe_value = str(value).encode('latin-1', 'replace').decode('latin-1')
                        pdf.set_font("Arial", style="B", size=9)
                        pdf.set_text_color(80, 80, 80)
                        pdf.write(4.5, f"{formatted_key}: ")
                        pdf.set_font("Arial", size=9)
                        pdf.set_text_color(0, 0, 0)
                        pdf.write(4.5, f"{safe_value}\n")

                # RAW FORENSIC SECTION
                if raw_log:
                    pdf.ln(3)
                    pdf.set_font("Arial", style="B", size=9)
                    pdf.set_text_color(180, 0, 0)
                    pdf.cell(0, 6, txt="RAW FORENSIC DATA LOG:", ln=True)
                    pdf.set_font("Courier", size=8)
                    pdf.set_text_color(40, 40, 40)
                    safe_raw = str(raw_log).encode('latin-1', 'replace').decode('latin-1')
                    pdf.write(4, f"{safe_raw}\n")
                
                # Status at end
                if status_value:
                    pdf.ln(2)
                    pdf.set_font("Arial", style="B", size=9)
                    pdf.set_text_color(0, 0, 0)
                    pdf.cell(0, 6, txt=f"Current Status: {status_value}", ln=True)
                
                pdf.ln(5)
            
            # REMEDIATION GUIDANCE PAGE
            pdf.add_page()
            pdf.set_font("Arial", style="B", size=13)
            pdf.cell(0, 8, txt="STRUCTURED REMEDIATION GUIDANCE", ln=True)
            pdf.ln(2)
            
            pdf.set_font("Arial", style="B", size=10)
            pdf.cell(0, 7, txt="Operational Response Protocol by Severity Level:", ln=True)
            pdf.ln(3)
            
            # CRITICAL
            pdf.set_font("Arial", style="B", size=10)
            pdf.set_text_color(220, 0, 0)
            pdf.cell(0, 7, txt="CRITICAL INCIDENTS (Risk >= 80):", ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Arial", size=9)
            pdf.multi_cell(0, 4.5, txt="Containment: Immediately isolate affected systems from network. Block suspicious IPs at firewall.\nInvestigation: Collect logs and forensic evidence. Analyze attack patterns for lateral movement.\nRecovery: Restore from clean backups after threat elimination and forensic sign-off.")
            pdf.ln(2)
            
            # HIGH
            pdf.set_font("Arial", style="B", size=10)
            pdf.set_text_color(255, 94, 14)
            pdf.cell(0, 7, txt="HIGH RISK INCIDENTS (Risk 60-79):", ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Arial", size=9)
            pdf.multi_cell(0, 4.5, txt="Containment: Restrict account privileges. Reset compromised credentials immediately.\nInvestigation: Deep-dive event analysis. Review related authentication logs across last 24h.\nRecovery: Apply security patches, update configuration rules, and verify system integrity.")
            pdf.ln(2)
            
            # MEDIUM
            pdf.set_font("Arial", style="B", size=10)
            pdf.set_text_color(220, 180, 0)
            pdf.cell(0, 7, txt="MEDIUM RISK INCIDENTS (Risk 40-59):", ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Arial", size=9)
            pdf.multi_cell(0, 4.5, txt="Review: Assess impact and reach of the event. Determine if this matches known internal patterns.\nMonitoring: Add entities to high-fidelity watch lists. Enhance alerting threshold for related users.\nPrevention: Implement mitigating controls and update firewall/EDR policies.")
            pdf.ln(2)
            
            # LOW
            pdf.set_font("Arial", style="B", size=10)
            pdf.set_text_color(0, 150, 0)
            pdf.cell(0, 7, txt="LOW RISK INCIDENTS (Risk < 40):", ln=True)
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Arial", size=9)
            pdf.multi_cell(0, 4.5, txt="Monitor: Track for frequency increase. Document findings for periodic review.\nDocument: Maintain audit trail. Log in internal ticket system for baseline references.\nPrevention: Continue standard security hygiene and user training.")
            
            pdf_path = self._get_path("Full_Report", "PDF")
            pdf.output(pdf_path)
            return pdf_path
        except Exception as e:
            print(f"ERROR generating Full PDF: {e}")
            import traceback
            traceback.print_exc()
            return None

    def generate_dashboard_pdf(self, incidents=None):
        """Generate SOC DASHBOARD PDF with vertical bar chart"""
        if incidents is None:
            incidents = []
        
        if not FPDF:
            return None
        
        try:
            pdf = FPDF(format='A4')
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()
            
            # TITLE
            pdf.set_font("Arial", style="B", size=16)
            pdf.cell(0, 10, txt="SENTINELHAWK SOC DASHBOARD", ln=True, align="C")
            pdf.set_font("Arial", size=9)
            pdf.cell(0, 6, txt=f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
            pdf.cell(0, 6, txt=f"Run ID: {self.run_id}", ln=True, align="C")
            pdf.ln(6)
            
            # SECTION 1: OVERVIEW
            pdf.set_font("Arial", style="B", size=11)
            pdf.cell(0, 7, txt="SOC Executive Overview:", ln=True)
            pdf.ln(2)
            
            # SECTION 2: BAR CHART
            pdf.set_font("Arial", style="B", size=11)
            pdf.cell(0, 7, txt="Incident Severity Distribution:", ln=True)
            pdf.ln(3)
            
            if incidents:
                critical = 0; high = 0; medium = 0; low = 0
                for i in incidents:
                    data = i.to_dict() if hasattr(i, 'to_dict') else (i if isinstance(i, dict) else vars(i))
                    r = data.get('risk', 0)
                    if r >= 80: critical += 1
                    elif r >= 60: high += 1
                    elif r >= 40: medium += 1
                    else: low += 1
                
                # VERTICAL BAR CHART
                max_val = max(critical, high, medium, low) if max(critical, high, medium, low) > 0 else 1
                bar_height = 35
                bar_width = 18
                spacing = 10
                start_x = 50
                chart_y = pdf.get_y()
                
                x_pos = start_x
                
                # Helper for bars
                for val, label, color in [
                    (critical, "Critical", (220, 0, 0)),
                    (high, "High", (255, 94, 14)),
                    (medium, "Medium", (220, 180, 0)),
                    (low, "Low", (0, 150, 0))
                ]:
                    bar_len = (val / max_val) * bar_height
                    pdf.set_fill_color(*color)
                    pdf.rect(x_pos, chart_y + bar_height - bar_len, bar_width, bar_len, 'F')
                    pdf.set_font("Arial", size=8)
                    pdf.set_text_color(*color)
                    pdf.set_xy(x_pos - 2, chart_y + bar_height + 2)
                    pdf.cell(bar_width + 4, 4, txt=str(val), align='C')
                    pdf.set_text_color(0, 0, 0)
                    pdf.set_xy(x_pos - 4, chart_y + bar_height + 7)
                    pdf.cell(bar_width + 8, 4, txt=label, align='C')
                    x_pos += bar_width + spacing
                
                pdf.set_xy(0, chart_y + bar_height + 20)
                pdf.ln(5)
                
                # INCIDENT LIST
                pdf.set_font("Arial", style="B", size=11)
                pdf.cell(0, 7, txt="Incident Details:", ln=True)
                pdf.ln(2)
                
                pdf.set_font("Arial", size=9)
                for idx, incident in enumerate(incidents, 1):
                    if pdf.get_y() > 260:
                        pdf.add_page()
                    
                    data = incident.to_dict() if hasattr(incident, 'to_dict') else (incident if isinstance(incident, dict) else vars(incident))
                    risk = data.get('risk', 0)
                    risk_level = "CRITICAL" if risk >= 80 else "HIGH" if risk >= 60 else "MEDIUM" if risk >= 40 else "LOW"
                    
                    event_data = data.get('event', {})
                    if not isinstance(event_data, dict): event_data = {}
                    
                    event_name = event_data.get('event_name', 'Unknown')
                    host = event_data.get('host', 'Unknown')
                    ip = event_data.get('ip', 'Unknown')
                    inc_id = data.get('id', 'N/A')
                    
                    pdf.set_text_color(0, 0, 0)
                    pdf.write(5, f"{idx}. ID: {inc_id} | Host: {host} triggered {event_name} from IP {ip} (")
                    
                    if risk >= 80: pdf.set_text_color(220, 0, 0)
                    elif risk >= 60: pdf.set_text_color(255, 94, 14)
                    elif risk >= 40: pdf.set_text_color(220, 180, 0)
                    else: pdf.set_text_color(0, 150, 0)
                    
                    pdf.write(5, f"{risk_level}")
                    pdf.set_text_color(0, 0, 0)
                    pdf.write(5, f" - Risk: {risk})\n")
                    pdf.ln(2)
            
            pdf_path = self._get_path("SOC_Dashboard", "PDF")
            pdf.output(pdf_path)
            return pdf_path
        except Exception as e:
            print(f"ERROR: {e}")
            return None

    def generate_decision_memory_txt(self, incidents=None):
        """Generate decision memory TXT"""
        if incidents is None:
            incidents = []
        
        txt_path = self._get_path("Decision_Memory", "TXT")
        
        try:
            with open(txt_path, "w", encoding='utf-8') as f:
                f.write("=" * 120 + "\n")
                f.write("SENTINELHAWK DECISION MEMORY ARCHIVE\n")
                f.write("=" * 120 + "\n\n")
                
                if incidents:
                    for i, incident in enumerate(incidents, 1):
                        f.write(f"DECISION #{i}\n")
                        f.write("-" * 120 + "\n")
                        
                        data = incident.to_dict() if hasattr(incident, 'to_dict') else (incident if isinstance(incident, dict) else vars(incident))
                        for key, value in data.items():
                            formatted_key = key.replace('_', ' ').title()
                            f.write(f"{formatted_key}: {value}\n")
                        f.write("\n")
            return txt_path
        except Exception as e:
            print(f"Error generating Decision TXT: {e}")
            return None

    def generate_decision_memory_pdf(self, incidents=None):
        """Generate DECISION MEMORY PDF - Structured for ML training with metrics"""
        if incidents is None:
            incidents = []
        
        if not FPDF:
            return None
        
        pdf_path = self._get_path("Decision_Memory", "PDF")
        
        try:
            pdf = FPDF(format='A4')
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()
            
            # TITLE
            pdf.set_font("Arial", style="B", size=16)
            pdf.cell(0, 10, txt="Decision Memory Archive", ln=True, align="C")
            pdf.set_font("Arial", size=9)
            pdf.cell(0, 6, txt="Historical Decision Data for ML Training & Algorithmic Optimization", ln=True, align="C")
            pdf.cell(0, 6, txt=f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
            pdf.cell(0, 6, txt=f"Run ID: {self.run_id}", ln=True, align="C")
            pdf.ln(5)
            
            # ARCHIVE METADATA
            pdf.set_font("Arial", style="B", size=11)
            pdf.cell(0, 7, txt="Archive Summary:", ln=True)
            pdf.ln(1)
            
            pdf.set_font("Arial", size=9)
            pdf.cell(0, 5, txt=f"Total Decisions Archived: {len(incidents)}", ln=True)
            pdf.cell(0, 5, txt=f"Archive Context: {self.today}", ln=True)
            pdf.cell(0, 5, txt="Data Retention: Optimized for machine learning trend analysis and pattern recognition.", ln=True)
            pdf.ln(3)
            
            # PURPOSE
            pdf.set_font("Arial", style="B", size=10)
            pdf.cell(0, 6, txt="Purpose Statement:", ln=True)
            pdf.set_font("Arial", size=8.5)
            pdf.multi_cell(0, 4, txt="This document preserves structured incident decisions, risk scores, and response actions. By archiving this data, SentinelHawk enables long-term pattern recognition and ML-driven improvements to detection accuracy. This data serves as the 'gold standard' for periodic model retraining.")
            pdf.ln(4)
            
            # DECISION METRICS
            if incidents:
                pdf.set_font("Arial", style="B", size=11)
                pdf.cell(0, 7, txt="Algorithmic Metrics:", ln=True)
                pdf.ln(1)
                
                critical = 0; high = 0; medium = 0; low = 0; total_risk = 0
                for i in incidents:
                    data = i.to_dict() if hasattr(i, 'to_dict') else (i if isinstance(i, dict) else vars(i))
                    r = data.get('risk', 0)
                    total_risk += r
                    if r >= 80: critical += 1
                    elif r >= 60: high += 1
                    elif r >= 40: medium += 1
                    else: low += 1
                
                avg_risk = total_risk / len(incidents)
                
                pdf.set_font("Arial", size=9)
                pdf.set_text_color(220, 0, 0); pdf.cell(0, 5, txt=f"Critical Decisions: {critical}", ln=True)
                pdf.set_text_color(255, 94, 14); pdf.cell(0, 5, txt=f"High Risk Decisions: {high}", ln=True)
                pdf.set_text_color(220, 180, 0); pdf.cell(0, 5, txt=f"Medium Risk Decisions: {medium}", ln=True)
                pdf.set_text_color(0, 150, 0); pdf.cell(0, 5, txt=f"Low Risk Decisions: {low}", ln=True)
                pdf.set_text_color(0, 0, 0); pdf.cell(0, 5, txt=f"Average Global Risk: {avg_risk:.2f}", ln=True)
                pdf.ln(5)
            
            # DECISION RECORDS
            pdf.set_font("Arial", style="B", size=11)
            pdf.cell(0, 7, txt="ML Training Data Records:", ln=True)
            pdf.ln(2)
            
            for i, incident in enumerate(incidents, 1):
                if pdf.get_y() > 240:
                    pdf.add_page()
                
                data = incident.to_dict() if hasattr(incident, 'to_dict') else (incident if isinstance(incident, dict) else vars(incident))
                risk = data.get('risk', 0)
                reason = data.get('reason', 'N/A')
                risk_level = "CRITICAL" if risk >= 80 else "HIGH" if risk >= 60 else "MEDIUM" if risk >= 40 else "LOW"
                
                pdf.set_font("Arial", style="B", size=10)
                if risk >= 80: pdf.set_text_color(220, 0, 0)
                elif risk >= 60: pdf.set_text_color(255, 94, 14)
                elif risk >= 40: pdf.set_text_color(220, 180, 0)
                else: pdf.set_text_color(0, 150, 0)
                
                pdf.cell(0, 6, txt=f"Record #{i} - {reason} [{risk_level}]", ln=True)
                pdf.ln(1)
                
                pdf.set_font("Arial", size=8.5)
                pdf.set_text_color(0, 0, 0)
                
                ml_fields = {
                    'id': 'Decision ID',
                    'timestamp': 'Timestamp',
                    'risk': 'Risk Score',
                    'confidence': 'Confidence Level',
                    'reason': 'Threat Class',
                    'recommended_action': 'Response Action',
                    'mitre': 'MITRE Technique'
                }
                
                for key, label in ml_fields.items():
                    if key in data:
                        val = data[key]
                        safe_val = str(val).encode('latin-1', 'replace').decode('latin-1')
                        # Note: No truncation here to preserve forensic integrity
                        pdf.set_font("Arial", style="B", size=8.5)
                        pdf.write(4, f"{label}: ")
                        pdf.set_font("Arial", size=8.5)
                        pdf.write(4, f"{safe_val}\n")
                
                pdf.ln(3)
            
            pdf.output(pdf_path)
            return pdf_path
        except Exception as e:
            print(f"ERROR: {e}")
            return None
