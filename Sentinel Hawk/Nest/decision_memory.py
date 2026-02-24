# 🦅 nest/decision_memory.py
# ---------------------------------------------------------
# SentinelHawk — Decision Memory & Incident Tracking
# ---------------------------------------------------------

import json
import os
from datetime import datetime

try:
    from fpdf import FPDF
except ImportError:
    FPDF = None


class DecisionMemory:

    REPORT_FOLDER = "reports"  # Folder where reports are saved

    def __init__(self):
        # Ensure report folder exists
        if not os.path.exists(self.REPORT_FOLDER):
            os.makedirs(self.REPORT_FOLDER, exist_ok=True)
        # In-memory storage for records during session
        self.records = []

    def _load(self):
        """Load from in-memory storage (no file I/O except during export)"""
        return self.records

    def _save_to_report_folder(self, data, filename=None):
        """Save decision memory as a timestamped JSON file in the report folder"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"decision_memory_{timestamp}.json"
        
        filepath = os.path.join(self.REPORT_FOLDER, filename)
        
        with open(filepath, "w") as f:
            json.dump(data, f, indent=4)
        
        return filepath

    def store(self, record_dict):
        """Stores an incident record dictionary in memory"""
        self.records.append(record_dict)
        return record_dict

    def export_to_report_with_metadata(self, records=None, metadata=None):
        """Export decision memory with additional metadata"""
        data = records if records is not None else self._load()
        
        export_data = {
            "exported_at": datetime.now().isoformat(),
            "total_incidents": len(data),
            "metadata": metadata or {},
            "decisions": data
        }
        
        filepath = self._save_to_report_folder(export_data)
        return filepath

    def export_decision_memory_txt(self, records=None, metadata=None, report_date=None):
        """Export decision memory as detailed TXT file"""
        data = records if records is not None else self._load()
        
        if report_date is None:
            report_date = datetime.now().strftime("%m-%d-%Y")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{report_date}_decision_memory_{timestamp}.TXT"
        filepath = os.path.join(self.REPORT_FOLDER, filename)
        
        try:
            with open(filepath, "w") as f:
                f.write("=" * 120 + "\n")
                f.write("SENTINELHAWK DECISION MEMORY EXPORT\n")
                f.write("=" * 120 + "\n")
                f.write(f"Exported: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Report Date: {report_date}\n")
                f.write(f"Total Decisions: {len(data)}\n")
                
                if metadata:
                    f.write(f"Metadata: {json.dumps(metadata, indent=2)}\n")
                
                f.write("=" * 120 + "\n\n")
                
                f.write("PURPOSE: This file contains decision data for machine learning and future threat analysis.\n\n")
                
                if data:
                    f.write("INCIDENT DECISIONS\n")
                    f.write("-" * 120 + "\n\n")
                    
                    for i, record in enumerate(data, 1):
                        f.write(f"DECISION #{i}\n")
                        f.write("-" * 120 + "\n")
                        
                        if isinstance(record, dict):
                            record_data = record
                        else:
                            record_data = record.to_dict() if hasattr(record, 'to_dict') else vars(record)
                        
                        for key, value in record_data.items():
                            formatted_key = key.replace('_', ' ').title()
                            f.write(f"  {formatted_key:<50}: {value}\n")
                        
                        f.write("\n")
                else:
                    f.write("No incidents recorded for this period.\n")
                
                f.write("=" * 120 + "\n")
                f.write("End of Decision Memory Export\n")
                f.write("=" * 120 + "\n")
            
            return filepath
        except Exception as e:
            print(f"Error exporting decision memory TXT: {e}")
            return None

    def export_decision_memory_pdf(self, records=None, metadata=None, report_date=None):
        """Export decision memory as detailed PDF file with proper page breaks"""
        if not FPDF:
            print("Error: PDF generation requires fpdf2. Install with: pip install fpdf2")
            return None
        
        data = records if records is not None else self._load()
        
        if report_date is None:
            report_date = datetime.now().strftime("%m-%d-%Y")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{report_date}_decision_memory_{timestamp}.PDF"
        filepath = os.path.join(self.REPORT_FOLDER, filename)
        
        try:
            pdf = FPDF()
            pdf.add_page()
            
            # Title
            pdf.set_font("Arial", style="B", size=14)
            pdf.cell(0, 10, txt="DECISION MEMORY EXPORT", ln=True, align="C")
            
            pdf.set_font("Arial", size=9)
            pdf.cell(0, 8, txt=f"Exported: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
            pdf.cell(0, 8, txt=f"Report Date: {report_date}", ln=True, align="C")
            pdf.ln(4)
            
            pdf.set_font("Arial", style="B", size=11)
            pdf.cell(0, 8, txt=f"Total Decisions: {len(data)}", ln=True)
            
            pdf.set_font("Arial", size=9)
            pdf.multi_cell(180, 5, txt="This export contains decision data for machine learning and future threat analysis optimization.")
            pdf.ln(3)
            
            if metadata:
                pdf.set_font("Arial", style="B", size=10)
                pdf.cell(0, 8, txt="METADATA", ln=True)
                pdf.set_font("Arial", size=8)
                for key, value in metadata.items():
                    formatted_key = key.replace('_', ' ').title()
                    safe_value = str(value).encode('latin-1', 'replace').decode('latin-1')
                    pdf.cell(0, 5, txt=f"{formatted_key}: {safe_value}", ln=True)
                pdf.ln(2)
            
            if data:
                pdf.set_font("Arial", style="B", size=10)
                pdf.cell(0, 8, txt="DECISIONS", ln=True)
                pdf.set_font("Arial", size=7)
                
                for i, record in enumerate(data, 1):
                    if pdf.will_page_break(20):
                        pdf.add_page()
                    
                    pdf.set_font("Arial", style="B", size=9)
                    pdf.cell(0, 6, txt=f"Decision #{i}", ln=True)
                    pdf.set_font("Arial", size=7)
                    
                    if isinstance(record, dict):
                        record_data = record
                    else:
                        record_data = record.to_dict() if hasattr(record, 'to_dict') else vars(record)
                    
                    for key, value in record_data.items():
                        formatted_key = key.replace('_', ' ').title()
                        safe_value = str(value).encode('latin-1', 'replace').decode('latin-1')
                        
                        if len(safe_value) > 80:
                            safe_value = safe_value[:80] + "..."
                        
                        pdf.multi_cell(180, 3, txt=f"{formatted_key}: {safe_value}")
                    
                    pdf.ln(2)
            else:
                pdf.set_font("Arial", size=9)
                pdf.cell(0, 8, txt="No decisions recorded for this period.", ln=True)
            
            pdf.output(filepath)
            return filepath
        except Exception as e:
            print(f"Error generating decision memory PDF: {e}")
            import traceback
            traceback.print_exc()
            return None
