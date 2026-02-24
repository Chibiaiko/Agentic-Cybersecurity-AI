# verify_reports.py
import sys
import os
from datetime import datetime

# Add the parent directory to sys.path to import from SentinelHawk
sys.path.append(os.path.join(os.getcwd(), 'SentinelHawk'))

try:
    from SentinelHawk.report_engine import ReportEngine
    from SentinelHawk.models import Colors
except ImportError as e:
    # Try alternate path if above fails
    try:
        from report_engine import ReportEngine
        from models import Colors
    except ImportError:
        print(f"Error importing: {e}")
        sys.exit(1)

class MockIncident:
    def __init__(self, id, risk, host, event_name, ip, reason, action, status):
        self.id = id
        self.risk = risk
        self.event = {
            'event_name': event_name,
            'host': host,
            'ip': ip
        }
        self.reason = reason
        self.recommended_action = action
        self.status = status
        self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        return {
            'id': self.id,
            'risk': self.risk,
            'event': self.event,
            'reason': self.reason,
            'recommended_action': self.recommended_action,
            'status': self.status,
            'timestamp': self.timestamp
        }

def run_verification():
    print("🚀 Starting Report Verification...")
    
    # Create sample incidents with long text and raw data
    incidents = [
        {
            "id": "6834dd50-b3ca-4278-927a-d4a44c918465",
            "timestamp": datetime.now().isoformat(),
            "event": {
                "event_name": "Logon Failed - Brute Force Attempt",
                "host": "HQ-FIN-01-SECURE-VLAN",
                "ip": "192.168.1.68",
                "user": "admin",
                "event_id": 4625,
                "raw": "Log Name: Security, Source: Microsoft-Windows-Security-Auditing, Event ID: 4625, Task Category: Logon, Level: Information, Keywords: Audit Failure, User: Name admin, Computer: HQ-FIN-01, Description: An account failed to log on. Subject: Security ID: S-1-5-18, Account Name: HQ-FIN-01$, Logon Type: 3"
            },
            "risk": 100,
            "confidence": "High",
            "severity": "CRITICAL",
            "mitre": ["T1110", "T1110.001"],
            "reason": "Excessive failed logins (25+) from internal IP range targeting administrative accounts."
        },
        {
            "id": "8e84c7dc-dc31-4ac8-a460-e96dca4bb638",
            "timestamp": datetime.now().isoformat(),
            "event": {
                "event_name": "PowerShell Script Block Logging",
                "host": "DEV-WORKSTATION-05",
                "ip": "10.0.0.101",
                "user": "developer_j",
                "raw": "powershell.exe -ExecutionPolicy Bypass -File C:\\temp\\update.ps1 -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA..."
            },
            "risk": 75,
            "confidence": "Medium",
            "severity": "HIGH",
            "reason": "Encoded PowerShell command detected in development environment."
        }
    ]
    
    reporter = ReportEngine()
    
    print("\n1. Generating TXT, JSON, and Full Report PDF...")
    reporter.generate(incidents)
    
    print("\n2. Generating SOC Dashboard PDF...")
    reporter.generate_dashboard_pdf(incidents)
    
    print("\n3. Generating Decision Memory TXT and PDF...")
    reporter.generate_decision_memory_txt(incidents)
    reporter.generate_decision_memory_pdf(incidents)
    
    print(f"\n✅ Verification complete. Reports saved to: {reporter.base_dir}")
    print("Files created:")
    for f in os.listdir(reporter.base_dir):
        print(f" - {f}")

if __name__ == "__main__":
    run_verification()
