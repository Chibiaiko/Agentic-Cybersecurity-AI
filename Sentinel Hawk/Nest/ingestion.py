# 🐣 nest/ingestion.py
# ---------------------------------------------------------
# SentinelHawk — Log Ingestion Layer
# ---------------------------------------------------------

import random
from datetime import datetime

class LogIngestion:
    """
    Simulated Log Ingestion.
    In a real scenario, this would connect to Azure Sentinel, Splunk, or Syslog.
    """

    def fetch_logs(self):
        """
        Generates simulated logs for demonstration purposes.
        """
        # Return a random number of events (1-3)
        num_events = random.randint(1, 3)
        events = []
        
        for _ in range(num_events):
            events.append(self._generate_random_event())
            
        return events

    def _generate_random_event(self):
        event_types = [
            # Event 1: Failed Login (Suspicious)
            {
                "EventID": 4625,
                "ActivityDisplayName": "Logon Failed",
                "Severity": "High",
                "Account": f"user_{random.randint(100, 999)}",
                "Computer": "HQ-FIN-01",
                "IpAddress": f"192.168.1.{random.randint(10, 200)}",
                "TimeGenerated": datetime.utcnow().isoformat()
            },
            # Event 2: Normal operation
            {
                "EventID": 4624,
                "ActivityDisplayName": "Successful Logon",
                "Severity": "Low",
                "Account": "admin_svc",
                "Computer": "HQ-DC-01",
                "IpAddress": "10.0.0.5",
                "TimeGenerated": datetime.utcnow().isoformat()
            },
            # Event 3: PowerShell Suspicion
            {
                "EventID": 4104,
                "ActivityDisplayName": "PowerShell Script Block Logging",
                "Severity": "Medium",
                "Account": "dev_ops",
                "Computer": "DEV-WORKSTATION",
                "IpAddress": "10.0.0.101",
                "raw": "powershell.exe -EncodedCommand JABXAGUAYgBDAGwAaQBlAG4AdAAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZw...",
                "TimeGenerated": datetime.utcnow().isoformat()
            },
             # Event 4: External IP Suspicion
            {
                "EventID": 3,
                "ActivityDisplayName": "Network Connection",
                "Severity": "Medium",
                "Account": "unknown",
                "Computer": "DMZ-WEB-01",
                "IpAddress": "8.8.8.8", # Specifically called out in baseline_engine
                "RemoteIPCountry": "Unknown",
                "TimeGenerated": datetime.utcnow().isoformat()
            }
        ]
        
        return random.choice(event_types)
