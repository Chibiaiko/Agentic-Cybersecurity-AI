# ============================================================================
# AEGIS – Agentic Incident Response & Triage AI
# Scenario-Agnostic / Sentinel-Aligned
# ============================================================================

import os
import sys
import datetime
from typing import Dict, Any, List

from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient

from reportlab.lib.pagesizes import LETTER
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch

from secrets_ import LOG_ANALYTICS_WORKSPACE_ID
from log_analytics_queries import query_log_analytics

# ----------------------------------------------------------------------------
# SCENARIO REGISTRY (ADD / MODIFY SCENARIOS HERE)
# ----------------------------------------------------------------------------

SCENARIOS = {
    "brute_force": {
        "title": "Brute Force Authentication Attempt",
        "mitre": ["T1110"],
        "table": "DeviceLogonEvents",
        "primary_filter": "ActionType == 'LogonFailed'",
        "validation_filter": "ActionType == 'LogonSuccess'",
        "lookback_hours": 5
    },
    "powershell_download": {
        "title": "Suspicious PowerShell Web Request",
        "mitre": ["T1059.001", "T1105"],
        "table": "DeviceProcessEvents",
        "primary_filter": "FileName == 'powershell.exe' and ProcessCommandLine contains 'Invoke-WebRequest'",
        "validation_filter": "ProcessCommandLine contains '-File'",
        "lookback_hours": 24
    },
    "impossible_travel": {
        "title": "Potential Impossible Travel",
        "mitre": ["T1078"],
        "table": "SigninLogs",
        "primary_filter": "LocationDetails != ''",
        "validation_filter": "",
        "lookback_hours": 168
    }
}

# ----------------------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------------------

ARTIFACT_DIR = "Investigated_Playbooks"
os.makedirs(ARTIFACT_DIR, exist_ok=True)

# ----------------------------------------------------------------------------
# AEGIS AGENT
# ----------------------------------------------------------------------------

class AegisAgent:
    """Scenario-agnostic IR & Triage Agent"""

    def __init__(self, hostname: str, scenario_key: str):
        self.hostname = hostname
        self.scenario_key = scenario_key
        self.scenario = SCENARIOS[scenario_key]

        self.start_time = datetime.datetime.utcnow()
        self.timeline: List[Dict[str, str]] = []

        self.primary_events: List[Any] = []
        self.validation_events: List[Any] = []

        self.triage_result = "Undetermined"
        self.incident_classification = "Undetermined"
        self.isolation_recommended = False

        self.credential = DefaultAzureCredential()
        self.logs_client = LogsQueryClient(self.credential)

    # ---------------------------------------------------------------------
    # LOGGING
    # ---------------------------------------------------------------------

    def log(self, stage: str, message: str):
        ts = datetime.datetime.utcnow().isoformat()
        self.timeline.append({
            "time": ts,
            "stage": stage,
            "message": message
        })
        print(f"[{stage}] {message}")

    # ---------------------------------------------------------------------
    # RUN
    # ---------------------------------------------------------------------

    def run(self):
        self.log("INIT", f"Starting investigation: {self.scenario['title']}")
        self.collect_events()
        self.perform_triage()

        # ALWAYS generate artifacts
        self.generate_playbook()
        self.generate_timeline()

        self.log("COMPLETE", "Investigation completed")

    # ---------------------------------------------------------------------
    # TELEMETRY COLLECTION
    # ---------------------------------------------------------------------

    def collect_events(self):
        self.log("COLLECT", "Collecting primary detection telemetry")

        self.primary_events = query_log_analytics(
            client=self.logs_client,
            workspace_id=LOG_ANALYTICS_WORKSPACE_ID,
            table=self.scenario["table"],
            hostname=self.hostname,
            filter_clause=self.scenario["primary_filter"],
            lookback_hours=self.scenario["lookback_hours"]
        )

        self.log("COLLECT", f"Primary events found: {len(self.primary_events)}")

        if self.scenario["validation_filter"]:
            self.log("COLLECT", "Collecting validation telemetry")
            self.validation_events = query_log_analytics(
                client=self.logs_client,
                workspace_id=LOG_ANALYTICS_WORKSPACE_ID,
                table=self.scenario["table"],
                hostname=self.hostname,
                filter_clause=self.scenario["validation_filter"],
                lookback_hours=self.scenario["lookback_hours"]
            )
            self.log("COLLECT", f"Validation events found: {len(self.validation_events)}")

    # ---------------------------------------------------------------------
    # TRIAGE (NIST 800-61 ALIGNED)
    # ---------------------------------------------------------------------

    def perform_triage(self):
        self.log("TRIAGE", "Assessing evidence and impact")

        if not self.primary_events:
            self.triage_result = "No malicious activity observed"
            self.incident_classification = "True Negative"
            return

        if self.primary_events and not self.validation_events:
            self.triage_result = "Attempted malicious activity detected with no impact"
            self.incident_classification = "True Positive"
            self.isolation_recommended = False
            return

        if self.primary_events and self.validation_events:
            self.triage_result = "Indicators of compromise observed"
            self.incident_classification = "True Positive"
            self.isolation_recommended = True

    # ---------------------------------------------------------------------
    # PLAYBOOK (ALWAYS GENERATED)
    # ---------------------------------------------------------------------

    def generate_playbook(self):
        path = os.path.join(
            ARTIFACT_DIR,
            f"{self.hostname}_{self.scenario_key}_Investigated_Playbook.txt"
        )

        with open(path, "w", encoding="utf-8") as f:
            f.write("AEGIS INCIDENT RESPONSE PLAYBOOK\n")
            f.write("=" * 80 + "\n\n")

            f.write(f"Scenario: {self.scenario['title']}\n")
            f.write(f"Hostname: {self.hostname}\n")
            f.write(f"MITRE ATT&CK Techniques: {', '.join(self.scenario['mitre'])}\n")
            f.write(f"Triage Outcome: {self.triage_result}\n")
            f.write(f"Incident Classification: {self.incident_classification}\n\n")

            f.write("Isolation Protocol (Human-Governed)\n")
            f.write("-" * 60 + "\n")
            if self.isolation_recommended:
                f.write(
                    "Based on observed indicators, endpoint isolation is recommended. "
                    "Isolation actions must be executed by a human analyst in accordance "
                    "with organizational policy.\n\n"
                )
            else:
                f.write(
                    "Isolation was evaluated and deemed unnecessary at this time. "
                    "No post-authentication or post-exploitation activity was observed.\n\n"
                )

            f.write("Event Summary\n")
            f.write("-" * 60 + "\n")
            f.write(f"Primary Detection Events: {len(self.primary_events)}\n")
            f.write(f"Validation Events: {len(self.validation_events)}\n\n")

            f.write("Investigation Timeline\n")
            f.write("-" * 60 + "\n")
            for e in self.timeline:
                f.write(f"{e['time']} | {e['stage']} | {e['message']}\n")

        self.log("ARTIFACT", f"Playbook created: {path}")

    # ---------------------------------------------------------------------
    # TIMELINE PDF (ALWAYS GENERATED)
    # ---------------------------------------------------------------------

    def generate_timeline(self):
        path = os.path.join(
            ARTIFACT_DIR,
            f"{self.hostname}_{self.scenario_key}_Incident_Timeline.pdf"
        )

        c = canvas.Canvas(path, pagesize=LETTER)
        width, height = LETTER
        y = height - inch

        c.setFont("Helvetica-Bold", 16)
        c.drawString(inch, y, "Incident Response Timeline")
        y -= inch

        c.setFont("Helvetica", 10)
        for entry in self.timeline:
            if y <= inch:
                c.showPage()
                y = height - inch
            c.drawString(
                inch,
                y,
                f"{entry['time']} | {entry['stage']} | {entry['message']}"
            )
            y -= 14

        c.save()
        self.log("ARTIFACT", f"Timeline PDF created: {path}")

# ----------------------------------------------------------------------------
# ENTRY POINT
# ----------------------------------------------------------------------------

def main():
    print("\n=== AEGIS Agentic IR & Triage AI ===\n")

    hostname = input("Enter hostname to investigate: ").strip()
    scenario_key = sys.argv[1] if len(sys.argv) > 1 else "brute_force"

    if scenario_key not in SCENARIOS:
        print(f"Unknown scenario: {scenario_key}")
        print(f"Available scenarios: {', '.join(SCENARIOS.keys())}")
        sys.exit(1)

    agent = AegisAgent(hostname, scenario_key)
    agent.run()

if __name__ == "__main__":
    main()
