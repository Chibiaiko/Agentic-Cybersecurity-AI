# ticketing.py

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
import os
import json

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class TicketState(str, Enum):
    NEW         = "NEW"
    TRIAGED     = "TRIAGED"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED    = "RESOLVED"
    CLOSED      = "CLOSED"

class Team(str, Enum):
    SECURITY = "Security Team"
    NETWORK  = "Network Team"
    IT_OPS   = "IT Ops"

SLA_TARGETS = {
    "Critical": 4,  "High": 8,  "Medium": 24, "Low": 72,
    "P1": 4,        "P2": 8,    "P3": 24,     "P4": 72,
}

# ---------------------------------------------------------------------------
# Ticket
# ---------------------------------------------------------------------------

@dataclass
class Ticket:
    ticket_id:     str
    requester:     str
    user:          str
    device_name:   str
    issue:         str
    error_message: str
    severity:      str = "Medium"
    assigned_team: Optional[Team] = None
    state:         TicketState = TicketState.NEW
    created_at:    datetime = field(default_factory=datetime.utcnow)
    resolved_at:   Optional[datetime] = None
    closed_at:     Optional[datetime] = None

    # ── State machine ────────────────────────────────────────────────────

    def transition(self, new_state: TicketState):
        valid = {
            TicketState.NEW:         [TicketState.TRIAGED],
            TicketState.TRIAGED:     [TicketState.IN_PROGRESS],
            TicketState.IN_PROGRESS: [TicketState.RESOLVED],
            TicketState.RESOLVED:    [TicketState.CLOSED],
        }
        if new_state in valid.get(self.state, []):
            self.state = new_state
            if new_state == TicketState.RESOLVED:
                self.resolved_at = datetime.utcnow()
            if new_state == TicketState.CLOSED:
                self.closed_at = datetime.utcnow()
        else:
            raise ValueError(f"Invalid transition: {self.state} → {new_state}")

    # ── SLA ──────────────────────────────────────────────────────────────

    def duration_hours(self) -> float:
        if not self.resolved_at:
            return 0.0
        return round((self.resolved_at - self.created_at).total_seconds() / 3600, 4)

    def sla_target_hours(self) -> int:
        return SLA_TARGETS.get(self.severity, 24)

    def sla_met(self) -> bool:
        if not self.resolved_at:
            return False
        return self.duration_hours() <= self.sla_target_hours()

    # ── Documentation ────────────────────────────────────────────────────

    def generate_documentation(self, enrichment_summary: str,
                                company_name: str = "Company") -> str:
        """
        Write TXT, JSON, and PDF reports into Tickets/<ticket_id>_<identity>/
        Returns the folder path string.
        """
        identity    = self.user if self.user != "N/A" else self.device_name
        folder_name = f"Tickets/{self.ticket_id}_{identity}"
        os.makedirs(folder_name, exist_ok=True)

        sla_status  = "MET" if self.sla_met() else "BREACHED"
        sla_icon    = "✓" if self.sla_met() else "✗"
        team_str    = self.assigned_team.value if self.assigned_team else "N/A"

        # ── TXT ──────────────────────────────────────────────────────────
        txt_path = os.path.join(folder_name, f"{self.ticket_id}.txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(f"{'=' * 64}\n")
            f.write(f"  {company_name.upper()} — TICKET REPORT\n")
            f.write(f"{'=' * 64}\n\n")

            # Section 1 — Ticket Overview
            f.write("SECTION 1 — TICKET OVERVIEW\n")
            f.write(f"{'─' * 40}\n")
            f.write(f"  Ticket ID      : {self.ticket_id}\n")
            f.write(f"  Requester      : {self.requester}\n")
            f.write(f"  User           : {self.user}\n")
            f.write(f"  Device         : {self.device_name}\n")
            f.write(f"  Issue Label    : {self.issue}\n")
            f.write(f"  Issue Detail   : {self.error_message}\n")
            f.write(f"  Assigned Team  : {team_str}\n")
            f.write(f"  State          : {self.state.value}\n\n")

            # Section 2 — SLA Metrics
            f.write("SECTION 2 — SLA METRICS\n")
            f.write(f"{'─' * 40}\n")
            f.write(f"  Priority       : {self.severity}\n")
            f.write(f"  SLA Target     : {self.sla_target_hours()} hours\n")
            f.write(f"  Duration       : {self.duration_hours()} hours\n")
            f.write(f"  SLA Result     : {sla_icon} {sla_status}\n")
            f.write(f"  Created At     : {self.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write(f"  Resolved At    : {self.resolved_at.strftime('%Y-%m-%d %H:%M:%S UTC') if self.resolved_at else 'N/A'}\n")
            f.write(f"  Closed At      : {self.closed_at.strftime('%Y-%m-%d %H:%M:%S UTC') if self.closed_at else 'N/A'}\n\n")

            # Section 3 — Data Sources
            f.write("SECTION 3 — DATA SOURCES\n")
            f.write(f"{'─' * 40}\n")
            f.write("  Log Analytics  : SecurityEvent, Heartbeat, Perf\n")
            f.write("  Sentinel       : SecurityAlert, SecurityIncident, SigninLogs,\n")
            f.write("                   AADRiskyUsers, AADUserRiskEvents\n")
            f.write("  Defender       : DeviceAlertEvents, DeviceNetworkEvents,\n")
            f.write("                   DeviceProcessEvents, DeviceLogonEvents,\n")
            f.write("                   DeviceFileEvents, DeviceInfo\n\n")

            # Section 4 — Issue Classification Reference
            f.write("SECTION 4 — ISSUE CLASSIFICATION REFERENCE\n")
            f.write(f"{'─' * 40}\n")
            f.write("  SECURITY ISSUES\n")
            f.write(f"  {'─' * 36}\n")
            SECURITY_ISSUES = [
                ("Multiple Failed Login Attempts",          "Critical", "Security Team",
                 "4625 / brute force / repeated auth failures"),
                ("Successful Login from Unusual Location",  "High",     "Security Team",
                 "AADUserRiskEvents / impossible travel / risky signin"),
                ("Malware Detection Alert",                 "Critical", "Security Team",
                 "DeviceAlertEvents / Defender threat detection"),
                ("Suspicious Process Execution",            "High",     "Security Team",
                 "DeviceProcessEvents / 4688 / LOLBin / encoded command"),
                ("Privilege Escalation Activity",           "Critical", "Security Team",
                 "4672 / 4673 / 4674 / admin rights elevation"),
                ("Unauthorized RDP/SSH Attempt",            "High",     "Security Team",
                 "4648 / LogonType 10 / DeviceLogonEvents"),
                ("Data Exfiltration Suspicion",             "Critical", "Security Team",
                 "DeviceNetworkEvents / TotalBytesSent > 10MB"),
                ("Account Lockout Due to Suspicious Activity","Medium", "Security Team",
                 "4740 / account locked out"),
                ("Security/Monitoring Agent Offline",       "High",     "Security Team",
                 "Heartbeat / DeviceInfo / OnboardingStatus"),
                ("Unauthorized Configuration Change",       "High",     "Security Team",
                 "4719 / 4907 / audit policy changed"),
            ]
            for label, priority, team, source in SECURITY_ISSUES:
                f.write(f"  • {label}\n")
                f.write(f"    Priority : {priority}  |  Team : {team}\n")
                f.write(f"    Source   : {source}\n\n")

            f.write("  NETWORK ISSUES\n")
            f.write(f"  {'─' * 36}\n")
            NETWORK_ISSUES = [
                ("Network Outage – Multiple Hosts Unreachable", "Critical", "Network Team",
                 "Heartbeat / MinutesSinceLastHeartbeat"),
                ("Single VM Network Connectivity Failure",      "High",     "Network Team",
                 "Heartbeat / DeviceInfo / OnboardingStatus"),
                ("High Network Latency Detected",               "Medium",   "Network Team",
                 "Perf / Bytes Sent-Received/sec / % Processor Time"),
                ("DNS Resolution Failure",                      "High",     "Network Team",
                 "DeviceNetworkEvents / RemoteUrl / ActionType"),
                ("VPN Connectivity Failure",                    "High",     "Network Team",
                 "DeviceNetworkEvents / SigninLogs"),
                ("Firewall Rule Blocking Legitimate Traffic",   "High",     "Network Team",
                 "DeviceNetworkEvents / ActionType: ConnectionFailed"),
                ("Excessive Bandwidth Utilization",             "Medium",   "Network Team",
                 "Perf / DeviceNetworkEvents / TotalBytesSent"),
                ("Network Interface Disabled or Flapping",      "High",     "Network Team",
                 "Heartbeat / DeviceInfo / ExposureLevel"),
            ]
            for label, priority, team, source in NETWORK_ISSUES:
                f.write(f"  • {label}\n")
                f.write(f"    Priority : {priority}  |  Team : {team}\n")
                f.write(f"    Source   : {source}\n\n")

            # Section 5 — Enrichment & Telemetry
            f.write("SECTION 5 — ENRICHMENT & TELEMETRY\n")
            f.write(f"{'─' * 40}\n")
            f.write(enrichment_summary)
            f.write("\n")

        # ── JSON ─────────────────────────────────────────────────────────
        json_path = os.path.join(folder_name, f"{self.ticket_id}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump({
                "schema_version":  "2.0",
                "company":         company_name,
                "ticket_id":       self.ticket_id,
                "requester":       self.requester,
                "user":            self.user,
                "device_name":     self.device_name,
                "issue":           self.issue,
                "error_message":   self.error_message,
                "assigned_team":   team_str,
                "severity":        self.severity,
                "state":           self.state.value,
                "data_sources": {
                    "log_analytics": ["SecurityEvent", "Heartbeat", "Perf"],
                    "sentinel":      ["SecurityAlert", "SecurityIncident",
                                      "SigninLogs", "AADRiskyUsers", "AADUserRiskEvents"],
                    "defender":      ["DeviceAlertEvents", "DeviceNetworkEvents",
                                      "DeviceProcessEvents", "DeviceLogonEvents",
                                      "DeviceFileEvents", "DeviceInfo"],
                },
                "issue_catalogue": {
                    "security": [
                        {"label": "Multiple Failed Login Attempts",           "priority": "Critical", "team": "Security Team", "source": "SecurityEvent 4625 / brute force"},
                        {"label": "Successful Login from Unusual Location",   "priority": "High",     "team": "Security Team", "source": "AADUserRiskEvents / SigninLogs"},
                        {"label": "Malware Detection Alert",                  "priority": "Critical", "team": "Security Team", "source": "DeviceAlertEvents / Defender"},
                        {"label": "Suspicious Process Execution",             "priority": "High",     "team": "Security Team", "source": "DeviceProcessEvents / 4688"},
                        {"label": "Privilege Escalation Activity",            "priority": "Critical", "team": "Security Team", "source": "SecurityEvent 4672/4673/4674"},
                        {"label": "Unauthorized RDP/SSH Attempt",             "priority": "High",     "team": "Security Team", "source": "SecurityEvent 4648 / DeviceLogonEvents"},
                        {"label": "Data Exfiltration Suspicion",              "priority": "Critical", "team": "Security Team", "source": "DeviceNetworkEvents / TotalBytesSent"},
                        {"label": "Account Lockout Due to Suspicious Activity","priority": "Medium",  "team": "Security Team", "source": "SecurityEvent 4740"},
                        {"label": "Security/Monitoring Agent Offline",        "priority": "High",     "team": "Security Team", "source": "Heartbeat / DeviceInfo"},
                        {"label": "Unauthorized Configuration Change",        "priority": "High",     "team": "Security Team", "source": "SecurityEvent 4719/4907"},
                    ],
                    "network": [
                        {"label": "Network Outage – Multiple Hosts Unreachable", "priority": "Critical", "team": "Network Team", "source": "Heartbeat"},
                        {"label": "Single VM Network Connectivity Failure",      "priority": "High",     "team": "Network Team", "source": "Heartbeat / DeviceInfo"},
                        {"label": "High Network Latency Detected",               "priority": "Medium",   "team": "Network Team", "source": "Perf / Bytes/sec"},
                        {"label": "DNS Resolution Failure",                      "priority": "High",     "team": "Network Team", "source": "DeviceNetworkEvents / RemoteUrl"},
                        {"label": "VPN Connectivity Failure",                    "priority": "High",     "team": "Network Team", "source": "DeviceNetworkEvents / SigninLogs"},
                        {"label": "Firewall Rule Blocking Legitimate Traffic",   "priority": "High",     "team": "Network Team", "source": "DeviceNetworkEvents / ActionType"},
                        {"label": "Excessive Bandwidth Utilization",             "priority": "Medium",   "team": "Network Team", "source": "Perf / DeviceNetworkEvents"},
                        {"label": "Network Interface Disabled or Flapping",      "priority": "High",     "team": "Network Team", "source": "Heartbeat / DeviceInfo"},
                    ],
                },
                "sla": {
                    "target_hours":   self.sla_target_hours(),
                    "duration_hours": self.duration_hours(),
                    "met":            self.sla_met(),
                    "status":         sla_status,
                },
                "timestamps": {
                    "created_at":  str(self.created_at),
                    "resolved_at": str(self.resolved_at),
                    "closed_at":   str(self.closed_at),
                },
                "enrichment_summary": enrichment_summary,
            }, f, indent=4)

        # ── PDF ──────────────────────────────────────────────────────────
        pdf_path = os.path.join(folder_name, f"{self.ticket_id}.pdf")
        self._write_pdf(pdf_path, company_name, enrichment_summary,
                        sla_status, sla_icon, team_str)

        return f"Documentation saved: {folder_name}/"

    def _write_pdf(self, pdf_path: str, company_name: str, enrichment: str,
                   sla_status: str, sla_icon: str, team_str: str):
        """Generate PDF. Requires fpdf2: pip install fpdf2"""
        try:
            from fpdf import FPDF

            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()

            def section(title):
                pdf.set_font("Helvetica", "B", 11)
                pdf.set_fill_color(230, 230, 230)
                pdf.cell(0, 8, title, ln=True, fill=True)
                pdf.set_font("Helvetica", "", 10)
                pdf.ln(1)

            def row(label, value):
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(50, 7, f"{label}:", ln=False)
                pdf.set_font("Helvetica", "", 10)
                pdf.cell(0, 7, str(value)[:90], ln=True)

            # Header
            pdf.set_font("Helvetica", "B", 15)
            pdf.cell(0, 10, f"{company_name.upper()} — TICKET REPORT", ln=True, align="C")
            pdf.ln(3)

            # Section 1 — Ticket Overview
            section("SECTION 1 — TICKET OVERVIEW")
            row("Ticket ID",     self.ticket_id)
            row("Requester",     self.requester)
            row("User",          self.user)
            row("Device",        self.device_name)
            row("Issue Label",   self.issue)
            row("Issue Detail",  self.error_message[:80])
            row("Assigned Team", team_str)
            row("State",         self.state.value)
            pdf.ln(3)

            # Section 2 — SLA Metrics
            section("SECTION 2 — SLA METRICS")
            row("Priority",    self.severity)
            row("SLA Target",  f"{self.sla_target_hours()} hours")
            row("Duration",    f"{self.duration_hours()} hours")
            row("SLA Result",  f"{sla_icon} {sla_status}")
            row("Created At",  self.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"))
            row("Resolved At", self.resolved_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                               if self.resolved_at else "N/A")
            pdf.ln(3)

            # Section 3 — Data Sources
            section("SECTION 3 — DATA SOURCES")
            row("Log Analytics", "SecurityEvent, Heartbeat, Perf")
            row("Sentinel",      "SecurityAlert, SecurityIncident, SigninLogs,")
            pdf.cell(50, 7, "", ln=False)
            pdf.cell(0, 7, "AADRiskyUsers, AADUserRiskEvents", ln=True)
            row("Defender",      "DeviceAlertEvents, DeviceNetworkEvents,")
            pdf.cell(50, 7, "", ln=False)
            pdf.cell(0, 7, "DeviceProcessEvents, DeviceLogonEvents,", ln=True)
            pdf.cell(50, 7, "", ln=False)
            pdf.cell(0, 7, "DeviceFileEvents, DeviceInfo", ln=True)
            pdf.ln(3)

            # Section 4 — Issue Classification Reference
            section("SECTION 4 — ISSUE CLASSIFICATION REFERENCE")

            SECURITY_ISSUES = [
                ("Multiple Failed Login Attempts",           "Critical", "Security Team"),
                ("Successful Login from Unusual Location",   "High",     "Security Team"),
                ("Malware Detection Alert",                  "Critical", "Security Team"),
                ("Suspicious Process Execution",             "High",     "Security Team"),
                ("Privilege Escalation Activity",            "Critical", "Security Team"),
                ("Unauthorized RDP/SSH Attempt",             "High",     "Security Team"),
                ("Data Exfiltration Suspicion",              "Critical", "Security Team"),
                ("Account Lockout Due to Suspicious Activity","Medium",  "Security Team"),
                ("Security/Monitoring Agent Offline",        "High",     "Security Team"),
                ("Unauthorized Configuration Change",        "High",     "Security Team"),
            ]
            NETWORK_ISSUES = [
                ("Network Outage - Multiple Hosts Unreachable", "Critical", "Network Team"),
                ("Single VM Network Connectivity Failure",      "High",     "Network Team"),
                ("High Network Latency Detected",               "Medium",   "Network Team"),
                ("DNS Resolution Failure",                      "High",     "Network Team"),
                ("VPN Connectivity Failure",                    "High",     "Network Team"),
                ("Firewall Rule Blocking Legitimate Traffic",   "High",     "Network Team"),
                ("Excessive Bandwidth Utilization",             "Medium",   "Network Team"),
                ("Network Interface Disabled or Flapping",      "High",     "Network Team"),
            ]

            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 7, "Security Issues", ln=True)
            pdf.set_font("Helvetica", "", 9)
            for label, priority, team in SECURITY_ISSUES:
                pdf.cell(0, 6, f"  {label}  |  {priority}  |  {team}", ln=True)
            pdf.ln(2)

            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 7, "Network Issues", ln=True)
            pdf.set_font("Helvetica", "", 9)
            for label, priority, team in NETWORK_ISSUES:
                pdf.cell(0, 6, f"  {label}  |  {priority}  |  {team}", ln=True)
            pdf.ln(3)

            # Section 5 — Enrichment
            section("SECTION 5 — ENRICHMENT & TELEMETRY")
            pdf.set_font("Courier", "", 8)
            safe = enrichment.encode("latin-1", errors="replace").decode("latin-1")
            pdf.multi_cell(0, 5, safe[:4000])

            pdf.output(pdf_path)

        except ImportError:
            print("[WARNING] fpdf2 not installed — PDF skipped. Run: pip install fpdf2")
        except Exception as e:
            print(f"[WARNING] PDF generation failed: {e}")
