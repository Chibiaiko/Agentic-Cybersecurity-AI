# ops_pilot.py
# OpsPilot — Automated Ticket 
# Integrates with Azure Log Analytics, Microsoft Sentinel, and Defender for Endpoint
# Supports: Network Team | Security Team | IT Ops routing

import re
import os
from datetime import datetime
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient

from log_analytics_queries import (
    # Identity base queries
    build_device_logon_query,
    build_user_logon_query,
    build_ip_correlation_query,
    # Log Analytics — native
    build_heartbeat_query,
    build_performance_query,
    build_brute_force_query,
    build_account_lockout_query,
    build_privilege_escalation_query,
    build_rdp_ssh_query,
    build_config_change_query,
    # Sentinel
    build_sentinel_alerts_query,
    build_sentinel_incidents_query,
    build_signin_logs_query,
    build_risky_user_query,
    build_unusual_location_query,
    # Defender
    build_defender_alerts_query,
    build_device_network_events_query,
    build_device_process_events_query,
    build_device_logon_events_query,
    build_data_exfil_query,
    build_device_info_query,
    # Execution + helpers
    run_log_analytics_query,
    extract_ip_from_csv,
    extract_user_from_csv,
    extract_severity_from_csv,
)
from ticketing import Ticket, Team, TicketState
from secrets_ import (
    LOG_ANALYTICS_WORKSPACE_ID,
    COMPANY_NAME,
    COMPANY_CODE,
    LOOKBACK_WINDOW,
)

# ---------------------------------------------------------------------------
# Terminal colors
# ---------------------------------------------------------------------------
URGENCY_COLORS = {
    "Critical": "\033[91m",
    "High":     "\033[38;2;252;106;3m",
    "Medium":   "\033[93m",
    "Low":      "\033[32m",
}
RESET = "\033[0m"

# ---------------------------------------------------------------------------
# Issue Catalogue
# Keywords are matched against combined telemetry + issue description
# ---------------------------------------------------------------------------
ISSUE_CATALOGUE = [
    # ── SECURITY ────────────────────────────────────────────────────────────
    {
        "keywords": ["brute", "4625", "multiple failed", "failed login",
                     "failed authentication", "repeated failed"],
        "label":    "Multiple Failed Login Attempts",
        "priority": "Critical",
        "team":     Team.SECURITY,
        "note":     "Repeated failed authentication attempts detected for {identity}. "
                    "Possible brute-force activity. Log review and source IP validation required.",
    },
    {
        "keywords": ["unusual location", "anomalous login", "unfamiliar ip",
                     "impossible travel", "risky signin", "risk state",
                     "riskstate", "risklevel", "atypicaltravel"],
        "label":    "Successful Login from Unusual Location",
        "priority": "High",
        "team":     Team.SECURITY,
        "note":     "Anomalous login detected for {identity} from unfamiliar IP/geolocation. "
                    "Risk of compromised credentials.",
    },
    {
        "keywords": ["malware", "virus", "ransomware", "trojan", "defender alert",
                     "endpoint protection", "threat detected", "alertseverity",
                     "severity: high", "severity: critical"],
        "label":    "Malware Detection Alert",
        "priority": "Critical",
        "team":     Team.SECURITY,
        "note":     "Endpoint protection triggered malware alert on {identity}. "
                    "Host isolation and forensic review recommended.",
    },
    {
        "keywords": ["suspicious process", "4688", "unauthorized process",
                     "unusual process", "process execution", "lolbin",
                     "powershell encoded", "processcommandline", "initiatingprocess"],
        "label":    "Suspicious Process Execution",
        "priority": "High",
        "team":     Team.SECURITY,
        "note":     "Unusual or unauthorized process execution observed on {identity}. "
                    "Behavioral analysis and threat validation required.",
    },
    {
        "keywords": ["privilege escalation", "4672", "4673", "elevation",
                     "admin rights", "sudo", "runas", "privilegelist"],
        "label":    "Privilege Escalation Activity",
        "priority": "Critical",
        "team":     Team.SECURITY,
        "note":     "Elevation of privileges detected for {identity}. "
                    "Verify authorization and investigate potential account compromise.",
    },
    {
        "keywords": ["rdp attempt", "ssh attempt", "3389", "4648",
                     "unauthorized rdp", "unauthorized ssh", "remote desktop",
                     "remoteinteractive", "logontype: 10"],
        "label":    "Unauthorized RDP/SSH Attempt",
        "priority": "High",
        "team":     Team.SECURITY,
        "note":     "Repeated RDP/SSH connection attempts detected on {identity}. "
                    "Source validation and access control review required.",
    },
    {
        "keywords": ["data exfil", "unusual outbound", "large upload",
                     "high outbound bytes", "exfiltration", "totalbytessent",
                     "sentbytes"],
        "label":    "Data Exfiltration Suspicion",
        "priority": "Critical",
        "team":     Team.SECURITY,
        "note":     "Unusual outbound traffic volume from {identity} detected. "
                    "Possible data exfiltration attempt. Immediate review required.",
    },
    {
        "keywords": ["account locked", "lockout", "4740", "locked out"],
        "label":    "Account Lockout Due to Suspicious Activity",
        "priority": "Medium",
        "team":     Team.SECURITY,
        "note":     "{identity} account locked following multiple failed authentication attempts. "
                    "Requires verification of legitimacy.",
    },
    {
        "keywords": ["security agent offline", "monitoring offline", "agent disabled",
                     "mma offline", "ama offline", "heartbeat missing",
                     "minutessincelastheartbeat", "onboardingstatus"],
        "label":    "Security/Monitoring Agent Offline",
        "priority": "High",
        "team":     Team.SECURITY,
        "note":     "Security monitoring agent on {identity} is offline or disabled. "
                    "Potential tampering or configuration issue.",
    },
    {
        "keywords": ["unauthorized config", "policy change", "4719", "4907",
                     "unauthorized change", "configuration change", "auditpolicy"],
        "label":    "Unauthorized Configuration Change",
        "priority": "High",
        "team":     Team.SECURITY,
        "note":     "Unauthorized system or policy change detected on {identity}. "
                    "Change audit and validation required.",
    },
    # ── NETWORK ─────────────────────────────────────────────────────────────
    {
        "keywords": ["network outage", "multiple hosts unreachable",
                     "mass unreachable", "core network failure", "routing failure"],
        "label":    "Network Outage – Multiple Hosts Unreachable",
        "priority": "Critical",
        "team":     Team.NETWORK,
        "note":     "Multiple hosts including {identity} are unreachable from monitoring systems. "
                    "Possible routing, firewall, or core network failure. Immediate investigation required.",
    },
    {
        "keywords": ["vm unreachable", "single vm", "not responding",
                     "connectivity failure", "nic issue", "nsg", "host unreachable"],
        "label":    "Single VM Network Connectivity Failure",
        "priority": "High",
        "team":     Team.NETWORK,
        "note":     "{identity} is not responding to internal or external connectivity checks. "
                    "Potential NIC, NSG, subnet, or routing misconfiguration.",
    },
    {
        "keywords": ["high latency", "latency", "packet loss", "slow network",
                     "slow internet", "bandwidth saturation", "congestion",
                     "avgvalue", "% processor time"],
        "label":    "High Network Latency Detected",
        "priority": "Medium",
        "team":     Team.NETWORK,
        "note":     "Elevated latency observed on {identity}. "
                    "Possible bandwidth saturation, packet loss, or upstream congestion.",
    },
    {
        "keywords": ["dns failure", "dns resolution", "nxdomain", "dns error",
                     "cannot resolve", "name resolution"],
        "label":    "DNS Resolution Failure",
        "priority": "High",
        "team":     Team.NETWORK,
        "note":     "{identity} unable to resolve internal/external DNS queries. "
                    "Potential DNS server or forwarder issue.",
    },
    {
        "keywords": ["vpn failure", "vpn connectivity", "vpn session",
                     "vpn disconnected", "unable to connect vpn"],
        "label":    "VPN Connectivity Failure",
        "priority": "High",
        "team":     Team.NETWORK,
        "note":     "User {identity} unable to establish VPN session. "
                    "Authentication and client-side checks completed; network gateway investigation required.",
    },
    {
        "keywords": ["firewall blocking", "nsg blocking", "traffic blocked",
                     "blocked by firewall", "firewall rule", "access control list"],
        "label":    "Firewall Rule Blocking Legitimate Traffic",
        "priority": "High",
        "team":     Team.NETWORK,
        "note":     "Traffic from/to {identity} appears blocked by firewall or NSG policy. "
                    "Rule validation and traffic flow review required.",
    },
    {
        "keywords": ["bandwidth spike", "excessive bandwidth", "abnormal traffic",
                     "bandwidth utilization", "high throughput", "bytes sent/sec",
                     "bytes received/sec"],
        "label":    "Excessive Bandwidth Utilization",
        "priority": "Medium",
        "team":     Team.NETWORK,
        "note":     "Abnormal bandwidth spike detected on {identity}. "
                    "Requires traffic pattern review and throughput analysis.",
    },
    {
        "keywords": ["nic disabled", "nic flapping", "interface down",
                     "network interface", "intermittent connectivity", "link flapping"],
        "label":    "Network Interface Disabled or Flapping",
        "priority": "High",
        "team":     Team.NETWORK,
        "note":     "NIC associated with {identity} showing intermittent connectivity or disabled state. "
                    "Infrastructure validation required.",
    },
]

PRIORITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


# ---------------------------------------------------------------------------
# Issue Classification
# ---------------------------------------------------------------------------

def classify_issue(telemetry_combined: str, issue_description: str) -> dict:
    """
    Match combined telemetry and issue description against ISSUE_CATALOGUE.
    Returns the best matching entry, or a General fallback.
    """
    text = (telemetry_combined + " " + issue_description).lower()

    matches = []
    for entry in ISSUE_CATALOGUE:
        hits = sum(1 for kw in entry["keywords"] if kw in text)
        if hits > 0:
            matches.append((hits, entry))

    if matches:
        matches.sort(key=lambda x: (-x[0], PRIORITY_ORDER.get(x[1]["priority"], 9)))
        return matches[0][1]

    return {
        "label":    "General Operational Anomaly",
        "priority": "Low",
        "team":     Team.IT_OPS,
        "note":     "No specific pattern matched for {identity}. "
                    "General investigation by IT Ops required.",
    }


# ---------------------------------------------------------------------------
# Identity Detection
# ---------------------------------------------------------------------------

DEVICE_PREFIXES = ("win-", "desktop-", "laptop-", "srv-", "vm-",
                   "server-", "dc-", "wks-", "pc-")

def detect_identity_type(identity: str) -> str:
    """Returns 'Device', 'User', or 'Unknown'."""
    lower = identity.lower()
    if any(lower.startswith(p) for p in DEVICE_PREFIXES):
        return "Device"
    if re.search(r"-\d", lower):
        return "Device"
    if "@" in identity or re.match(r"^[a-z]+\.[a-z]+$", lower):
        return "User"
    return "Unknown"


# ---------------------------------------------------------------------------
# Telemetry Collection
# Queries all three sources: Log Analytics, Sentinel, Defender
# ---------------------------------------------------------------------------

def collect_telemetry(client, workspace_id: str, identity: str,
                      lookback_hours: int) -> tuple:
    """
    Collect telemetry from Log Analytics, Sentinel, and Defender.

    Device path:
        SecurityEvent + DeviceInfo + Defender alerts + process/network/file events
        + brute force check + heartbeat → extract IP → SigninLogs correlation
        + Sentinel alerts/incidents + data exfil check

    User path:
        SecurityEvent + SigninLogs + brute force check + account lockout
        + privilege escalation + risky user + Sentinel alerts/incidents

    Returns
    -------
    tuple: (telemetry_combined, detected_type, correlated_ip, correlated_user,
            sentinel_severity, sources_hit)
        telemetry_combined : str   All collected data merged into one string
        detected_type      : str   'Device' | 'User' | 'Unknown'
        correlated_ip      : str   IP extracted from device events (or None)
        correlated_user    : str   User resolved via IP correlation (or None)
        sentinel_severity  : str   Highest Sentinel/Defender severity found (or None)
        sources_hit        : list  Names of sources that returned data
    """
    print(f"\n[INFO] Querying identity: {identity}")
    identity_type   = detect_identity_type(identity)
    parts           = []
    correlated_ip   = None
    correlated_user = None
    sentinel_sev    = None
    sources_hit     = []

    def _run(label: str, query: str) -> str:
        result = run_log_analytics_query(client, workspace_id, query, lookback_hours)
        if result and not result.startswith("[ERROR]"):
            count = len(result.splitlines()) - 1
            print(f"  [+] {label}: {count} records")
            sources_hit.append(label)
            return result
        return ""

    # =========================================================
    # DEVICE PATH
    # =========================================================
    if identity_type in ("Device", "Unknown"):

        # Log Analytics — SecurityEvent
        r = _run("SecurityEvent (device)", build_device_logon_query(
            "SecurityEvent", identity,
            ["TimeGenerated", "EventID", "Computer", "Account",
             "IpAddress", "LogonType", "SubStatus"]))
        if r:
            parts.append(r)
            correlated_ip = extract_ip_from_csv(r)

        # Log Analytics — Heartbeat
        r = _run("Heartbeat", build_heartbeat_query(identity))
        if r:
            parts.append(r)

        # Log Analytics — Performance
        r = _run("Performance", build_performance_query(identity))
        if r:
            parts.append(r)

        # Log Analytics — Brute force check
        r = _run("Brute Force (device)", build_brute_force_query(identity, "device"))
        if r:
            parts.append(r)

        # Log Analytics — RDP/SSH attempts
        r = _run("RDP/SSH Attempts", build_rdp_ssh_query(identity))
        if r:
            parts.append(r)

        # Log Analytics — Config changes
        r = _run("Config Changes", build_config_change_query(identity))
        if r:
            parts.append(r)

        # Defender — Device info
        r = _run("Defender DeviceInfo", build_device_info_query(identity))
        if r:
            parts.append(r)

        # Defender — Alerts
        r = _run("Defender Alerts", build_defender_alerts_query(identity))
        if r:
            parts.append(r)
            sev = extract_severity_from_csv(r)
            if sev:
                sentinel_sev = sev

        # Defender — Network events
        r = _run("Defender NetworkEvents", build_device_network_events_query(
            identity,
            ["TimeGenerated", "DeviceName", "ActionType", "RemoteIP",
             "RemoteUrl", "LocalIP", "SentBytes", "ReceivedBytes"]))
        if r:
            parts.append(r)
            if not correlated_ip:
                correlated_ip = extract_ip_from_csv(r)

        # Defender — Process events
        r = _run("Defender ProcessEvents", build_device_process_events_query(identity))
        if r:
            parts.append(r)

        # Defender — Logon events
        r = _run("Defender LogonEvents", build_device_logon_events_query(identity))
        if r:
            parts.append(r)

        # Defender — Data exfiltration check
        r = _run("Defender DataExfil", build_data_exfil_query(identity))
        if r:
            parts.append(r)

        # Sentinel — Alerts
        r = _run("Sentinel Alerts", build_sentinel_alerts_query(identity))
        if r:
            parts.append(r)
            sev = extract_severity_from_csv(r)
            if sev and (sentinel_sev is None or
                        PRIORITY_ORDER.get(sev, 9) < PRIORITY_ORDER.get(sentinel_sev, 9)):
                sentinel_sev = sev

        # Sentinel — Incidents
        r = _run("Sentinel Incidents", build_sentinel_incidents_query(identity))
        if r:
            parts.append(r)

        # IP Correlation — SigninLogs
        if correlated_ip:
            print(f"  [+] Correlating IP {correlated_ip} → SigninLogs")
            r = _run("SigninLogs (IP correlation)", build_ip_correlation_query(
                "SigninLogs", correlated_ip,
                ["TimeGenerated", "UserPrincipalName", "IPAddress",
                 "ResultType", "ResultDescription", "Location"]))
            if r:
                parts.append(r)
                correlated_user = extract_user_from_csv(r)
                if correlated_user:
                    print(f"  [+] Correlated user: {correlated_user}")

        if parts:
            return "\n".join(parts), "Device", correlated_ip, correlated_user, sentinel_sev, sources_hit

        # No device match — fall through to user path
        identity_type = "User"
        print(f"  [~] No device records — retrying as User")

    # =========================================================
    # USER PATH
    # =========================================================

    # Log Analytics — SecurityEvent by Account
    r = _run("SecurityEvent (user)", build_user_logon_query(
        "SecurityEvent", identity,
        ["TimeGenerated", "EventID", "Computer", "Account",
         "IpAddress", "LogonType", "SubStatus"]))
    if r:
        parts.append(r)

    # Log Analytics — Brute force check
    r = _run("Brute Force (user)", build_brute_force_query(identity, "user"))
    if r:
        parts.append(r)

    # Log Analytics — Account lockout
    r = _run("Account Lockout", build_account_lockout_query(identity))
    if r:
        parts.append(r)

    # Log Analytics — Privilege escalation
    r = _run("Privilege Escalation", build_privilege_escalation_query(identity))
    if r:
        parts.append(r)

    # Sentinel — SigninLogs
    r = _run("SigninLogs", build_signin_logs_query(
        identity,
        ["TimeGenerated", "UserPrincipalName", "ResultType",
         "ResultDescription", "IPAddress", "Location", "AppDisplayName",
         "AuthenticationRequirement"]))
    if r:
        parts.append(r)

    # Sentinel — Risky user
    r = _run("Risky User", build_risky_user_query(identity))
    if r:
        parts.append(r)

    # Sentinel — Unusual location
    r = _run("Unusual Location", build_unusual_location_query(identity))
    if r:
        parts.append(r)

    # Sentinel — Alerts
    r = _run("Sentinel Alerts", build_sentinel_alerts_query(identity))
    if r:
        parts.append(r)
        sev = extract_severity_from_csv(r)
        if sev:
            sentinel_sev = sev

    # Sentinel — Incidents
    r = _run("Sentinel Incidents", build_sentinel_incidents_query(identity))
    if r:
        parts.append(r)

    telemetry = "\n".join(parts)

    if not telemetry:
        print("  [~] No records found for this identity.")

    return telemetry, identity_type, correlated_ip, correlated_user, sentinel_sev, sources_hit


# ---------------------------------------------------------------------------
# Ticket ID Generator
# ---------------------------------------------------------------------------

def generate_ticket_id(team: Team) -> str:
    """Format: <COMPANY_CODE>-<TEAM_CODE>-<TIMESTAMP>  e.g. LNP-SEC-20260213141530"""
    codes = {Team.SECURITY: "SEC", Team.NETWORK: "NET", Team.IT_OPS: "ITO"}
    ts    = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    return f"{COMPANY_CODE}-{codes.get(team, 'GEN')}-{ts}"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    import sys
    print(f"\n  OPS PILOT — {COMPANY_NAME}\n")

    # ── Identity: accept from command-line arg, else prompt ──────────────
    # Usage:  python ops_pilot.py <identity>
    #         python ops_pilot.py win-11-2026
    #         python ops_pilot.py john.doe
    if len(sys.argv) > 1:
        identity   = sys.argv[1].strip()
        issue_desc = sys.argv[2].strip() if len(sys.argv) > 2 else "Automated investigation"
        requester  = "OpsPilot Automated"
        print(f"  Identity    : {identity}")
        print(f"  Issue       : {issue_desc}")
        print(f"  Requester   : {requester}\n")
    else:
        requester  = input("Requester Name                  : ").strip()
        identity   = input("Affected User / Device / System : ").strip()
        issue_desc = input("Issue Description               : ").strip() or "Automated investigation"

    if not identity:
        print("[ERROR] Identity is required.")
        print("Usage: python ops_pilot.py <username_or_device>")
        return

    # Azure authentication
    print("\n[INFO] Authenticating with Azure...")
    try:
        credential  = DefaultAzureCredential()
        logs_client = LogsQueryClient(credential)
        print("[INFO] Authentication successful\n")
    except Exception as e:
        print(f"[ERROR] Azure authentication failed: {e}")
        return

    # Parse lookback hours from secrets
    try:
        lookback_hours = int(re.sub(r"\D", "", LOOKBACK_WINDOW))
    except ValueError:
        lookback_hours = 72

    # Collect telemetry from all sources
    telemetry, detected_type, correlated_ip, correlated_user, \
        sentinel_sev, sources_hit = collect_telemetry(
            logs_client, LOG_ANALYTICS_WORKSPACE_ID, identity, lookback_hours
        )

    record_count = len(telemetry.splitlines()) - 1 if telemetry else 0

    # Classify and route
    matched  = classify_issue(telemetry, issue_desc)
    label    = matched["label"]
    priority = matched["priority"]
    team     = matched["team"]
    note     = matched["note"].format(identity=identity)

    # Upgrade priority if Sentinel/Defender found a higher severity
    if sentinel_sev:
        sev_map = {"High": "Critical", "Medium": "High",
                   "Low": "Medium", "Informational": "Low"}
        upgraded = sev_map.get(sentinel_sev, priority)
        if PRIORITY_ORDER.get(upgraded, 9) < PRIORITY_ORDER.get(priority, 9):
            print(f"  [!] Priority upgraded {priority} → {upgraded} "
                  f"based on Sentinel/Defender severity: {sentinel_sev}")
            priority = upgraded

    # Build ticket
    ticket_id = generate_ticket_id(team)
    ticket = Ticket(
        ticket_id    = ticket_id,
        requester    = requester,
        user         = correlated_user or (identity if detected_type == "User" else "N/A"),
        device_name  = identity if detected_type == "Device" else "N/A",
        issue        = label,
        error_message= issue_desc,
        severity     = priority,
        assigned_team= team,
    )

    # Run ticket through state pipeline
    ticket.transition(TicketState.TRIAGED)
    ticket.transition(TicketState.IN_PROGRESS)
    ticket.transition(TicketState.RESOLVED)
    ticket.transition(TicketState.CLOSED)

    # Terminal output
    color = URGENCY_COLORS.get(priority, "")
    sep   = "=" * 52

    print(f"\n{sep}")
    print("  ROUTING DECISION")
    print(sep)
    print(f"  Ticket ID        : {ticket_id}")
    print(f"  Lookback Window  : {LOOKBACK_WINDOW}")
    print(f"  Identity         : {identity}")
    print(f"  Identity Type    : {detected_type}")
    if correlated_ip:
        print(f"  Correlated IP    : {correlated_ip}")
    if correlated_user:
        print(f"  Correlated User  : {correlated_user}")
    print(f"  Sources Queried  : {len(sources_hit)}")
    print(f"  Records Found    : {record_count}")
    print(f"  Issue Label      : {label}")
    if sentinel_sev:
        print(f"  Sentinel/Defender: {sentinel_sev}")
    print(f"  Priority         : {color}{priority}{RESET}")
    print(f"  Assigned Team    : {team.value}")
    print(sep)
    print(f"\n  Escalation Note:\n  {note}\n")

    # Build enrichment for documentation
    sources_str = ", ".join(sources_hit) if sources_hit else "None"
    enrichment = f"""
Lookback Window      : {LOOKBACK_WINDOW}
Identity Queried     : {identity}
Identity Type        : {detected_type}
Correlated IP        : {correlated_ip or 'N/A'}
Correlated User      : {correlated_user or 'N/A'}
Sources Hit          : {sources_str}
Records Returned     : {record_count}
Sentinel/Defender Sev: {sentinel_sev or 'N/A'}
Issue Label          : {label}
Priority             : {priority}
Assigned Team        : {team.value}

Escalation Note:
{note}

Raw Telemetry (truncated):
{telemetry[:3000] if telemetry else 'No telemetry collected'}
"""

    result = ticket.generate_documentation(enrichment, COMPANY_NAME)
    print(result)


if __name__ == "__main__":
    main()
