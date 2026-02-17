# log_analytics_queries.py
# Query engine for Azure Log Analytics, Microsoft Sentinel, and Defender for Endpoint
#
# Table sources:
#   Log Analytics (Native)  — SecurityEvent, Heartbeat, Perf, Event, Syslog
#   Microsoft Sentinel      — SecurityAlert, SecurityIncident, ThreatIntelligenceIndicator,
#                             AuditLogs, SigninLogs, AADUserRiskEvents, AADRiskyUsers
#   Defender for Endpoint   — DeviceNetworkEvents, DeviceProcessEvents, DeviceLogonEvents,
#                             DeviceFileEvents, DeviceAlertEvents, DeviceInfo

from datetime import timedelta
from io import StringIO
import pandas as pd


# ===========================================================================
# Input Sanitization
# ===========================================================================

def _sanitize(value: str) -> str:
    """Escape double quotes to prevent breaking KQL string literals."""
    if not value:
        return ""
    return value.replace('"', '\\"').replace("'", "\\'")


# ===========================================================================
# Generic KQL Query Builders
# ===========================================================================

def build_startswith_query(table_name: str, column_name: str,
                            value: str, fields: list) -> str:
    """KQL query using startswith filter — matches partial names/usernames."""
    value = _sanitize(value)
    return f"""
{table_name}
| where {column_name} startswith "{value}"
| project {', '.join(fields)}
| order by TimeGenerated desc
"""


def build_exact_match_query(table_name: str, column_name: str,
                             value: str, fields: list) -> str:
    """KQL query using exact match filter — used for IPs, event IDs, etc."""
    value = _sanitize(value)
    return f"""
{table_name}
| where {column_name} == "{value}"
| project {', '.join(fields)}
| order by TimeGenerated desc
"""


def build_contains_query(table_name: str, column_name: str,
                          value: str, fields: list) -> str:
    """KQL query using contains filter — used for partial string matching."""
    value = _sanitize(value)
    return f"""
{table_name}
| where {column_name} contains "{value}"
| project {', '.join(fields)}
| order by TimeGenerated desc
"""


def build_event_id_query(table_name: str, event_ids: list,
                          identity: str, identity_column: str,
                          fields: list) -> str:
    """
    KQL query filtering by one or more Windows Event IDs.
    Used for SecurityEvent brute-force, privilege escalation, etc.
    """
    identity = _sanitize(identity)
    ids_str  = " or ".join(f"EventID == {eid}" for eid in event_ids)
    return f"""
{table_name}
| where ({ids_str})
| where {identity_column} startswith "{identity}"
| project {', '.join(fields)}
| order by TimeGenerated desc
"""


# ===========================================================================
# Log Analytics — Native Tables
# ===========================================================================

def build_device_logon_query(table_name: str, device_name: str,
                              fields: list) -> str:
    """
    SecurityEvent — query by Computer (device name).
    Used for device-based investigation: logon events, event IDs.
    Source: Native Log Analytics
    """
    return build_startswith_query(table_name, "Computer", device_name, fields)


def build_user_logon_query(table_name: str, user_name: str,
                            fields: list) -> str:
    """
    SecurityEvent — query by Account (username).
    Used for user-based investigation: logon activity, failed attempts.
    Source: Native Log Analytics
    """
    return build_startswith_query(table_name, "Account", user_name, fields)


def build_ip_correlation_query(table_name: str, ip_address: str,
                                fields: list) -> str:
    """
    Correlate an IP address back to a user or device.
    Works across SigninLogs, SecurityEvent, DeviceNetworkEvents.
    Source: Native Log Analytics / Sentinel
    """
    return build_exact_match_query(table_name, "IPAddress", ip_address, fields)


def build_heartbeat_query(device_name: str) -> str:
    """
    Heartbeat table — check if a device is online/offline.
    Missing heartbeat = Network Outage or Agent Offline alert.
    Source: Native Log Analytics
    """
    device_name = _sanitize(device_name)
    return f"""
Heartbeat
| where Computer startswith "{device_name}"
| summarize LastHeartbeat=max(TimeGenerated) by Computer, OSType, Version
| extend MinutesSinceLastHeartbeat = datetime_diff('minute', now(), LastHeartbeat)
| project Computer, LastHeartbeat, MinutesSinceLastHeartbeat, OSType, Version
| order by MinutesSinceLastHeartbeat desc
"""


def build_performance_query(device_name: str) -> str:
    """
    Perf table — CPU, memory, and network utilization.
    High utilization can indicate bandwidth saturation or malware activity.
    Source: Native Log Analytics
    """
    device_name = _sanitize(device_name)
    return f"""
Perf
| where Computer startswith "{device_name}"
| where ObjectName in ("Processor", "Memory", "Network Interface")
| where CounterName in ("% Processor Time", "Available MBytes",
                        "Bytes Sent/sec", "Bytes Received/sec")
| summarize AvgValue=avg(CounterValue) by Computer, ObjectName, CounterName
| order by AvgValue desc
"""


def build_brute_force_query(identity: str, identity_type: str = "device") -> str:
    """
    SecurityEvent — detect brute-force / multiple failed login attempts.
    Event ID 4625 = Failed Logon.
    Threshold: 5+ failures in the lookback window flags as brute-force.
    Source: Native Log Analytics

    Parameters
    ----------
    identity      : str   Device name or username
    identity_type : str   "device" (filters on Computer) or "user" (filters on Account)
    """
    identity = _sanitize(identity)
    column   = "Computer" if identity_type == "device" else "Account"
    return f"""
SecurityEvent
| where EventID == 4625
| where {column} startswith "{identity}"
| summarize FailureCount=count(), 
            FirstAttempt=min(TimeGenerated),
            LastAttempt=max(TimeGenerated),
            SourceIPs=make_set(IpAddress)
  by {column}, Account, WorkstationName
| where FailureCount >= 5
| order by FailureCount desc
"""


def build_account_lockout_query(identity: str) -> str:
    """
    SecurityEvent — detect account lockout events.
    Event ID 4740 = Account Locked Out.
    Source: Native Log Analytics
    """
    identity = _sanitize(identity)
    return f"""
SecurityEvent
| where EventID == 4740
| where TargetUserName startswith "{identity}" 
     or SubjectUserName startswith "{identity}"
| project TimeGenerated, TargetUserName, SubjectUserName,
          Computer, SubjectDomainName
| order by TimeGenerated desc
"""


def build_privilege_escalation_query(identity: str) -> str:
    """
    SecurityEvent — detect privilege escalation activity.
    Event ID 4672 = Special Privileges Assigned (admin logon)
    Event ID 4673 = Privileged Service Called
    Source: Native Log Analytics
    """
    identity = _sanitize(identity)
    return f"""
SecurityEvent
| where EventID in (4672, 4673, 4674)
| where SubjectUserName startswith "{identity}"
     or TargetUserName startswith "{identity}"
| project TimeGenerated, EventID, SubjectUserName, TargetUserName,
          Computer, PrivilegeList, ProcessName
| order by TimeGenerated desc
"""


def build_rdp_ssh_query(device_name: str) -> str:
    """
    SecurityEvent — detect RDP/SSH login attempts.
    Event ID 4648 = Explicit Credential Logon (RDP)
    LogonType 10  = RemoteInteractive (RDP)
    Source: Native Log Analytics
    """
    device_name = _sanitize(device_name)
    return f"""
SecurityEvent
| where Computer startswith "{device_name}"
| where (EventID == 4648) or (EventID == 4624 and LogonType == 10)
| project TimeGenerated, EventID, Account, Computer,
          IpAddress, LogonType, ProcessName
| order by TimeGenerated desc
"""


def build_config_change_query(device_name: str) -> str:
    """
    SecurityEvent — detect unauthorized configuration changes.
    Event ID 4719 = System Audit Policy Changed
    Event ID 4907 = Auditing Settings Changed
    Source: Native Log Analytics
    """
    device_name = _sanitize(device_name)
    return f"""
SecurityEvent
| where Computer startswith "{device_name}"
| where EventID in (4719, 4907, 4670, 4657)
| project TimeGenerated, EventID, SubjectUserName, Computer,
          ObjectName, OldValue, NewValue
| order by TimeGenerated desc
"""


# ===========================================================================
# Microsoft Sentinel Tables
# ===========================================================================

def build_sentinel_alerts_query(identity: str) -> str:
    """
    SecurityAlert — active Sentinel alerts for a device or user.
    Covers alerts from all connected data connectors including
    Defender, MDE, and custom analytics rules.
    Source: Microsoft Sentinel
    """
    identity = _sanitize(identity)
    return f"""
SecurityAlert
| where Entities contains "{identity}"
    or CompromisedEntity contains "{identity}"
    or ExtendedProperties contains "{identity}"
| project TimeGenerated, AlertName, AlertSeverity, Description,
          CompromisedEntity, Tactics, Techniques,
          ProviderName, ProductName, RemediationSteps
| order by TimeGenerated desc
"""


def build_sentinel_incidents_query(identity: str) -> str:
    """
    SecurityIncident — open/active Sentinel incidents linked to an identity.
    Source: Microsoft Sentinel
    """
    identity = _sanitize(identity)
    return f"""
SecurityIncident
| where Title contains "{identity}"
    or Description contains "{identity}"
| project TimeGenerated, IncidentNumber, Title, Severity, Status,
          Owner, Classification, Description, ProviderName
| order by TimeGenerated desc
"""


def build_signin_logs_query(user_principal: str, fields: list) -> str:
    """
    SigninLogs — Azure AD / Entra ID sign-in activity for a user.
    Includes ResultType (0=success, non-zero=failure), location, IP, MFA status.
    Source: Microsoft Sentinel / Azure AD Diagnostic Settings
    """
    return build_startswith_query("SigninLogs", "UserPrincipalName",
                                  user_principal, fields)


def build_risky_user_query(user_principal: str) -> str:
    """
    AADRiskyUsers + AADUserRiskEvents — Azure AD Identity Protection risk signals.
    Flags accounts with compromised credential risk, impossible travel, etc.
    Source: Microsoft Sentinel / Azure AD
    """
    user_principal = _sanitize(user_principal)
    return f"""
AADRiskyUsers
| where UserPrincipalName startswith "{user_principal}"
| project TimeGenerated, UserPrincipalName, RiskLevel, RiskState,
          RiskDetail, RiskLastUpdatedDateTime
| order by TimeGenerated desc
"""


def build_risky_signin_query(user_principal: str) -> str:
    """
    AADUserRiskEvents — individual risk events (impossible travel,
    leaked credentials, anonymous IP, malware-linked IP, etc.)
    Source: Microsoft Sentinel / Azure AD Identity Protection
    """
    user_principal = _sanitize(user_principal)
    return f"""
AADUserRiskEvents
| where UserPrincipalName startswith "{user_principal}"
| project TimeGenerated, UserPrincipalName, RiskEventType,
          RiskLevel, RiskState, IpAddress, Location, DetectionTimingType
| order by TimeGenerated desc
"""


def build_unusual_location_query(user_principal: str) -> str:
    """
    SigninLogs — detect logins from unusual locations.
    Flags sign-ins where LocationDetails differs from the user's
    most common location in the last 30 days.
    Source: Microsoft Sentinel / Azure AD
    """
    user_principal = _sanitize(user_principal)
    return f"""
SigninLogs
| where UserPrincipalName startswith "{user_principal}"
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize LoginCount=count() by Country, UserPrincipalName
| order by LoginCount asc
"""


# ===========================================================================
# Microsoft Defender for Endpoint Tables
# ===========================================================================

def build_defender_alerts_query(device_name: str) -> str:
    """
    DeviceAlertEvents — Defender for Endpoint alerts on a specific device.
    Covers malware, suspicious behaviour, ransomware, lateral movement.
    Source: Defender for Endpoint / MDE
    """
    device_name = _sanitize(device_name)
    return f"""
DeviceAlertEvents
| where DeviceName startswith "{device_name}"
| project TimeGenerated, AlertId, Title, Severity, Category,
          DeviceName, FileName, ProcessCommandLine,
          RemoteIP, RemoteUrl, AttackTechniques
| order by TimeGenerated desc
"""


def build_device_network_events_query(device_name: str, fields: list) -> str:
    """
    DeviceNetworkEvents — all network connections from a device.
    Used for: data exfiltration, C2 communication, DNS failures,
    VPN activity, bandwidth anomalies.
    Source: Defender for Endpoint
    """
    return build_startswith_query("DeviceNetworkEvents", "DeviceName",
                                  device_name, fields)


def build_device_process_events_query(device_name: str) -> str:
    """
    DeviceProcessEvents — process creation events on a device.
    Used for: suspicious process execution, LOLBins, encoded commands,
    malware spawning child processes.
    Source: Defender for Endpoint
    """
    device_name = _sanitize(device_name)
    return f"""
DeviceProcessEvents
| where DeviceName startswith "{device_name}"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          AccountName, AccountDomain, SHA256
| order by TimeGenerated desc
"""


def build_device_logon_events_query(device_name: str) -> str:
    """
    DeviceLogonEvents — interactive and remote logons to a device.
    Covers RDP, network logons, local interactive sessions.
    Source: Defender for Endpoint
    """
    device_name = _sanitize(device_name)
    return f"""
DeviceLogonEvents
| where DeviceName startswith "{device_name}"
| project TimeGenerated, DeviceName, AccountName, AccountDomain,
          LogonType, RemoteIP, RemoteDeviceName, IsLocalAdmin,
          ActionType
| order by TimeGenerated desc
"""


def build_device_file_events_query(device_name: str) -> str:
    """
    DeviceFileEvents — file creation, modification, deletion on a device.
    Used for: data staging before exfiltration, ransomware file changes,
    malware dropping payloads.
    Source: Defender for Endpoint
    """
    device_name = _sanitize(device_name)
    return f"""
DeviceFileEvents
| where DeviceName startswith "{device_name}"
| project TimeGenerated, DeviceName, ActionType, FileName,
          FolderPath, FileSize, SHA256, InitiatingProcessFileName,
          InitiatingProcessAccountName
| order by TimeGenerated desc
"""


def build_data_exfil_query(device_name: str) -> str:
    """
    DeviceNetworkEvents — detect abnormal outbound data volume.
    Flags connections where the outbound byte count is significantly
    above baseline — potential data exfiltration.
    Source: Defender for Endpoint
    """
    device_name = _sanitize(device_name)
    return f"""
DeviceNetworkEvents
| where DeviceName startswith "{device_name}"
| where ActionType == "ConnectionSuccess"
| summarize TotalBytesSent=sum(SentBytes),
            ConnectionCount=count(),
            DestinationIPs=make_set(RemoteIP)
  by DeviceName, RemoteUrl, bin(TimeGenerated, 1h)
| where TotalBytesSent > 10000000
| order by TotalBytesSent desc
"""


def build_device_info_query(device_name: str) -> str:
    """
    DeviceInfo — device inventory and health information.
    Includes OS, onboarding status, last seen, exposure level.
    Source: Defender for Endpoint
    """
    device_name = _sanitize(device_name)
    return f"""
DeviceInfo
| where DeviceName startswith "{device_name}"
| project TimeGenerated, DeviceName, OSPlatform, OSVersion,
          PublicIP, OnboardingStatus, ExposureLevel,
          IsAzureADJoined, LastSeen=TimeGenerated
| order by TimeGenerated desc
"""


# ===========================================================================
# Query Execution
# ===========================================================================

def run_log_analytics_query(client, workspace_id: str, query: str,
                             time_range_hours: int) -> str:
    """
    Execute a KQL query against an Azure Log Analytics workspace.

    Works for all three sources (Log Analytics, Sentinel, Defender)
    as long as the workspace has the relevant tables connected.

    Parameters
    ----------
    client           : LogsQueryClient   Authenticated Azure client
    workspace_id     : str               Log Analytics workspace GUID
    query            : str               KQL query string
    time_range_hours : int               Lookback window in hours

    Returns
    -------
    str
        Results as CSV string. Empty string if no tables or no rows.
    """
    try:
        response = client.query_workspace(
            workspace_id=workspace_id,
            query=query,
            timespan=timedelta(hours=time_range_hours)
        )

        if not response.tables:
            return ""

        table = response.tables[0]
        if not table.rows:
            return ""

        df = pd.DataFrame(table.rows, columns=table.columns)
        return df.to_csv(index=False)

    except Exception as e:
        return f"[ERROR] Query failed: {e}"


# ===========================================================================
# CSV Extraction Helpers
# ===========================================================================

def extract_ip_from_csv(csv_data: str):
    """
    Extract the first IP address from a CSV query result.
    Checks columns in priority order: LocalIP, IpAddress, IPAddress,
    ClientIP, SourceIP, RemoteIP, DestinationIP.

    Returns str or None.
    """
    if not csv_data or csv_data.startswith("[ERROR]"):
        return None
    try:
        df = pd.read_csv(StringIO(csv_data))
        for col in ["LocalIP", "IpAddress", "IPAddress", "ClientIP",
                    "SourceIP", "RemoteIP", "DestinationIP"]:
            if col in df.columns:
                values = df[col].dropna()
                if not values.empty:
                    ip = str(values.iloc[0])
                    # Skip empty or placeholder values
                    if ip and ip not in ("-", "N/A", "nan", "::1", "127.0.0.1"):
                        return ip
    except Exception:
        pass
    return None


def extract_user_from_csv(csv_data: str):
    """
    Extract the first username from a CSV query result.
    Checks: UserPrincipalName, Account, AccountName, SubjectUserName.

    Returns str or None.
    """
    if not csv_data or csv_data.startswith("[ERROR]"):
        return None
    try:
        df = pd.read_csv(StringIO(csv_data))
        for col in ["UserPrincipalName", "Account", "AccountName", "SubjectUserName"]:
            if col in df.columns:
                values = df[col].dropna()
                if not values.empty:
                    user = str(values.iloc[0])
                    if user and user not in ("-", "N/A", "nan", "SYSTEM",
                                             "LOCAL SERVICE", "NETWORK SERVICE"):
                        return user
    except Exception:
        pass
    return None


def extract_severity_from_csv(csv_data: str):
    """
    Extract the highest alert severity from a Sentinel or Defender alert CSV.
    Returns: 'High', 'Medium', 'Low', 'Informational', or None.
    """
    if not csv_data or csv_data.startswith("[ERROR]"):
        return None
    try:
        df = pd.read_csv(StringIO(csv_data))
        for col in ["AlertSeverity", "Severity"]:
            if col in df.columns:
                values = df[col].dropna()
                if not values.empty:
                    order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
                    sorted_vals = sorted(values, key=lambda x: order.get(str(x), 9))
                    return str(sorted_vals[0])
    except Exception:
        pass
    return None
