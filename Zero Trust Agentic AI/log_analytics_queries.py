# log_analytics_queries.py
from datetime import timedelta
from azure.identity import DefaultAzureCredential, CredentialUnavailableError
from azure.monitor.query import LogsQueryClient
from secrets_ import LOG_ANALYTICS_WORKSPACE_ID
from colorama import Fore
import pandas as pd

# ==================== TIME RANGE CONFIGURATION ====================
# timerange_hours = 1      # Last 1 hour
# timerange_hours = 24     # Last 24 hours (1 day) - Currently active
# timerange_hours = 168    # Last 7 days (1 week)
# timerange_hours = 720    # Last 30 days (1 month)

timerange_hours = 24
# ====================================================================

# Zero Trust Assessment Steps
ZERO_TRUST_STEPS = {
    1: "Analyze authentication anomalies (geo anomalies, brute force, impossible travel).",
    2: "Evaluate privilege escalation and least privilege violations.",
    3: "Assess lateral movement indicators.",
    4: "Detect trust boundary violations.",
    5: "Identify monitoring visibility gaps.",
    6: "Detect conditional access / policy enforcement failures.",
    7: "Assume breach and identify attacker persistence behaviors.",
    8: "Prioritize risk areas aligned with Zero Trust."
}

# MITRE ATT&CK Framework Mapping
MITRE_MAPPING = {
    1: "T1078 - Valid Accounts",
    2: "T1068 - Privilege Escalation",
    3: "T1021 - Remote Services",
    4: "T1199 - Trusted Relationship",
    5: "T1087 - Account Discovery",
    6: "T1556 - Modify Authentication Process",
    7: "T1053 - Scheduled Task Persistence",
    8: "T1595 - Active Scanning"
}


# KQL Query Templates for different table types
def build_kql_query(table_name, device_name="", user_name="", fields="*", hours=24):
    """
    Build KQL queries for different table types.
    
    Supported tables:
    - SecurityEvent: Windows Security events
    - Syslog: Linux syslog events
    - AuditLogs: Azure AD audit logs
    - SigninLogs: Azure AD sign-in logs
    - CloudAppEvents: Microsoft Defender for Cloud Apps events
    - DeviceNetworkEvents: Endpoint device network events
    - DeviceProcessEvents: Endpoint device process events
    - OfficeActivity: Microsoft 365 activity
    - CommonSecurityLog: CEF/Syslog from various security appliances
    """
    
    if table_name == "SecurityEvent":
        return f'''{table_name}
| where TimeGenerated > ago({hours}h)
| where DeviceName startswith "{device_name}" or "{device_name}" == ""
| project {fields}
| order by TimeGenerated desc'''
        
    elif table_name == "Syslog":
        return f'''{table_name}
| where TimeGenerated > ago({hours}h)
| where Computer startswith "{device_name}" or "{device_name}" == ""
| project {fields}
| order by TimeGenerated desc'''
        
    elif table_name == "AuditLogs":
        return f'''{table_name}
| where TimeGenerated > ago({hours}h)
| where InitiatedBy contains "{user_name}" or "{user_name}" == ""
| project {fields}
| order by TimeGenerated desc'''
        
    elif table_name == "SigninLogs":
        return f'''{table_name}
| where TimeGenerated > ago({hours}h)
| where UserPrincipalName startswith "{user_name}" or "{user_name}" == ""
| project {fields}
| order by TimeGenerated desc'''
        
    elif table_name == "CloudAppEvents":
        return f'''{table_name}
| where TimeGenerated > ago({hours}h)
| where AccountName startswith "{user_name}" or "{user_name}" == ""
| project {fields}
| order by TimeGenerated desc'''
        
    elif table_name == "DeviceNetworkEvents":
        return f'''{table_name}
| where TimeGenerated > ago({hours}h)
| where DeviceName startswith "{device_name}" or "{device_name}" == ""
| project {fields}
| order by TimeGenerated desc'''
        
    elif table_name == "DeviceProcessEvents":
        return f'''{table_name}
| where TimeGenerated > ago({hours}h)
| where DeviceName startswith "{device_name}" or "{device_name}" == ""
| project {fields}
| order by TimeGenerated desc'''
        
    elif table_name == "OfficeActivity":
        return f'''{table_name}
| where TimeGenerated > ago({hours}h)
| where UserId startswith "{user_name}" or "{user_name}" == ""
| project {fields}
| order by TimeGenerated desc'''
        
    elif table_name == "CommonSecurityLog":
        return f'''{table_name}
| where TimeGenerated > ago({hours}h)
| project {fields}
| order by TimeGenerated desc'''
        
    else:
        # Default fallback query
        return f'''{table_name}
| where TimeGenerated > ago({hours}h)
| project {fields}
| order by TimeGenerated desc'''


class LogAnalyticsQuery:
    def __init__(self):
        if not LOG_ANALYTICS_WORKSPACE_ID or "YOUR_" in LOG_ANALYTICS_WORKSPACE_ID:
            raise ValueError("Invalid LOG_ANALYTICS_WORKSPACE_ID in secrets_.py")

        try:
            # We use DefaultAzureCredential to allow various auth methods (CLI, Environment, MSI)
            self.credential = DefaultAzureCredential()
            self.client = LogsQueryClient(self.credential)
        except CredentialUnavailableError:
            print("ERROR: Azure credentials unavailable. Please log in via Azure CLI.")
            raise

    def get_security_summary(self, hours=24):
        """
        Executes a read-only KQL query to get security event summary.
        """
        kql_query = """
        SecurityEvent
        | where TimeGenerated > ago(24h)
        | summarize EventCount = count() by EventLevelName
        """
        
        try:
            # Show what query is being executed
            print("\n" + "="*70)
            print("🔍 EXECUTING KQL QUERY")
            print("="*70)
            print("\nKQL Query:")
            print("─" * 70)
            print(kql_query)
            print("─" * 70)
            print(f"⏱️  Time Range: Last {hours} hours")
            print(f"📊 Workspace ID: {LOG_ANALYTICS_WORKSPACE_ID}")
            print("\nExecuting query...")
            
            response = self.client.query_workspace(
                workspace_id=LOG_ANALYTICS_WORKSPACE_ID,
                query=kql_query,
                timespan=timedelta(hours=hours)
            )
            
            # Convert result to list of dicts for easier processing
            result = [
                dict(zip(table.columns, row))
                for table in response.tables
                for row in table.rows
            ]
            
            # Show success message only
            print("\n✅ Query executed successfully!")
            print(f"📊 Records retrieved: {len(result)}")
            print("="*70 + "\n")
            
            return result
            
        except Exception as e:
            print(f"\n❌ Error querying Log Analytics: {e}")
            print(f"   Please verify:")
            print(f"   - Workspace ID is correct: {LOG_ANALYTICS_WORKSPACE_ID}")
            print(f"   - You have 'Log Analytics Reader' role")
            print(f"   - Azure CLI is authenticated (run: az login)")
            return None

    def query_logs(self, table_name, timerange_hours=24, device_name="", user_name="", fields="*"):
        """
        Advanced query for any supported Log Analytics table type.
        
        Args:
            table_name: Log Analytics table to query
                - SecurityEvent: Windows Security events
                - Syslog: Linux syslog events
                - AuditLogs: Azure AD audit logs
                - SigninLogs: Azure AD sign-in logs
                - CloudAppEvents: Microsoft Defender for Cloud Apps events
                - DeviceNetworkEvents: Endpoint device network events
                - DeviceProcessEvents: Endpoint device process events
                - OfficeActivity: Microsoft 365 activity
                - CommonSecurityLog: CEF/Syslog from various security appliances
            timerange_hours: Number of hours to look back (default: 24)
            device_name: Device/Computer name to filter (optional)
            user_name: User/Account name to filter (optional)
            fields: Comma-separated field names to project (default: '*' for all)
        
        Returns:
            CSV formatted results as string, or None if error
        """
        
        try:
            # Validate table name
            valid_tables = [
                "SecurityEvent", "Syslog", "AuditLogs", "SigninLogs",
                "CloudAppEvents", "DeviceNetworkEvents", "DeviceProcessEvents",
                "OfficeActivity", "CommonSecurityLog"
            ]
            
            if table_name not in valid_tables:
                print(f"\n{Fore.RED}❌ Invalid table name: {table_name}")
                print(f"Valid tables are: {', '.join(valid_tables)}\n")
                return None
            
            # Construct KQL query based on table type
            user_query = build_kql_query(
                table_name=table_name,
                device_name=device_name,
                user_name=user_name,
                fields=fields,
                hours=timerange_hours
            )
            
            # Display the constructed query
            print(f"\n{Fore.LIGHTGREEN_EX}Constructed KQL Query:")
            print(f"{Fore.WHITE}{user_query}\n")
            
            # Show query metadata
            print(f"{Fore.LIGHTGREEN_EX}Querying Log Analytics Workspace ID: '{LOG_ANALYTICS_WORKSPACE_ID}'...")
            print(f"⏱️  Time Range: Last {timerange_hours} hours")
            print(f"📊 Table: {table_name}")
            if device_name:
                print(f"🖥️  Device Filter: {device_name}")
            if user_name:
                print(f"👤 User Filter: {user_name}")
            print()
            
            # Execute query
            response = self.client.query_workspace(
                workspace_id=LOG_ANALYTICS_WORKSPACE_ID,
                query=user_query,
                timespan=timedelta(hours=timerange_hours)
            )
            
            # Check if results exist
            if not response.tables or len(response.tables[0].rows) == 0:
                print(f"{Fore.YELLOW}⚠️  No records found for this query.\n")
                return None
            
            # Extract the table
            table = response.tables[0]
            columns = table.columns
            rows = table.rows
            
            print(f"{Fore.WHITE}✅ Log Analytics query returned {len(rows)} record(s).\n")
            
            # Convert to DataFrame and then to CSV
            df = pd.DataFrame(rows, columns=columns)
            results = df.to_csv(index=False)
            
            return results
            
        except Exception as e:
            print(f"\n{Fore.RED}❌ Error querying Log Analytics: {e}")
            print(f"   Please verify:")
            print(f"   - Table name is correct: {table_name}")
            print(f"   - Workspace ID is correct: {LOG_ANALYTICS_WORKSPACE_ID}")
            print(f"   - You have 'Log Analytics Reader' role")
            print(f"   - Azure CLI is authenticated (run: az login)\n")
            return None

    def get_available_tables(self):
        """Return list of available table names."""
        return [
            "SecurityEvent",
            "Syslog",
            "AuditLogs",
            "SigninLogs",
            "CloudAppEvents",
            "DeviceNetworkEvents",
            "DeviceProcessEvents",
            "OfficeActivity",
            "CommonSecurityLog"
        ]
