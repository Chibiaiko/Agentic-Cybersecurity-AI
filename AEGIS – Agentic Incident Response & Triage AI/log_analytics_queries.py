from datetime import timedelta
import pandas as pd
from colorama import Fore


# ============================================================================
# INTERNAL SAFETY
# ============================================================================

def _safe(value):
    return value if value not in [None, "", "None"] else ""


# ============================================================================
# CORE QUERY EXECUTOR
# ============================================================================

def _execute_query(
    log_analytics_client,
    workspace_id,
    table_name,
    device_name,
    time_range_hours,
    fields,
    caller=""
):
    project_fields = ", ".join(fields) if fields else "TimeGenerated"

    table_name = _safe(table_name)
    device_name = _safe(device_name)
    caller = _safe(caller)

    if table_name == "AzureNetworkAnalytics_CL":
        query = f"""
{table_name}
| where FlowType_s == "MaliciousFlow"
| project {project_fields}
| order by TimeGenerated desc
"""

    elif table_name == "AzureActivity" and caller:
        query = f"""
{table_name}
| where Caller startswith "{caller}"
| project {project_fields}
| order by TimeGenerated desc
"""

    elif table_name == "SigninLogs" and caller:
        query = f"""
{table_name}
| where UserPrincipalName startswith "{caller}"
| project {project_fields}
| order by TimeGenerated desc
"""

    elif device_name:
        query = f"""
{table_name}
| where DeviceName startswith "{device_name}"
| project {project_fields}
| order by TimeGenerated desc
"""

    else:
        query = f"""
{table_name}
| project {project_fields}
| order by TimeGenerated desc
"""

    print(f"{Fore.LIGHTGREEN_EX}Constructed KQL Query:{Fore.WHITE}")
    print(query.strip(), "\n")

    response = log_analytics_client.query_workspace(
        workspace_id=workspace_id,
        query=query,
        timespan=timedelta(hours=int(time_range_hours))
    )

    if not response.tables:
        return ""

    table = response.tables[0]
    df = pd.DataFrame(table.rows, columns=table.columns)
    return df.to_csv(index=False)


# ============================================================================
# 🔥 AEGIS HARD SHIM — ACCEPTS ANY ARGUMENTS
# ============================================================================

def query_log_analytics(*args, **kwargs):
    """
    DO NOT CHANGE.
    This function intentionally accepts ANY signature.
    """

    log_analytics_client = kwargs.get("client") or kwargs.get("log_analytics_client")
    workspace_id = kwargs.get("workspace_id")

    table_name = kwargs.get("table") or kwargs.get("table_name")
    device_name = kwargs.get("device_name", "")
    caller = kwargs.get("caller", "")

    time_range_hours = (
        kwargs.get("lookback_hours")
        or kwargs.get("time_range_hours")
        or 24
    )

    fields = kwargs.get("fields") or ["TimeGenerated"]

    if not log_analytics_client or not workspace_id or not table_name:
        return ""

    return _execute_query(
        log_analytics_client=log_analytics_client,
        workspace_id=workspace_id,
        table_name=table_name,
        device_name=device_name,
        time_range_hours=time_range_hours,
        fields=fields,
        caller=caller
    )
