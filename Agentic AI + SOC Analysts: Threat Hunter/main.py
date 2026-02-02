# =============================================================================
# Standard Library Imports
# =============================================================================
import time
import json
import os
from datetime import datetime

# =============================================================================
# Third-Party Imports
# =============================================================================
from colorama import Fore, init
from openai import OpenAI
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient

# =============================================================================
# Internal Imports
# =============================================================================
import utilities
import queries.log_analytics_queries as queries
import models.models as models
from secrets_ import LOG_ANALYTICS_WORKSPACE_ID, API_KEY

import context.prompts as prompts
from context.prompts import SYSTEM_PROMPT_THREAT_HUNT
from context.prompt_builder import build_threat_hunt_prompt

from protocols.function_tools import tools
import protocols.hunt_protocol as hunt_protocol
import protocols.tool_routing as tool_routing

# =============================================================================
# Initialization
# =============================================================================

init(autoreset=True)

law_client = LogsQueryClient(credential=DefaultAzureCredential())
openai_client = OpenAI(api_key=API_KEY)

# =============================================================================
# Output Paths
# =============================================================================

REPORT_TIME = datetime.utcnow()
DATE_ONLY = REPORT_TIME.strftime("%Y-%m-%d")
TIMESTAMP = REPORT_TIME.strftime("%Y-%m-%d_%H-%M-%S")

SUMMARY_DIR = "summary"
os.makedirs(SUMMARY_DIR, exist_ok=True)

JSON_REPORT_PATH = os.path.join(SUMMARY_DIR, f"ai_threat_hunt_{TIMESTAMP}.json")
TXT_REPORT_PATH = os.path.join(SUMMARY_DIR, f"{DATE_ONLY}.txt")

# =============================================================================
# KQL → MITRE ATT&CK Mapping (Authoritative)
# =============================================================================

KQL_ATTACK_MAPPING = {
    "Suspicious Logon Patterns": {"tactic": "Initial Access", "techniques": ["T1078"]},
    "Brute Force Authentication": {"tactic": "Initial Access", "techniques": ["T1110"]},
    "Impossible Travel": {"tactic": "Initial Access", "techniques": ["T1078"]},

    "LSASS Memory Access": {"tactic": "Credential Access", "techniques": ["T1003.001"]},
    "Password Spraying": {"tactic": "Credential Access", "techniques": ["T1110.003"]},

    "Account Discovery": {"tactic": "Discovery", "techniques": ["T1087"]},
    "System Information Discovery": {"tactic": "Discovery", "techniques": ["T1082"]},

    "RDP Lateral Movement": {"tactic": "Lateral Movement", "techniques": ["T1021.001"]},
    "SMB Admin Shares": {"tactic": "Lateral Movement", "techniques": ["T1021.002"]},

    "C2 HTTP Beaconing": {"tactic": "Command and Control", "techniques": ["T1071.001"]},
    "DNS Tunneling": {"tactic": "Command and Control", "techniques": ["T1071.004"]},

    "Disable Security Tools": {"tactic": "Defense Evasion", "techniques": ["T1562.001"]},
}

# =============================================================================
# User Prompt
# =============================================================================

user_message = prompts.get_user_message()

print(f"{Fore.WHITE}\nDeciding log search parameters based on user request...\n")

args = tool_routing.get_log_query_from_agent(openai_client, user_message)

table = args["table_name"]
time_range = args["time_range_hours"]
fields = ", ".join(map(str, args["fields"]))
device = args.get("device_name", "")
caller = args.get("caller", "")

print(f"{Fore.LIGHTGREEN_EX}Log search parameters finalized:")
print(f"{Fore.WHITE}Table Name:  {table}")
print(f"{Fore.WHITE}Device Name: {device or 'Not specified'}")
print(f"{Fore.WHITE}Caller:      {caller or 'Not specified'}")
print(f"{Fore.WHITE}Time Range:  {time_range} hour(s)")
print(f"{Fore.WHITE}Fields:      {fields}\n")

# =============================================================================
# Query Logs
# =============================================================================

law_query_results = queries.query_devicelogonevents(
    log_analytics_client=law_client,
    workspace_id=LOG_ANALYTICS_WORKSPACE_ID,
    timerange_hours=time_range,
    table_name=table,
    device_name=device,
    caller=caller,
    fields=fields,
)

# =============================================================================
# Build Threat Hunt Prompt
# =============================================================================

threat_hunt_user_message = build_threat_hunt_prompt(
    user_prompt=user_message["content"],
    table_name=table,
    log_data=law_query_results,
)

print(f"{Fore.LIGHTGREEN_EX}Initiating AI cognitive threat hunt...\n")

start_time = time.time()

hunt_results = hunt_protocol.hunt(
    openai_client=openai_client,
    threat_hunt_system_message=SYSTEM_PROMPT_THREAT_HUNT,
    threat_hunt_user_message=threat_hunt_user_message,
    openai_model=models.GPT_4_1,
)

elapsed = time.time() - start_time

print(
    f"{Fore.WHITE}Threat hunt complete in {elapsed:.2f}s "
    f"with {Fore.LIGHTRED_EX}{len(hunt_results)}{Fore.WHITE} findings."
)

# =============================================================================
# FULL SUMMARY CONSTRUCTION
# =============================================================================

summary = {
    "metadata": {
        "timestamp_utc": TIMESTAMP,
        "log_table": table,
        "time_range_hours": time_range,
        "device": device or None,
        "caller": caller or None,
        "total_findings": len(hunt_results),
    },
    "findings": [],
    "kql_to_mitre_mapping": [],
}

txt_lines = [
    "AI THREAT HUNT – FULL SUMMARY",
    "=" * 60,
    f"Report Date (UTC): {DATE_ONLY}",
    f"Log Table: {table}",
    f"Time Range: {time_range} hours",
    f"Device: {device or 'Not specified'}",
    f"Total Findings: {len(hunt_results)}",
    "",
]

# =============================================================================
# Enrich Findings
# =============================================================================

for finding in hunt_results:
    kql_name = finding.get("kql_name") or finding.get("detection", "Unknown KQL")
    mapping = KQL_ATTACK_MAPPING.get(kql_name, {})

    enriched = {
        **finding,
        "kql_block": kql_name,
        "mitre_tactic": mapping.get("tactic", "Unknown"),
        "mitre_techniques": mapping.get("techniques", []),
    }

    summary["findings"].append(enriched)

    txt_lines.extend([
        "-" * 60,
        f"KQL Block: {kql_name}",
        f"MITRE Tactic: {enriched['mitre_tactic']}",
        f"ATT&CK Techniques: {', '.join(enriched['mitre_techniques']) or 'Unknown'}",
        f"Severity: {finding.get('severity', 'Unknown')}",
        f"Description: {finding.get('description', '')}",
        "",
    ])

# =============================================================================
# KQL → MITRE MATRIX
# =============================================================================

txt_lines.extend([
    "",
    "KQL → MITRE ATT&CK MATRIX",
    "-" * 60,
])

for kql, data in KQL_ATTACK_MAPPING.items():
    summary["kql_to_mitre_mapping"].append({
        "kql_block": kql,
        "tactic": data["tactic"],
        "techniques": data["techniques"],
    })

    txt_lines.extend([
        f"{kql}",
        f"  Tactic: {data['tactic']}",
        f"  Techniques: {', '.join(data['techniques'])}",
        "",
    ])

# =============================================================================
# Write Reports
# =============================================================================

with open(JSON_REPORT_PATH, "w", encoding="utf-8") as jf:
    json.dump(summary, jf, indent=2)

with open(TXT_REPORT_PATH, "w", encoding="utf-8") as tf:
    tf.write("\n".join(txt_lines))

print(f"{Fore.LIGHTGREEN_EX}Reports saved to /summary/")
print(f"  JSON → {JSON_REPORT_PATH}")
print(f"  TXT  → {TXT_REPORT_PATH}")

# =============================================================================
# Display Results
# =============================================================================

print(f"\nPress [Enter] to view findings.")
input()

utilities.display_threats(threat_list=hunt_results)

print("\nfin.")
