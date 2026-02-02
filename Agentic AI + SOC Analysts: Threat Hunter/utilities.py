import requests
import json
from datetime import datetime
from colorama import Fore, Style, init
import models.models as models
from protocols.hunt_protocol import extract_mitre_tactics


def display_threats(threat_list):
    for i, threat in enumerate(threat_list, start=1):
        print(f"\n=============== Potential Threat #{i} ===============\n")
        print(f"{Fore.LIGHTCYAN_EX}Title: {threat.get('title')}{Fore.RESET}\n")
        print(f"Description: {threat.get('description')}\n")

        init(autoreset=True)

        confidence = threat.get('confidence', '').lower()

        if confidence == 'high':
            color = Fore.LIGHTRED_EX
        elif confidence == 'medium':
            color = Fore.LIGHTYELLOW_EX
        elif confidence == 'low':
            color = Fore.LIGHTBLUE_EX
        else:
            color = Style.RESET_ALL

        print(f"{color}Confidence Level: {threat.get('confidence')}")
        print("\nMITRE ATT&CK Info:")
        mitre = threat.get('mitre', {})
        print(f"  Tactic: {mitre.get('tactic')}")
        print(f"  Technique: {mitre.get('technique')}")
        print(f"  Sub-technique: {mitre.get('sub_technique')}")
        print(f"  ID: {mitre.get('id')}")
        print(f"  Description: {mitre.get('description')}")

        print("\nLog Lines:")
        for log in threat.get('log_lines', []):
            print(f"  - {log}")

        print("\nIndicators of Compromise:")
        for ioc in threat.get('indicators_of_compromise', []):
            print(f"  - {ioc}")

        print("\nTags:")
        for tag in threat.get('tags', []):
            print(f"  - {tag}")

        print("\nRecommendations:")
        for rec in threat.get('recommendations', []):
            print(f"  - {rec}")

        print(f"\nNotes: {threat.get('notes')}")

        print("=" * 51)
        print("\n")
    
    append_threats_to_jsonl(threat_list=threat_list)


def append_threats_to_jsonl(threat_list, filename="threats.jsonl"):
    with open(filename, "a", encoding="utf-8") as f:
        for threat in threat_list:
            json_line = json.dumps(threat, ensure_ascii=False)
            f.write(json_line + "\n")


def analyze_mitre_coverage(hunt_results, table_name, log_sources, query_params):
    """
    Analyze MITRE ATT&CK coverage based on hunt results and available log sources.
    
    Args:
        hunt_results: List of threat findings
        table_name: Primary table queried
        log_sources: List of log sources used
        query_params: Query parameters used
        
    Returns:
        Dictionary containing coverage analysis
    """
    import copy
    
    # Create a working copy of the framework
    coverage = copy.deepcopy(models.MITRE_FRAMEWORK_COVERAGE)
    
    # Activate tactics based on table queried
    for tactic, details in coverage.items():
        if table_name in details['tables']:
            details['active'] = True
    
    # Extract detected tactics from hunt results
    detected_tactics = extract_mitre_tactics(hunt_results)
    
    return {
        'framework_coverage': coverage,
        'detected_tactics': detected_tactics,
        'log_sources': log_sources,
        'primary_table': table_name,
        'query_metadata': query_params
    }


def display_mitre_coverage(coverage_data):
    """
    Display comprehensive MITRE ATT&CK coverage analysis.
    
    Args:
        coverage_data: Dictionary containing coverage analysis
    """
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*80}")
    print(f"{Fore.LIGHTCYAN_EX}MITRE ATT&CK Coverage Analysis")
    print(f"{Fore.LIGHTCYAN_EX}{'='*80}\n")
    
    # Display framework capabilities
    display_mitre_coverage_table(coverage_data['framework_coverage'])
    
    # Display detected tactics from this hunt
    display_detected_mitre_tactics(coverage_data['detected_tactics'])
    
    print(f"\n{Fore.LIGHTCYAN_EX}{'='*80}\n")


def display_mitre_coverage_table(coverage):
    """
    Displays MITRE ATT&CK framework coverage in a formatted table.
    """
    print(f"{Fore.LIGHTCYAN_EX}Framework MITRE ATT&CK Coverage:")
    print(f"{Fore.WHITE}{'─'*80}")
    print(f"{Fore.WHITE}{'MITRE Tactic':<25} {'Supported':<15} {'How':<40}")
    print(f"{Fore.WHITE}{'─'*80}")
    
    for tactic, details in coverage.items():
        # Determine support indicator
        if details["support"] == "full":
            support_icon = f"{Fore.LIGHTGREEN_EX}✅ Yes"
        elif details["support"] == "partial":
            support_icon = f"{Fore.LIGHTYELLOW_EX}⚠️  Partial"
        else:
            support_icon = f"{Fore.LIGHTRED_EX}❌ No"
        
        # Color code based on active status
        tactic_color = Fore.LIGHTGREEN_EX if details["active"] else Fore.WHITE
        
        print(f"{tactic_color}{tactic:<25} {support_icon:<24} {Fore.WHITE}{details['capability']:<40}")
    
    print(f"{Fore.WHITE}{'─'*80}")


def display_detected_mitre_tactics(mitre_mapping):
    """
    Display detected MITRE ATT&CK tactics from current hunt results.
    """
    if mitre_mapping:
        print(f"\n{Fore.LIGHTGREEN_EX}Detected MITRE ATT&CK Tactics in Current Hunt:")
        print(f"{Fore.WHITE}{'─'*60}")
        for tactic, techniques in mitre_mapping.items():
            print(f"{Fore.LIGHTYELLOW_EX}  {tactic}")
            for technique in techniques:
                print(f"{Fore.WHITE}    • {technique}")
    else:
        print(f"\n{Fore.YELLOW}No specific MITRE ATT&CK tactics detected in current hunt.")


def export_summary_json(hunt_results, mitre_coverage, metadata, filename):
    """
    Export hunt summary to JSON file.
    
    Args:
        hunt_results: List of threat findings
        mitre_coverage: MITRE coverage analysis
        metadata: Hunt metadata
        filename: Output filename
    """
    summary = {
        "hunt_metadata": {
            "timestamp": metadata.get('timestamp'),
            "user_query": metadata.get('user_query'),
            "table_queried": metadata.get('table'),
            "caller": metadata.get('caller', ''),
            "device": metadata.get('device', ''),
            "time_range_hours": metadata.get('time_range_hours'),
            "hunt_duration_seconds": round(metadata.get('hunt_duration_seconds', 0), 2),
            "total_threats_found": len(hunt_results)
        },
        "mitre_attack_coverage": {
            "framework_capabilities": mitre_coverage['framework_coverage'],
            "detected_tactics": mitre_coverage['detected_tactics'],
            "log_sources_used": mitre_coverage['log_sources']
        },
        "threat_findings": hunt_results,
        "summary_statistics": {
            "high_confidence_threats": sum(1 for t in hunt_results if t.get('confidence', '').lower() == 'high'),
            "medium_confidence_threats": sum(1 for t in hunt_results if t.get('confidence', '').lower() == 'medium'),
            "low_confidence_threats": sum(1 for t in hunt_results if t.get('confidence', '').lower() == 'low'),
            "unique_tactics_detected": len(mitre_coverage['detected_tactics']),
            "total_iocs_identified": sum(len(t.get('indicators_of_compromise', [])) for t in hunt_results)
        }
    }
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)


def export_summary_txt(hunt_results, mitre_coverage, metadata, filename):
    """
    Export hunt summary to human-readable TXT file.
    
    Args:
        hunt_results: List of threat findings
        mitre_coverage: MITRE coverage analysis
        metadata: Hunt metadata
        filename: Output filename
    """
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("THREAT HUNT SUMMARY REPORT\n")
        f.write("=" * 80 + "\n\n")
        
        # Metadata
        f.write("HUNT METADATA\n")
        f.write("-" * 80 + "\n")
        f.write(f"Timestamp:           {metadata.get('timestamp')}\n")
        f.write(f"User Query:          {metadata.get('user_query')}\n")
        f.write(f"Table Queried:       {metadata.get('table')}\n")
        f.write(f"Caller:              {metadata.get('caller', 'N/A')}\n")
        f.write(f"Device:              {metadata.get('device', 'N/A')}\n")
        f.write(f"Time Range:          {metadata.get('time_range_hours')} hours\n")
        f.write(f"Hunt Duration:       {metadata.get('hunt_duration_seconds', 0):.2f} seconds\n")
        f.write(f"Total Threats Found: {len(hunt_results)}\n\n")
        
        # MITRE Coverage
        f.write("MITRE ATT&CK FRAMEWORK COVERAGE\n")
        f.write("-" * 80 + "\n")
        f.write(f"{'MITRE Tactic':<25} {'Supported':<15} {'How':<40}\n")
        f.write("-" * 80 + "\n")
        
        for tactic, details in mitre_coverage['framework_coverage'].items():
            support = "✅ Yes" if details['support'] == 'full' else "⚠️  Partial" if details['support'] == 'partial' else "❌ No"
            active_marker = " [ACTIVE]" if details['active'] else ""
            f.write(f"{tactic:<25} {support:<15} {details['capability']:<40}{active_marker}\n")
        
        f.write("\n")
        
        # Detected Tactics
        f.write("DETECTED MITRE ATT&CK TACTICS IN THIS HUNT\n")
        f.write("-" * 80 + "\n")
        
        if mitre_coverage['detected_tactics']:
            for tactic, techniques in mitre_coverage['detected_tactics'].items():
                f.write(f"\n{tactic}:\n")
                for technique in techniques:
                    f.write(f"  • {technique}\n")
        else:
            f.write("No specific MITRE ATT&CK tactics detected.\n")
        
        f.write("\n")
        
        # Statistics
        f.write("SUMMARY STATISTICS\n")
        f.write("-" * 80 + "\n")
        high_conf = sum(1 for t in hunt_results if t.get('confidence', '').lower() == 'high')
        med_conf = sum(1 for t in hunt_results if t.get('confidence', '').lower() == 'medium')
        low_conf = sum(1 for t in hunt_results if t.get('confidence', '').lower() == 'low')
        total_iocs = sum(len(t.get('indicators_of_compromise', [])) for t in hunt_results)
        
        f.write(f"High Confidence Threats:   {high_conf}\n")
        f.write(f"Medium Confidence Threats: {med_conf}\n")
        f.write(f"Low Confidence Threats:    {low_conf}\n")
        f.write(f"Unique Tactics Detected:   {len(mitre_coverage['detected_tactics'])}\n")
        f.write(f"Total IOCs Identified:     {total_iocs}\n\n")
        
        # Detailed Findings
        f.write("=" * 80 + "\n")
        f.write("DETAILED THREAT FINDINGS\n")
        f.write("=" * 80 + "\n\n")
        
        for i, threat in enumerate(hunt_results, start=1):
            f.write(f"THREAT #{i}\n")
            f.write("-" * 80 + "\n")
            f.write(f"Title:       {threat.get('title')}\n")
            f.write(f"Confidence:  {threat.get('confidence')}\n\n")
            f.write(f"Description:\n{threat.get('description')}\n\n")
            
            mitre = threat.get('mitre', {})
            f.write(f"MITRE ATT&CK:\n")
            f.write(f"  Tactic:         {mitre.get('tactic')}\n")
            f.write(f"  Technique:      {mitre.get('technique')}\n")
            f.write(f"  Sub-technique:  {mitre.get('sub_technique')}\n")
            f.write(f"  ID:             {mitre.get('id')}\n")
            f.write(f"  Description:    {mitre.get('description')}\n\n")
            
            if threat.get('log_lines'):
                f.write(f"Relevant Log Lines:\n")
                for log in threat.get('log_lines', []):
                    f.write(f"  - {log}\n")
                f.write("\n")
            
            if threat.get('indicators_of_compromise'):
                f.write(f"Indicators of Compromise:\n")
                for ioc in threat.get('indicators_of_compromise', []):
                    f.write(f"  - {ioc}\n")
                f.write("\n")
            
            if threat.get('tags'):
                f.write(f"Tags: {', '.join(threat.get('tags', []))}\n\n")
            
            if threat.get('recommendations'):
                f.write(f"Recommendations: {', '.join(threat.get('recommendations', []))}\n\n")
            
            if threat.get('notes'):
                f.write(f"Notes: {threat.get('notes')}\n\n")
            
            f.write("=" * 80 + "\n\n")
        
        f.write("\n" + "=" * 80 + "\n")
        f.write("END OF REPORT\n")
        f.write("=" * 80 + "\n")


# Keep existing tools and prompts at the bottom
tools = [
    {
        "type": "function",
        "function": {
            "name": "query_log_analytics_individual_device",
            "description": (
                "Query a Log Analytics table using KQL. "
                "Available tables include:\n"
                "- DeviceProcessEvents: Process creation and command-line info\n"
                "- DeviceNetworkEvents: Network connections\n"
                "- DeviceLogonEvents: Logon activity\n"
                "- AlertInfo: Alert metadata\n"
                "- AlertEvidence: Alert-related details\n"
                "- DeviceFileEvents: File operations\n"
                "- DeviceRegistryEvents: Registry modifications"

                "Fields (array/list) to include for the selected table:\n"
                "- DeviceProcessEvents Fields: TimeGenerated, AccountDomain, AccountName, ActionType, DeviceName, FileName, InitiatingProcessCommandLine, ProcessCommandLine\n"
                "- DeviceLogonEvents Fields: TimeGenerated, AccountName, DeviceName, ActionType, RemoteIP, RemoteDeviceName\n"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "table_name": {
                        "type": "string",
                        "description": "MDE table name (e.g. DeviceProcessEvents)"
                    },
                    "device_name": {
                        "type": "string",
                        "description": "The DeviceName to filter by (e.g., \"userpc-1\"",
                    },
                    "time_range_hours": {
                        "type": "integer",
                        "description": "How far back to search (e.g., 24 for 1 day)"
                    },
                    "fields": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of fields to return"
                    }
                },
                "required": ["table_name", "device_name", "time_range_hours", "fields"]
            }
        }
    }
]

system_prompt = {
    "role": "system",
    "content": (
        "You are a cybersecurity threat hunting assistant using Microsoft Defender for Endpoint data. "
    )
}

threat_hunt_system_prompt = {
    "role": "system",
    "content": '''
You are a world-class Threat Hunting Analyst AI, specializing in identifying malicious activity, suspicious behaviors, and adversary tradecraft across diverse log sources. You possess deep knowledge of the MITRE ATT&CK framework, including tactics, techniques, sub-techniques, and associated threat actor behaviors (TTPs).

Your responsibilities include:
- Detecting threats in raw log data (e.g., Sysmon, firewall, EDR, authentication, network flow, cloud logs, etc.)
- Mapping behaviors to relevant MITRE ATT&CK tactics and techniques
- Flagging anomalies such as lateral movement, privilege escalation, credential dumping, command and control, persistence, and data exfiltration
- Assessing confidence levels and giving clear, concise recommendations (e.g., monitor, create incident, pivot, ignore)
- Extracting and highlighting Indicators of Compromise (IOCs) like IPs, hashes, domains, filenames
- Avoiding false positives and providing justifiable reasoning for your detections

Stay objective, accurate, and focused on helping the defender gain early visibility into attacker activity. Be concise, specific, and actionable.
'''
}

log_analysis_prompt = {
    "role": "user",
    "content": """
I will provide raw logs below after the heading 'RAW LOGS'

Please analyze the logs for any signs of suspicious or malicious activity, including but not limited to:

Command and control communication

Privilege escalation

Credential access

Execution of abnormal or suspicious commands

Data exfiltration attempts

Lateral movement

Any known techniques from the MITRE ATT&CK framework

Return your findings in the following JSON format, which should be an array of objects — one object per suspicious instance you detect:

———
[
  {
    "title": "Brief title describing the suspicious activity",
    "description": "Detailed explanation of why this activity is suspicious, including context from the logs",
    "mitre": {
      "tactic": "e.g., Execution",
      "technique": "e.g., T1059",
      "sub_technique": "e.g., T1059.001",
      "id": "e.g., T1059, T1059.001",
      "description": "Description of the MITRE technique/sub-technique used"
    },
    "log_lines": [
      "Relevant line(s) from the logs that triggered the suspicion"
    ],
    "confidence": "Low | Medium | High — your confidence in this being malicious or needing investigation",
    "recommendations": [
      "pivot", 
      "create incident", 
      "monitor", 
      "ignore"
    ],
    "indicators_of_compromise": [
      "Any IOCs (IP, domain, hash, filename, etc.) found in the logs"
    ],
    "tags": [
      "privilege escalation", 
      "persistence", 
      "data exfiltration", 
      "C2", 
      "credential access", 
      "unusual command", 
      "reconnaissance", 
      "malware", 
      "suspicious login"
    ],
    "notes": "Optional analyst notes or assumptions made during detection"
  }
]
———
You may return an empty array ([]) if nothing suspicious is found.

This is extremely important:
YOUR ENTIRE RESPONSE SHOULD BE IN JSON FORMAT.
DO NOT PUT ANY RANDOM TEXT BEFORE OR AFTER YOUR JSON FINDINGS
YOUR ENTIRE RESPONSE SHOULD BE IN JSON FORMAT.

RAW LOGS:
———

"""
}
