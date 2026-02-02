"""
MITRE ATT&CK Coverage Module

Provides MITRE ATT&CK framework coverage definitions, technique mappings,
and analysis utilities for threat hunting operations.
"""

from typing import Dict, List, Tuple
from colorama import Fore

# =============================================================================
# MITRE ATT&CK FRAMEWORK COVERAGE
# =============================================================================

MITRE_FRAMEWORK_COVERAGE: Dict[str, Dict] = {
    "Initial Access": {
        "support": "partial",
        "capability": "Suspicious logon patterns",
        "tables": ["DeviceLogonEvents"],
        "active": False,
        "description": "Detection of initial access vectors",
        "confidence": "medium",
    },
    "Execution": {
        "support": "full",
        "capability": "Process creation and command-line analysis",
        "tables": ["DeviceProcessEvents"],
        "active": False,
        "description": "Execution of malicious payloads",
        "confidence": "high",
    },
    "Persistence": {
        "support": "partial",
        "capability": "Registry changes and scheduled tasks",
        "tables": ["DeviceRegistryEvents", "DeviceProcessEvents"],
        "active": False,
        "description": "Maintaining long-term access",
        "confidence": "medium",
    },
    "Privilege Escalation": {
        "support": "partial",
        "capability": "Elevation and token abuse",
        "tables": ["DeviceProcessEvents", "DeviceLogonEvents"],
        "active": False,
        "description": "Privilege escalation attempts",
        "confidence": "medium",
    },
    "Defense Evasion": {
        "support": "partial",
        "capability": "Evasion and telemetry suppression",
        "tables": ["DeviceProcessEvents", "DeviceFileEvents"],
        "active": False,
        "description": "Avoidance of security controls",
        "confidence": "low",
    },
    "Credential Access": {
        "support": "full",
        "capability": "Credential harvesting detection",
        "tables": ["DeviceLogonEvents"],
        "active": False,
        "description": "Credential theft techniques",
        "confidence": "high",
    },
    "Discovery": {
        "support": "partial",
        "capability": "System and identity enumeration",
        "tables": ["DeviceProcessEvents", "DeviceNetworkEvents", "DeviceInfo"],
        "active": False,
        "description": "Environment reconnaissance",
        "confidence": "medium",
    },
    "Lateral Movement": {
        "support": "partial",
        "capability": "Remote access relationships",
        "tables": ["DeviceLogonEvents", "DeviceNetworkEvents"],
        "active": False,
        "description": "Movement across hosts",
        "confidence": "medium",
    },
    "Collection": {
        "support": "partial",
        "capability": "File access patterns",
        "tables": ["DeviceFileEvents"],
        "active": False,
        "description": "Data collection activities",
        "confidence": "low",
    },
    "Command and Control": {
        "support": "partial",
        "capability": "C2 communications",
        "tables": ["DeviceNetworkEvents"],
        "active": False,
        "description": "Command-and-control channels",
        "confidence": "medium",
    },
    "Exfiltration": {
        "support": "partial",
        "capability": "Outbound data transfer analysis",
        "tables": ["DeviceNetworkEvents"],
        "active": False,
        "description": "Data exfiltration attempts",
        "confidence": "low",
    },
    "Impact": {
        "support": "partial",
        "capability": "Destructive behaviors",
        "tables": ["DeviceFileEvents", "DeviceProcessEvents"],
        "active": False,
        "description": "Operational impact activities",
        "confidence": "medium",
    },
}

# =============================================================================
# MITRE TECHNIQUE DATABASE
# =============================================================================

MITRE_TECHNIQUES: Dict[str, Dict] = {
    "T1078": {"name": "Valid Accounts", "tactic": "Initial Access"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1087": {"name": "Account Discovery", "tactic": "Discovery"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1005": {"name": "Data from Local System", "tactic": "Collection"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
}

# =============================================================================
# TABLE → TECHNIQUE MAPPING
# =============================================================================

TABLE_TECHNIQUE_MAPPING: Dict[str, List[str]] = {
    "DeviceLogonEvents": ["T1078", "T1110", "T1021"],
    "DeviceProcessEvents": ["T1059", "T1059.001", "T1053", "T1003", "T1068"],
    "DeviceNetworkEvents": ["T1071", "T1041"],
    "DeviceFileEvents": ["T1005", "T1486"],
    "DeviceRegistryEvents": ["T1053"],
    "DeviceInfo": ["T1087"],
}

# =============================================================================
# ANALYSIS FUNCTIONS
# =============================================================================

def get_supported_techniques(table_name: str) -> List[str]:
    return TABLE_TECHNIQUE_MAPPING.get(table_name, [])


def get_technique_info(technique_id: str) -> Dict:
    return MITRE_TECHNIQUES.get(
        technique_id,
        {"name": "Unknown", "tactic": "Unknown"},
    )


def calculate_coverage_score(tables_used: List[str]) -> Dict[str, float]:
    scores = {}
    used = set(tables_used)

    for tactic, details in MITRE_FRAMEWORK_COVERAGE.items():
        required = set(details["tables"])
        scores[tactic] = (
            len(required & used) / len(required) if required else 0.0
        )

    return scores


def map_finding_to_tactic(finding: Dict) -> Tuple[str, str]:
    mitre = finding.get("mitre", {})
    tactic = mitre.get("tactic", "Unknown")
    technique = mitre.get("id", "Unknown").split(",")[0]
    return tactic, technique


def generate_coverage_matrix(hunt_results: List[Dict], tables_used: List[str]) -> Dict:
    coverage = calculate_coverage_score(tables_used)
    detected = {}

    for finding in hunt_results:
        tactic, technique = map_finding_to_tactic(finding)
        if tactic != "Unknown":
            detected.setdefault(tactic, set()).add(technique)

    return {
        "coverage_scores": coverage,
        "detected_techniques": {k: list(v) for k, v in detected.items()},
        "coverage_percentage": sum(coverage.values()) / len(coverage) * 100,
    }


def display_coverage_matrix(matrix: Dict):
    print(f"\n{Fore.LIGHTCYAN_EX}MITRE ATT&CK Coverage\n{'='*60}")

    for tactic, score in sorted(matrix["coverage_scores"].items(), key=lambda x: x[1], reverse=True):
        bar = "█" * int(score * 30)
        print(f"{tactic:<25} {bar:<30} {score*100:.0f}%")

    print(f"\nOverall Coverage: {matrix['coverage_percentage']:.1f}%")

