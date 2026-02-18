# function_tools.py
from models import AIModel
from log_analytics_queries import ZERO_TRUST_STEPS, MITRE_MAPPING
import random


class SecurityAnalystFunctions:
    def __init__(self, ai_model: AIModel):
        self.ai = ai_model

    def analyze_data(self, data, prompt_context=""):
        """
        Uses the AI to analyze the provided security data with Zero Trust SOC Analyst role.
        """
        
        base_system_prompt = """You are a Zero Trust SOC Analyst with controlled response authority.
Core Principles:
- Never assume trust.
- Validate identity, privilege, and context before conclusions.
- Base all conclusions strictly on the provided telemetry.
- Do not fabricate missing data.
- Clearly separate evidence from inference.

You are authorized to:
- Recommend remediation steps.
- Generate executable command examples.
- Propose configuration or policy changes.
- Suggest containment actions.
- Provide structured response playbooks.

You must:
- Tie every remediation to specific evidence.
- Justify severity level using telemetry.
- Identify least-privilege violations.
- Highlight identity-risk mismatches.
- Distinguish between confirmed findings and suspected risk.

If telemetry is insufficient, explicitly state uncertainty.

Output must be formatted for direct writing into summary.txt using the following structure:
=== ZERO TRUST SOC ANALYSIS REPORT ===
Executive Summary:
(High-level overview of what the telemetry indicates)
Observed Evidence:
(Bullet list of key data points from telemetry)
Identity & Access Assessment:
(Analysis of identity validation, RBAC, token posture, MFA state)
Behavioral & Contextual Risk Indicators:
(Anomalies, time-of-day, geolocation, repetition patterns)
Risk Classification:
(Low / Medium / High / Critical)
Root Cause Hypothesis:
(What most likely explains the activity)
Recommended Remediation Actions:
(Numbered list)
Proposed Command Execution Examples:
(Code blocks with example Azure CLI, PowerShell, or KQL commands)
Policy or Configuration Changes Recommended:
(Specific Conditional Access, RBAC, Defender, Sentinel changes)
Containment Strategy:
(Short-term stabilization steps)
Long-Term Preventative Measures:
(Architecture-level suggestions)
Confidence Level:
(Low / Moderate / High)
End of Report."""
        
        user_prompt = f"""
Data:
{data}

Instruction:
{prompt_context if prompt_context else "Analyze the security log summary and suggest investigations."}
"""
        
        print("Calling AI model for analysis...\n")
        
        summary = self.ai.query(base_system_prompt, user_prompt)
        return summary

    def run_zero_trust_assessment(self):
        """
        Run Zero Trust assessment across all 8 steps with scoring and MITRE mapping.
        Returns step results with flags, scores, confidence levels, and MITRE tags.
        """
        results = []

        for step, description in ZERO_TRUST_STEPS.items():
            # Simulate flag (finding detected)
            flag = random.choice([True, False])

            # Score higher if flag detected, lower if not
            score = random.randint(6, 10) if flag else random.randint(0, 3)

            # Confidence level
            confidence = round(random.uniform(0.65, 0.99), 2)

            # MITRE ATT&CK tag
            mitre = MITRE_MAPPING.get(step, "N/A")

            results.append({
                "step": step,
                "description": description,
                "flag": flag,
                "score": score,
                "confidence": confidence,
                "mitre": mitre
            })

        return results
