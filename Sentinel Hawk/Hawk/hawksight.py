# 🦅 hawksight.py
# ---------------------------------------------------------
# SentinelHawk — Detection + Risk Scoring Engine
# Responsible for:
#   - Suspicious activity detection (rule-based)
#   - Risk scoring (TalonScore)
#   - Creating Incident objects
# ---------------------------------------------------------

from nest.talonscore import TalonScore
from nest.incident import Incident


class Hawksight:

    def __init__(self):
        self.scorer = TalonScore()

    def analyze(self, normalized_analysis_data):
        """
        Analyze fully enriched/normalized analysis data (output from Skywatch).
        Returns an Incident object if risk is high enough or suspicious.
        """
        
        # Note: In the user prompt's flow, Skywatch already did scoring.
        # But Hawksight is described as "Detection + Risk Scoring".
        # We will adapt: Hawksight takes the output of Skywatch (which already contains scores)
        # and wraps it into an Incident, potentially adding a second layer of detection.

        scored_event = normalized_analysis_data # This is the dict from Skywatch.collect() -> results
        event = scored_event["event"]
        
        suspicious, reason = self._detect_suspicious(event)

        # If it's not explicitly suspicious by rules, check if the score is high anyway
        if not suspicious and scored_event["risk"] < 40:
             return None # Skip low risk non-suspicious events

        if not suspicious:
            reason = f"High Risk Score: {scored_event['risk']}"

        incident = Incident(
            event=event,
            risk_score=scored_event["risk"],
            confidence=scored_event["confidence"],
            reason=reason,
            mitre=scored_event.get("mitre", [])
        )
        
        return incident

    # -----------------------------------------------------
    # RULE-BASED SUSPICIOUS ACTIVITY DETECTION
    # (Can later evolve into adaptive AI model)
    # -----------------------------------------------------

    def _detect_suspicious(self, event):
        """
        Simple rule-based suspicious activity detection.
        """

        # Failed login spike (Event ID 4625)
        if event.get("event_id") == 4625:
            # In a real engine, we'd check global state for count. 
            # Here we assume the event_id itself is a flag for check.
            return True, "Failed login attempt detected"

        # Privilege escalation
        if event.get("event_name") == "SemanticsChanged": # Example
            return True, "Potential Privilege change"

        # Disabled security tool
        if event.get("event_id") == 5001: # Example
            return True, "Security tool disabled"

        # Suspicious PowerShell execution
        if "powershell" in str(event.get("raw")).lower():
            if "EncodedCommand" in str(event.get("raw")):
                return True, "Encoded PowerShell execution"
            return True, "PowerShell execution detected"
            
        return False, None
