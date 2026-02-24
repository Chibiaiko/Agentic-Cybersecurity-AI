# 🛡 nest/incident.py
# ---------------------------------------------------------
# SentinelHawk — Enterprise-grade Incident Object
# ---------------------------------------------------------

import uuid
from datetime import datetime

class Incident:
    """
    Standardized Incident object for SentinelHawk.
    Tracks the lifecycle of an event from detection to resolution.
    """
    def __init__(self, event, risk_score, confidence, reason, mitre=None, status="OPEN"):
        self.id = str(uuid.uuid4())
        self.timestamp = datetime.utcnow().isoformat()
        
        # Event Details
        self.event = event
        
        # Risk Analysis
        self.risk = risk_score
        self.confidence = confidence
        self.reason = reason
        self.mitre = mitre or []
        
        # Response State
        self.recommended_action = None
        self.decision = {}
        self.execution_result = {}
        self.requires_human = False
        
        # Metadata
        self.summary = None
        self.status = status  # OPEN, PENDING_APPROVAL, EXECUTED, CLOSED
        self.history = []

        # Initialize history
        self.add_history(f"Incident created. Risk: {risk_score}, Reason: {reason}")

    def set_recommendation(self, action_plan):
        """Sets the recommended action plan."""
        self.recommended_action = action_plan.get("action")
        self.requires_human = action_plan.get("requires_approval", False)
        self.decision = action_plan
        self.add_history(f"Recommendation set: {self.recommended_action} (Human Required: {self.requires_human})")

    def execute_decision(self, execution_result):
        """Updates incident with execution results."""
        self.execution_result = execution_result
        self.status = execution_result.get("status", "EXECUTED")
        self.add_history(f"Action executed. Output: {execution_result}")

    def add_history(self, note, user=None):
        """Adds an entry to the audit log."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "note": note,
            "user": user or "system"
        }
        self.history.append(entry)

    def to_dict(self):
        """Serializes the incident to a dictionary."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "event": self.event,
            "risk": self.risk,
            "confidence": self.confidence,
            "reason": self.reason,
            "mitre": self.mitre,
            "recommended_action": self.recommended_action,
            "decision": self.decision,
            "execution_result": self.execution_result,
            "summary": self.summary,
            "status": self.status,
            "history": self.history
        }
    
    # Alias for compatibility if needed, though to_dict is preferred
    def as_dict(self):
        return self.to_dict()
