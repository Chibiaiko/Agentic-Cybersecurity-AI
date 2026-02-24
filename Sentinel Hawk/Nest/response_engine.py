# 🦅 nest/response_engine.py
# ---------------------------------------------------------
# SentinelHawk — Response Engine with Containment & Color Coding
# ---------------------------------------------------------

from nest.talonscore import TalonScore
from nest.confidence_engine import ConfidenceEngine
from models import Colors

class ResponseEngine:

    def __init__(self):
        self.executed_actions = []
        self.talon_score = TalonScore()
        self.confidence_engine = ConfidenceEngine()

    @staticmethod
    def get_action_color(risk_score):
        """
        Map action severity to colors based on risk score.
        
        Returns dict with action type, color, and urgency info
        """
        if risk_score >= 80:
            return {
                "hex": "#FF0000",           # Red
                "rgb": "255, 0, 0",
                "urgency": "CRITICAL",
                "description": "Immediate action required"
            }
        elif risk_score >= 60:
            return {
                "hex": "#FF5E0E",           # Orange-Red
                "rgb": "255, 94, 14",
                "urgency": "HIGH",
                "description": "Urgent action required"
            }
        elif risk_score >= 40:
            return {
                "hex": "#FFD700",           # Gold
                "rgb": "255, 215, 0",
                "urgency": "MEDIUM",
                "description": "Monitor and review"
            }
        else:
            return {
                "hex": "#016E01",           # Green
                "rgb": "46, 255, 46",
                "urgency": "LOW",
                "description": "Informational only"
            }

    def recommend_action(self, scoring):
        """
        Derives an action plan based on risk score with color information.
        """
        risk = scoring["risk"]
        event = scoring["event"]
        
        # Get color information
        action_color = self.get_action_color(risk)
        severity = scoring.get("severity", "MEDIUM")
        risk_color = scoring.get("risk_color", {})
        confidence_color = scoring.get("confidence_color", {})

        if risk >= 80:
            reason = f"Risk score >= 80 ({Colors.bold_colored('CRITICAL', Colors.RED)})"
            return {
                "action": "isolate_host",
                "target": event.get("host"),
                "requires_approval": True,
                "reason": reason,
                "severity": severity,
                "action_color": action_color,
                "risk_color": risk_color,
                "confidence_color": confidence_color
            }

        if risk >= 60:
            reason = f"Risk score >= 60 ({Colors.bold_colored('HIGH', Colors.ORANGE)})"
            return {
                "action": "disable_user",
                "target": event.get("user"),
                "requires_approval": True,
                "reason": reason,
                "severity": severity,
                "action_color": action_color,
                "risk_color": risk_color,
                "confidence_color": confidence_color
            }

        if risk >= 40:
            reason = f"Risk score >= 40 ({Colors.bold_colored('MEDIUM', Colors.YELLOW)})"
            return {
                "action": "monitor",
                "target": None,
                "requires_approval": False,
                "reason": reason,
                "severity": severity,
                "action_color": action_color,
                "risk_color": risk_color,
                "confidence_color": confidence_color
            }

        reason = f"Risk score < 40 ({Colors.bold_colored('LOW', Colors.GREEN)})"
        return {
            "action": "log_only",
            "target": None,
            "requires_approval": False,
            "reason": reason,
            "severity": severity,
            "action_color": action_color,
            "risk_color": risk_color,
            "confidence_color": confidence_color
        }

    def execute(self, action_dict, approved=False):
        """
        Executes containment actions with color-coded status.
        Human approval is required for high-risk actions.
        """
        
        # Get color for this action
        action_color = action_dict.get("action_color", {})
        
        # If approval is required and NOT granted, return pending status
        if action_dict.get("requires_approval") and not approved:
            return {
                "status": "PENDING_APPROVAL",
                "status_color": "#FF9500",  # Orange for pending
                "action": action_dict.get("action"),
                "detail": "Action blocked awaiting human approval.",
                "action_color": action_color,
                "severity": action_dict.get("severity", "MEDIUM")
            }

        result = {
            "status": "EXECUTED",
            "status_color": action_color.get("hex", "#FFD700"),
            "action": action_dict.get("action"),
            "action_color": action_color,
            "severity": action_dict.get("severity", "MEDIUM")
        }

        # Simulation of active defense actions
        if action_dict.get("action") == "isolate_host":
            host = action_dict.get("target")
            result["detail"] = f"Simulated isolation of host {host} via Defender API"
        elif action_dict.get("action") == "disable_user":
            user = action_dict.get("target")
            result["detail"] = f"Simulated disabling of user account {user} via AD"
        else:
            result["detail"] = "No active containment required. Logging event."

        self.executed_actions.append(result)
        return result
    
    # Helper for simple decision logic (backward compatibility)
    def decide(self, risk, confidence):
        """
        Simply maps to the logic in recommend_action but returns a simplified dict with colors.
        """
        action_color = self.get_action_color(risk)
        
        if risk >= 80:
            return {
                "action": "isolate_host",
                "requires_human": True,
                "action_color": action_color
            }
        if risk >= 60:
            return {
                "action": "disable_user",
                "requires_human": True,
                "action_color": action_color
            }
        return {
            "action": "monitor",
            "requires_human": False,
            "action_color": action_color
        }
