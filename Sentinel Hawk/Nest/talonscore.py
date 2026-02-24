# 🦅 nest/talonscore.py
# ---------------------------------------------------------
# SentinelHawk — Adaptive AI Risk Scoring Engine
# Learns from past incidents to adjust scoring dynamically
# ---------------------------------------------------------

from collections import deque
from nest.confidence_engine import ConfidenceEngine

class TalonScore:

    def __init__(self, history_limit=100):
        self.confidence_engine = ConfidenceEngine()
        self.history = deque(maxlen=history_limit)  # stores recent risk scores for learning
        self.event_history = deque(maxlen=history_limit)  # stores raw events for adaptive adjustment

    @staticmethod
    def get_risk_color(risk_score):
        """
        Map risk scores to colors and severity levels.
        
        Args:
            risk_score: numeric risk score (0-100)
        
        Returns:
            dict with severity level, hex color, rgb, and description
        """
        if risk_score >= 80:
            return {
                "severity": "CRITICAL",
                "hex": "#FF0000",           # Red
                "rgb": "255, 0, 0",
                "description": "Critical Risk"
            }
        elif risk_score >= 60:
            return {
                "severity": "HIGH",
                "hex": "#FF5E0E",           # Orange-Red
                "rgb": "255, 94, 14",
                "description": "High Risk"
            }
        elif risk_score >= 40:
            return {
                "severity": "MEDIUM",
                "hex": "#FFD700",           # Gold
                "rgb": "255, 215, 0",
                "description": "Medium Risk"
            }
        else:
            return {
                "severity": "LOW",
                "hex": "#2EFF2E",           # Bright Green
                "rgb": "46, 255, 46",
                "description": "Low Risk"
            }

    @staticmethod
    def classify_severity(risk_score):
        """
        Classify severity level based on risk score.
        """
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        return "LOW"

    def calculate_risk(self, event, anomaly_score, correlation_score):
        """
        Base scoring + adaptive adjustment based on historical incidents.
        """
        base_score = anomaly_score + correlation_score

        # Severity weight
        severity = event.get("severity")
        if severity == "High":
            base_score += 40
        elif severity == "Medium":
            base_score += 25
        elif severity == "Low":
            base_score += 10

        # Event-specific rules
        if event.get("event_id") == 4625:  # failed login
            base_score += 30
        if "powershell" in str(event.get("raw", "")).lower():
            base_score += 20

        # Adaptive adjustment: compare with previous incidents
        if self.history:
            avg_past = sum(self.history) / len(self.history)
            # If current risk is much lower than recent critical incidents, boost it slightly
            if base_score < avg_past - 15:
                base_score += 10
            # If unusually high, dampen slightly
            elif base_score > avg_past + 15:
                base_score -= 5

        return min(max(base_score, 0), 100)  # clamp between 0-100

    def score(self, analysis):
        """
        Score an analysis result and return risk metrics with color information.
        """
        event = analysis.get("event")
        
        # Validate event exists
        if not event:
            raise ValueError("Analysis must contain 'event' key")
        
        # Calculate scores
        risk = self.calculate_risk(
            event,
            analysis.get("anomaly_score", 0),
            analysis.get("correlation_score", 0)
        )
        
        confidence = self.confidence_engine.calculate_confidence(
            analysis.get("anomaly_score", 0),
            analysis.get("correlation_score", 0)
        )

        # Get color information
        risk_color = self.get_risk_color(risk)
        confidence_color = ConfidenceEngine.get_confidence_color(confidence)

        # store for learning
        self.history.append(risk)
        self.event_history.append(event)

        return {
            "event": event,
            "risk": risk,
            "risk_color": risk_color,
            "confidence": confidence,
            "confidence_color": confidence_color,
            "severity": risk_color["severity"],
            "mitre": analysis.get("mitre", []),
            "anomaly_score": analysis.get("anomaly_score", 0),
            "correlation_score": analysis.get("correlation_score", 0)
        }
