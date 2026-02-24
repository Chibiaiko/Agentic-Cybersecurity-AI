# 🦅 nest/confidence_engine.py
# ---------------------------------------------------------
# SentinelHawk — Confidence Engine (Adaptive AI)
# ---------------------------------------------------------

class ConfidenceEngine:

    def __init__(self):
        self.history = []

    @staticmethod
    def get_confidence_color(confidence_level):
        """
        Map confidence levels to colors.
        
        Args:
            confidence_level: "High", "Medium", or "Low"
        
        Returns:
            dict with hex color, rgb, and description
        """
        color_map = {
            "Low": {
                "hex": "#FF0000",      # Red
                "rgb": "255, 0, 0",
                "description": "Low Confidence"
            },
            "Medium": {
                "hex": "#FF9500",      # Orange
                "rgb": "255, 149, 0",
                "description": "Medium Confidence"
            },
            "High": {
                "hex": "#FFFF00",      # Yellow
                "rgb": "255, 255, 0",
                "description": "High Confidence"
            }
        }
        return color_map.get(confidence_level, color_map["Low"])

    def calculate_confidence(self, anomaly_score, correlation_score):
        """
        Adaptive confidence calculation based on current scores and historical trends.
        Returns confidence level with color information.
        """

        # Historical weighting
        if not self.history:
            avg_risk = 0
        else:
            avg_risk = sum(self.history[-20:]) / max(len(self.history[-20:]), 1)
            
        combined_score = anomaly_score + correlation_score + (avg_risk * 0.1)

        # Dynamic thresholds
        if combined_score > 50:
            confidence = "High"
        elif combined_score > 25:
            confidence = "Medium"
        else:
            confidence = "Low"

        # Store for adaptive learning
        self.history.append(combined_score)
        if len(self.history) > 1000:  # memory cap
            self.history.pop(0)

        return confidence
