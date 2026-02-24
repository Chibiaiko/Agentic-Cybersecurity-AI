# 🦅 nest/baseline_engine.py
# ---------------------------------------------------------
# SentinelHawk — Baseline / Anomaly Detection Engine
# ---------------------------------------------------------

from collections import defaultdict

class BaselineEngine:

    def __init__(self):
        # Track user and host activity for anomaly detection
        self.user_activity = defaultdict(int)
        self.host_activity = defaultdict(int)
        self.ip_activity = defaultdict(int)

    def analyze(self, event):
        """
        Analyze event against baseline behavior.
        Returns an anomaly score (0-100).
        """
        score = 0
        user = event.get("user")
        host = event.get("host")
        ip = event.get("ip")
        severity = event.get("severity")
        event_level = event.get("event_level")

        # Adaptive user activity scoring
        if user:
            self.user_activity[user] += 1
            if self.user_activity[user] > 20:
                score += 25

        # Adaptive host activity scoring
        if host:
            self.host_activity[host] += 1
            if self.host_activity[host] > 15:
                score += 20

        # IP anomaly scoring
        if ip:
            self.ip_activity[ip] += 1
            if str(ip).startswith("8."):
                score += 15
            if self.ip_activity[ip] > 10:
                score += 10

        # Event severity scoring
        if severity == "High":
            score += 40
        elif severity == "Medium":
            score += 25
        elif severity == "Low":
            score += 10

        # Event level scoring
        if event_level == "Error":
            score += 20

        # Cap score at 100
        return min(score, 100)
