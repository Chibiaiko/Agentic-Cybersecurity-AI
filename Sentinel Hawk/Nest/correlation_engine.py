# 🦅 nest/correlation_engine.py
# ---------------------------------------------------------
# SentinelHawk — Event Correlation Engine
# ---------------------------------------------------------

class CorrelationEngine:

    def __init__(self):
        # Maintain simple state for correlated events
        self.failed_logins = {}
        self.admin_access = {}

    def analyze(self, event):
        """
        Correlate events to detect patterns of suspicious activity.
        Returns a correlation score (0-100).
        """
        score = 0
        user = event.get("user")
        host = event.get("host")
        event_id = event.get("event_id")
        ip = event.get("ip")

        # Brute-force login detection
        if event_id == 4625:
            self.failed_logins[user] = self.failed_logins.get(user, 0) + 1
            if self.failed_logins[user] >= 5:
                score += 30

        # Admin activity detection
        if user and "admin" in str(user).lower():
            self.admin_access[user] = self.admin_access.get(user, 0) + 1
            if self.admin_access[user] > 3:
                score += 20

        # Suspicious IP activity
        if ip and str(ip).startswith("8."):
            score += 15

        # Cap score at 100
        return min(score, 100)
