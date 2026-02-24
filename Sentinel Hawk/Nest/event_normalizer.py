# 🦅 nest/event_normalizer.py
# ---------------------------------------------------------
# SentinelHawk — Event Normalizer
# ---------------------------------------------------------

class EventNormalizer:

    @staticmethod
    def normalize(raw_event: dict) -> dict:
        """
        Normalize raw logs from any SIEM/EDR source into
        a consistent internal event structure.
        """

        return {
            "timestamp": str(raw_event.get("TimeGenerated") or raw_event.get("TimeStamp")),
            "user": (
                raw_event.get("Account")
                or raw_event.get("UserPrincipalName")
                or raw_event.get("Identity")
                or "unknown_user"
            ),
            "ip": (
                raw_event.get("IpAddress")
                or raw_event.get("IPAddress")
                or raw_event.get("ClientIP")
                or raw_event.get("RemoteIP")
                or "0.0.0.0"
            ),
            "host": (
                raw_event.get("Computer")
                or raw_event.get("DeviceName")
                or raw_event.get("CompromisedEntity")
                or "unknown_host"
            ),
            "event_id": raw_event.get("EventID") or raw_event.get("EventCode") or 0,
            "event_name": (
                raw_event.get("ActivityDisplayName")
                or raw_event.get("AlertName")
                or "unknown_event"
            ),
            "severity": raw_event.get("Severity") or "Low",
            "event_level": raw_event.get("EventLevelName") or raw_event.get("Level") or "Info",
            "country": (
                raw_event.get("Location")
                or raw_event.get("RemoteIPCountry")
                or "unknown"
            ),
            "raw": raw_event.get("raw") or raw_event
        }
