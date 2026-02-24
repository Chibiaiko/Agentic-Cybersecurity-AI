# 🦅 nest/mitre_mapper.py

class MITREMapper:

    def map(self, event):

        techniques = []

        if event.get("event_id") == 4625:
            techniques.append({"technique": "T1110", "name": "Brute Force"})

        if "powershell" in str(event.get("raw")).lower():
            techniques.append({"technique": "T1059", "name": "Command and Scripting Interpreter"})

        if event.get("country") and event["country"] not in ["US", "JP", "unknown"]:
            techniques.append({"technique": "T1078", "name": "Valid Accounts"})

        return techniques
