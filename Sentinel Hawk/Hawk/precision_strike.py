# ⚔ precision_strike.py
# ---------------------------------------------------------
# SentinelHawk — Precision Strike / Response Layer with Colored Output
# ---------------------------------------------------------

from nest.response_engine import ResponseEngine
from nest.human_gate import HumanGate
from nest.decision_memory import DecisionMemory
from nest.llm_advisor import LLMAdvisor
from models import Colors
from secrets_ import *

class PrecisionStrike:

    def __init__(self):
        self.response = ResponseEngine()
        self.human_gate = HumanGate()
        self.memory = DecisionMemory()

        if ENABLE_LLM:
            self.llm = LLMAdvisor()
        else:
            self.llm = None

    def respond(self, incident):
        """
        Respond to an Incident object:
        - Recommend action
        - Execute if approved
        - Request human approval if necessary
        """
        
        # 1. Generate Recommendation
        recommendation = self.response.recommend_action({
            "risk": incident.risk,
            "event": incident.event
        })
        
        incident.set_recommendation(recommendation)

        # 2. Check Human Gate
        if incident.requires_human:
            # Print colored approval request
            action_color = Colors.severity_color(recommendation.get("severity", "MEDIUM"))
            action_text = recommendation.get('action').replace('_', ' ').upper()
            print(Colors.bold_colored("\n=== HUMAN APPROVAL REQUIRED ===", Colors.BRIGHT_GREEN))
            print(f"Timestamp: {incident.timestamp}")
            print(f"Event: {incident.event}")
            print(f"Proposed Action: {Colors.bold_colored(action_text, Colors.GOLD)}")
            print(f"Reason: {recommendation.get('reason')}")
            print(Colors.bold_colored("================================\n", Colors.BRIGHT_GREEN))
            
            self.human_gate.request_approval(recommendation, incident.event)
            # In this automated POC, we leave it as Pending Approval.
            # In a real app, this might block or send an email.
            incident.status = "PENDING_APPROVAL"
            status_color = Colors.status_color(incident.status)
            print(Colors.bold_colored(f"Status: {incident.status}", status_color))
            
            # If strictly automated, we stop here. 
            # If we want to simulate auto-approval for testing, we can:
            # incident.execute_decision(self.response.execute(recommendation, approved=True))
            # But let's stick to the logic: requires approval -> pending.
        
        # 3. Execute (if not blocked)
        # Note: execute() handles the 'requires_approval' check itself.
        # If requires_approval is True and approved=False, it returns PENDING.
        execution_result = self.response.execute(recommendation, approved=False)
        incident.execute_decision(execution_result)

        # 4. LLM Summary (Optional)
        if self.llm:
            summary = self.llm.summarize(
                incident.event,
                incident.risk
            )
            incident.summary = summary

        # 5. Store in Memory
        self.memory.store(incident.to_dict())
        
        return incident
