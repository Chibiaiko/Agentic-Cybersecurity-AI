# 🚪 nest/human_gate.py
# ---------------------------------------------------------
# SentinelHawk — Human Gate / Approval System with Color
# ---------------------------------------------------------

from models import Colors

class HumanGate:
    """
    Human approval gate for high-risk actions.
    Displays colored requests for human review.
    """

    def __init__(self):
        self.approvals = []

    def request_approval(self, recommendation, event):
        """
        Request human approval for an action.
        Displays a colored approval request in the terminal.
        """
        action_text = recommendation.get('action', 'unknown').replace('_', ' ').upper()
        reason = recommendation.get('reason', 'No reason provided')
        
        # Display colored approval request
        print(Colors.bold_colored("\n=== HUMAN APPROVAL REQUIRED ===", Colors.BRIGHT_GREEN))
        print(f"Timestamp: {event.get('timestamp', 'N/A')}")
        print(f"Event: {event}")
        print(f"Proposed Action: {Colors.bold_colored(action_text, Colors.GOLD)}")
        print(f"Reason: {reason}")
        print(Colors.bold_colored("================================\n", Colors.BRIGHT_GREEN))
        
        # Store approval request
        self.approvals.append({
            "action": recommendation.get('action'),
            "reason": reason,
            "event": event,
            "approved": False
        })

    def approve(self, action_index):
        """Approve an action by index"""
        if 0 <= action_index < len(self.approvals):
            self.approvals[action_index]["approved"] = True
            return True
        return False

    def get_pending(self):
        """Get all pending approvals"""
        return [a for a in self.approvals if not a["approved"]]
