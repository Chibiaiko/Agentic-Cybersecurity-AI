from typing import Dict, Any, List
from datetime import datetime
from agents.base_agent import BaseAgent
from models.risk_model import Risk, SecurityReport, RiskLevel

class ReportingAgent(BaseAgent):
    def __init__(self):
        super().__init__("Reporting Agent")

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        risks = context.get("risks", [])
        
        # Calculate aggregate metrics
        total_min_loss = sum([r.financial_impact.min_loss for r in risks if r.financial_impact])
        total_max_loss = sum([r.financial_impact.max_loss for r in risks if r.financial_impact])
        
        critical_count = sum(1 for r in risks if r.severity == RiskLevel.CRITICAL)
        high_count = sum(1 for r in risks if r.severity == RiskLevel.HIGH)
        
        # Determine Gate Status
        gate_status = "PASS"
        if critical_count > 0:
            gate_status = "FAIL"
        elif high_count > 2:
            gate_status = "FAIL"
        elif high_count > 0:
            gate_status = "PASS WITH WARNINGS"
            
        overall_posture = "LOW_RISK"
        if critical_count > 0:
            overall_posture = "CRITICAL"
        elif high_count > 0:
            overall_posture = "ELEVATED"
            
        report = SecurityReport(
            date=datetime.now().strftime("%Y-%m-%d"),
            risks=risks,
            gate_status=gate_status,
            overall_posture=overall_posture,
            total_financial_exposure_min=total_min_loss,
            total_financial_exposure_max=total_max_loss,
            trend="DEGRADING" # Mocked trend
        )
        
        return {"report": report}
