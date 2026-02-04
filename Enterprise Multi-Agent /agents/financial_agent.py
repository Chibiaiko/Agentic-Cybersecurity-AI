from typing import Dict, Any
from agents.base_agent import BaseAgent
from models.risk_model import Risk, FinancialEstimate, RiskLevel, BusinessImpact

class FinancialLossAgent(BaseAgent):
    def __init__(self):
        super().__init__("Financial Loss Agent")

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        risks = context.get("risks", [])
        
        for risk in risks:
            # Base cost depending on impact
            base_loss = 10000.0 # Default
            
            if risk.business_impact == BusinessImpact.CRITICAL:
                base_loss = 500000.0
            elif risk.business_impact == BusinessImpact.HIGH:
                base_loss = 150000.0
            elif risk.business_impact == BusinessImpact.MEDIUM:
                base_loss = 50000.0
            
            # Severity multiplier
            severity_mult = 1.0
            if risk.severity == RiskLevel.CRITICAL:
                severity_mult = 5.0
            elif risk.severity == RiskLevel.HIGH:
                severity_mult = 2.5
            elif risk.severity == RiskLevel.MEDIUM:
                severity_mult = 1.5
                
            estimated_loss = base_loss * severity_mult
            
            risk.financial_impact = FinancialEstimate(
                min_loss=estimated_loss * 0.5,
                most_likely_loss=estimated_loss,
                max_loss=estimated_loss * 2.5,
                annualized_risk_exposure=estimated_loss * 0.1, # Assuming 10% annual likelihood for simplicity
                description=f"Potential loss due to {risk.title} in {risk.component}"
            )
            
        return {"risks": risks}
