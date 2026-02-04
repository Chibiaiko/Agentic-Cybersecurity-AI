from typing import Dict, Any
from agents.base_agent import BaseAgent
from models.risk_model import Risk, BusinessImpact, RiskLevel

class BusinessImpactAgent(BaseAgent):
    def __init__(self):
        super().__init__("Business Impact Agent")

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        risks = context.get("risks", [])
        
        for risk in risks:
            # Simple heuristic for demonstration
            # In reality, this would query a CMDB or asset inventory
            
            impact = BusinessImpact.LOW
            
            if "database" in risk.component.lower() or "prod" in risk.component.lower():
                impact = BusinessImpact.HIGH
            elif "auth" in risk.title.lower() or "credentials" in risk.title.lower():
                impact = BusinessImpact.CRITICAL
            elif "docker" in risk.component.lower():
                impact = BusinessImpact.MEDIUM
                
            risk.business_impact = impact
            
            # Calculate Composite Score (Simple weighted average)
            # CVSS (0-10) * Impact Weight (1-2)
            impact_weight = 1.0
            if impact == BusinessImpact.CRITICAL:
                impact_weight = 2.0
            elif impact == BusinessImpact.HIGH:
                impact_weight = 1.5
            elif impact == BusinessImpact.MEDIUM:
                impact_weight = 1.2
            
            risk.composite_score = risk.cvss_score * impact_weight
            
        context["risks"] = risks
        return context
