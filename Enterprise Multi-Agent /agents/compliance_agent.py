from typing import Dict, Any, List
from agents.base_agent import BaseAgent
from models.risk_model import Risk, RiskLevel, BusinessImpact

class RiskClassificationAgent(BaseAgent):
    def __init__(self):
        super().__init__("Risk Classification Agent")

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        findings = context.get("findings", [])
        risks = []
        
        for finding in findings:
            # Map raw severity to RiskLevel
            raw_sev = finding.get("raw_severity", "INFO")
            severity = RiskLevel.INFO
            cvss = 0.0
            vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N" # Default zero
            
            if raw_sev == "CRITICAL":
                severity = RiskLevel.CRITICAL
                cvss = 9.8
                vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            elif raw_sev == "HIGH":
                severity = RiskLevel.HIGH
                cvss = 7.5
                vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L" # Simplified
            elif raw_sev == "MEDIUM":
                severity = RiskLevel.MEDIUM
                cvss = 5.3
                vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
            elif raw_sev == "LOW":
                severity = RiskLevel.LOW
                cvss = 3.1
            
            risk = Risk(
                id=finding["id"].replace("FIND", "RISK"),
                title=finding["title"],
                description=finding["description"],
                component=finding["component"],
                severity=severity,
                cvss_score=cvss,
                cvss_vector=vector,
                business_impact=BusinessImpact.LOW  # Placeholder, will be updated by Business Agent
            )
            risks.append(risk)
            
        return {"risks": risks}
