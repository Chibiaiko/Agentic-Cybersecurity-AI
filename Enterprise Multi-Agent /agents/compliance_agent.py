from typing import Dict, Any, List
from agents.base_agent import BaseAgent
from models.risk_model import Risk, ComplianceMapping

class ComplianceMappingAgent(BaseAgent):
    def __init__(self):
        super().__init__("Compliance Mapping Agent")

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        risks = context.get("risks", [])
        
        for risk in risks:
            mappings = []
            
            # Example Mappings based on keywords
            if "credentials" in risk.title.lower() or "secret" in risk.title.lower():
                mappings.append(ComplianceMapping(
                    framework="NIST SP 800-53",
                    control_id="IA-2",
                    control_title="Identification and Authentication",
                    justification="Hardcoded credentials violate IAM principles."
                ))
                mappings.append(ComplianceMapping(
                    framework="PCI-DSS",
                    control_id="8.2.1",
                    control_title="Strong Credential Management",
                    justification="Credentials found in clear text."
                ))
            
            if "container" in risk.title.lower() or "docker" in risk.component.lower():
                mappings.append(ComplianceMapping(
                    framework="SOC 2",
                    control_id="CC6.1",
                    control_title="Logical Access Security",
                    justification="Container security configuration issue."
                ))
                
            risk.compliance_mappings = mappings
            
        return {"risks": risks}
